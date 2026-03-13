// SPDX-License-Identifier: GPL-2.0+
/*
 * Sandbox TPM SPI Emulator
 *
 * Copyright (c) 2025 wolfSSL Inc.
 * Author: Aidan Garske <aidan@wolfssl.com>
 *
 * Emulates TPM TIS SPI protocol for testing wolfTPM SPI HAL
 * without hardware. Wraps the existing sandbox TPM2 state machine.
 */

#include <dm.h>
#include <log.h>
#include <spi.h>
#include <spi_flash.h>
#include <asm/spi.h>
#include <asm/state.h>
#include <linux/bitops.h>

/* TIS register addresses (locality 0) */
#define TPM_ACCESS_REG		0x0000
#define TPM_INT_ENABLE_REG	0x0008
#define TPM_INTF_CAPS_REG	0x0014
#define TPM_STS_REG		0x0018
#define TPM_DATA_FIFO_REG	0x0024
#define TPM_DID_VID_REG		0x0F00
#define TPM_RID_REG		0x0F04

/* TIS access register bits */
#define TPM_ACCESS_VALID		0x80
#define TPM_ACCESS_ACTIVE_LOCALITY	0x20
#define TPM_ACCESS_REQUEST_PENDING	0x04
#define TPM_ACCESS_REQUEST_USE		0x02

/* TIS status register bits */
#define TPM_STS_VALID		0x80
#define TPM_STS_COMMAND_READY	0x40
#define TPM_STS_GO		0x20
#define TPM_STS_DATA_AVAIL	0x10
#define TPM_STS_DATA_EXPECT	0x08

/* Interface capabilities */
#define TPM_INTF_CAPS_VALUE	0x30000697  /* Typical Infineon value */

/* Device/Vendor ID - Infineon SLB9670 */
#define TPM_DID_VID_VALUE	0x001D15D1

/* Revision ID */
#define TPM_RID_VALUE		0x36

/* Maximum buffer sizes */
#define TPM_CMD_BUF_SIZE	4096
#define TPM_RSP_BUF_SIZE	4096
#define MAX_SPI_FRAMESIZE	64

/* TPM TIS SPI protocol states */
enum tpm_spi_state {
	TPM_SPI_IDLE,
	TPM_SPI_HEADER,		/* Receiving 4-byte header */
	TPM_SPI_WAIT_STATE,	/* Sending wait state bytes */
	TPM_SPI_DATA,		/* Transfer data */
};

/* TIS state machine */
enum tpm_tis_state {
	TIS_IDLE,
	TIS_READY,		/* Ready to receive command */
	TIS_RECEPTION,		/* Receiving command data */
	TIS_EXECUTION,		/* Executing command */
	TIS_COMPLETION,		/* Response available */
};

struct sandbox_tpm_spi {
	/* SPI protocol state */
	enum tpm_spi_state spi_state;
	u8 header[4];
	int header_pos;
	bool is_read;
	u32 addr;
	int xfer_len;
	int data_pos;

	/* TIS state */
	enum tpm_tis_state tis_state;
	u8 access_reg;
	u32 sts_reg;
	u32 intf_caps;

	/* Command/response buffers */
	u8 cmd_buf[TPM_CMD_BUF_SIZE];
	int cmd_len;
	int cmd_pos;
	u8 rsp_buf[TPM_RSP_BUF_SIZE];
	int rsp_len;
	int rsp_pos;

	/* Burst count for status register */
	u16 burst_count;
};

/*
 * Parse TIS SPI header
 * Format: [R/W|len-1][0xD4][addr_hi][addr_lo]
 * Bit 7 of byte 0: 1=read, 0=write
 * Bits 5:0 of byte 0: transfer length - 1
 */
static void parse_spi_header(struct sandbox_tpm_spi *priv)
{
	priv->is_read = (priv->header[0] & 0x80) != 0;
	priv->xfer_len = (priv->header[0] & 0x3F) + 1;
	priv->addr = (priv->header[2] << 8) | priv->header[3];
	priv->data_pos = 0;
}

/*
 * Read from TIS register
 */
static u8 tis_reg_read(struct sandbox_tpm_spi *priv, u32 addr)
{
	u32 reg = addr & 0x0FFF;  /* Mask off locality bits */

	switch (reg) {
	case TPM_ACCESS_REG:
		return priv->access_reg;

	case TPM_STS_REG:
	case TPM_STS_REG + 1:
	case TPM_STS_REG + 2:
	case TPM_STS_REG + 3: {
		int byte_off = reg - TPM_STS_REG;
		u32 sts = priv->sts_reg;

		/* Update burst count in status */
		sts |= ((u32)priv->burst_count << 8);
		return (sts >> (byte_off * 8)) & 0xFF;
	}

	case TPM_INTF_CAPS_REG:
	case TPM_INTF_CAPS_REG + 1:
	case TPM_INTF_CAPS_REG + 2:
	case TPM_INTF_CAPS_REG + 3: {
		int byte_off = reg - TPM_INTF_CAPS_REG;

		return (priv->intf_caps >> (byte_off * 8)) & 0xFF;
	}

	case TPM_DID_VID_REG:
	case TPM_DID_VID_REG + 1:
	case TPM_DID_VID_REG + 2:
	case TPM_DID_VID_REG + 3: {
		int byte_off = reg - TPM_DID_VID_REG;

		return (TPM_DID_VID_VALUE >> (byte_off * 8)) & 0xFF;
	}

	case TPM_RID_REG:
		return TPM_RID_VALUE;

	default:
		/*
		 * Handle FIFO reads - the FIFO can be accessed at any address
		 * from 0x0024 up to 0x0F00 for multi-byte transfers.
		 */
		if (reg >= TPM_DATA_FIFO_REG && reg < TPM_DID_VID_REG) {
			if (priv->tis_state == TIS_COMPLETION &&
			    priv->rsp_pos < priv->rsp_len) {
				u8 data = priv->rsp_buf[priv->rsp_pos++];

				/* Update status when all data read */
				if (priv->rsp_pos >= priv->rsp_len) {
					priv->sts_reg &= ~TPM_STS_DATA_AVAIL;
					priv->sts_reg |= TPM_STS_COMMAND_READY;
					priv->tis_state = TIS_READY;
				}
				return data;
			}
			return 0xFF;
		}
		return 0xFF;
	}
}

/*
 * Write to TIS register
 */
static void tis_reg_write(struct sandbox_tpm_spi *priv, u32 addr, u8 value)
{
	u32 reg = addr & 0x0FFF;

	switch (reg) {
	case TPM_ACCESS_REG:
		if (value & TPM_ACCESS_REQUEST_USE) {
			/* Request locality */
			priv->access_reg |= TPM_ACCESS_ACTIVE_LOCALITY;
			priv->access_reg |= TPM_ACCESS_VALID;
		}
		break;

	case TPM_STS_REG:
		if (value & TPM_STS_COMMAND_READY) {
			/* Abort current command and go to ready state */
			priv->tis_state = TIS_READY;
			priv->cmd_len = 0;
			priv->cmd_pos = 0;
			priv->rsp_len = 0;
			priv->rsp_pos = 0;
			priv->sts_reg = TPM_STS_VALID | TPM_STS_COMMAND_READY;
			priv->burst_count = MAX_SPI_FRAMESIZE;
		}
		if (value & TPM_STS_GO) {
			/* Execute command */
			if (priv->tis_state == TIS_RECEPTION &&
			    priv->cmd_len > 0) {
				/*
				 * Generate a simple success response.
				 * A full implementation would call the
				 * sandbox TPM2 state machine here.
				 */
				priv->rsp_buf[0] = 0x80;  /* TPM_ST_NO_SESSIONS */
				priv->rsp_buf[1] = 0x01;
				priv->rsp_buf[2] = 0x00;  /* Response size: 10 */
				priv->rsp_buf[3] = 0x00;
				priv->rsp_buf[4] = 0x00;
				priv->rsp_buf[5] = 0x0A;
				priv->rsp_buf[6] = 0x00;  /* TPM_RC_SUCCESS */
				priv->rsp_buf[7] = 0x00;
				priv->rsp_buf[8] = 0x00;
				priv->rsp_buf[9] = 0x00;
				priv->rsp_len = 10;
				priv->rsp_pos = 0;

				priv->tis_state = TIS_COMPLETION;
				priv->sts_reg = TPM_STS_VALID |
						TPM_STS_DATA_AVAIL;
			}
		}
		break;

	default:
		/*
		 * Handle FIFO writes - the FIFO is at 0x0024 but any address
		 * from 0x0024 up to 0x0F00 can be used for FIFO access when
		 * doing multi-byte transfers (address auto-increments).
		 */
		if (reg >= TPM_DATA_FIFO_REG && reg < TPM_DID_VID_REG) {
			if (priv->tis_state == TIS_READY) {
				/* Start receiving command */
				priv->tis_state = TIS_RECEPTION;
				priv->cmd_len = 0;
				priv->cmd_pos = 0;
				priv->sts_reg = TPM_STS_VALID | TPM_STS_DATA_EXPECT;
			}
			if (priv->tis_state == TIS_RECEPTION) {
				if (priv->cmd_len < TPM_CMD_BUF_SIZE) {
					priv->cmd_buf[priv->cmd_len++] = value;

					/* Check if we have complete command */
					if (priv->cmd_len >= 6) {
						u32 expected_len;

						expected_len = (priv->cmd_buf[2] << 24) |
							       (priv->cmd_buf[3] << 16) |
							       (priv->cmd_buf[4] << 8) |
							       priv->cmd_buf[5];
						if (priv->cmd_len >= expected_len) {
							/* Command complete */
							priv->sts_reg &=
								~TPM_STS_DATA_EXPECT;
						}
					}
				}
			}
		}
		break;
	}
}

/*
 * SPI emulation transfer callback
 */
static int sandbox_tpm_spi_xfer(struct udevice *dev, unsigned int bitlen,
				const void *dout, void *din, unsigned long flags)
{
	struct sandbox_tpm_spi *priv = dev_get_priv(dev);
	int bytes = bitlen / 8;
	const u8 *tx = dout;
	u8 *rx = din;
	int i;

	/* Handle CS assert - reset state machine */
	if (flags & SPI_XFER_BEGIN) {
		priv->spi_state = TPM_SPI_HEADER;
		priv->header_pos = 0;
	}

	for (i = 0; i < bytes; i++) {
		u8 tx_byte = tx ? tx[i] : 0;
		u8 rx_byte = 0;

		switch (priv->spi_state) {
		case TPM_SPI_IDLE:
			/* Should not happen during active transfer */
			rx_byte = 0xFF;
			break;

		case TPM_SPI_HEADER:
			/* Receive 4-byte header */
			priv->header[priv->header_pos++] = tx_byte;
			rx_byte = 0x00;

			if (priv->header_pos >= 4) {
				parse_spi_header(priv);
				log_debug("TPM SPI: %s len=%d addr=0x%04x\n",
					  priv->is_read ? "read" : "write",
					  priv->xfer_len, priv->addr);
				/* Return wait state in last header byte */
				rx_byte = 0x01;  /* Ready immediately */
				priv->spi_state = TPM_SPI_DATA;
			}
			break;

		case TPM_SPI_DATA:
			if (priv->is_read) {
				/* Read from TPM register */
				rx_byte = tis_reg_read(priv,
						       priv->addr + priv->data_pos);
			} else {
				/* Write to TPM register */
				tis_reg_write(priv, priv->addr + priv->data_pos,
					      tx_byte);
				rx_byte = 0x00;
			}
			priv->data_pos++;
			break;

		default:
			rx_byte = 0xFF;
			break;
		}

		if (rx)
			rx[i] = rx_byte;
	}

	/* Handle CS deassert - return to idle */
	if (flags & SPI_XFER_END)
		priv->spi_state = TPM_SPI_IDLE;

	return 0;
}

static int sandbox_tpm_spi_probe(struct udevice *dev)
{
	struct sandbox_tpm_spi *priv = dev_get_priv(dev);

	/* Initialize TIS state */
	priv->spi_state = TPM_SPI_IDLE;
	priv->tis_state = TIS_IDLE;
	priv->access_reg = TPM_ACCESS_VALID;
	priv->sts_reg = TPM_STS_VALID;
	priv->intf_caps = TPM_INTF_CAPS_VALUE;
	priv->burst_count = MAX_SPI_FRAMESIZE;
	priv->cmd_len = 0;
	priv->rsp_len = 0;

	log_debug("TPM SPI sandbox emulator probed\n");

	return 0;
}

static const struct dm_spi_emul_ops sandbox_tpm_spi_ops = {
	.xfer = sandbox_tpm_spi_xfer,
};

static const struct udevice_id sandbox_tpm_spi_ids[] = {
	{ .compatible = "sandbox,tpm-spi-emul" },
	{ }
};

U_BOOT_DRIVER(sandbox_tpm_spi_emul) = {
	.name = "sandbox_tpm_spi_emul",
	.id = UCLASS_SPI_EMUL,
	.of_match = sandbox_tpm_spi_ids,
	.ops = &sandbox_tpm_spi_ops,
	.probe = sandbox_tpm_spi_probe,
	.priv_auto = sizeof(struct sandbox_tpm_spi),
};

/*
 * SPI slave driver for TPM device
 * This gets probed when a device with "sandbox,tpm-spi" is found in DTS.
 * The actual SPI transfers are handled by the emulator above.
 */
static int sandbox_tpm_spi_slave_probe(struct udevice *dev)
{
	log_debug("TPM SPI slave device probed\n");
	return 0;
}

static const struct udevice_id sandbox_tpm_spi_slave_ids[] = {
	{ .compatible = "sandbox,tpm-spi" },
	{ }
};

U_BOOT_DRIVER(sandbox_tpm_spi) = {
	.name = "sandbox_tpm_spi",
	.id = UCLASS_SPI_GENERIC,
	.of_match = sandbox_tpm_spi_slave_ids,
	.probe = sandbox_tpm_spi_slave_probe,
};
