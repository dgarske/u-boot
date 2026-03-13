/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * wolfTPM build configuration for U-Boot
 *
 * Copyright (C) 2025 wolfSSL Inc.
 * Author: Aidan Garske <aidan@wolfssl.com>
 */

#ifndef USER_SETTINGS_H
#define USER_SETTINGS_H

/* Define U-Boot's byte-order macros first so wolfTPM's #ifndef-guarded
 * fallbacks in tpm2_packet.h don't redefine them.
 */
#include <asm/byteorder.h>

#ifdef __cplusplus
extern "C" {
#endif

/******************************************************************************/
/* --- BEGIN wolfTPM U-boot Settings -- */
/******************************************************************************/

/* =========================================================================
 * TPM Chip Configuration
 * =========================================================================
 *
 * CONFIG_TPM_AUTODETECT: For swtpm/QEMU testing (no specific chip)
 * !CONFIG_TPM_AUTODETECT: For real hardware (SLB9672/SLB9673)
 */
#ifdef CONFIG_TPM_AUTODETECT
	#define WOLFTPM_AUTODETECT
#else
	/* Real hardware - Infineon SLB9672/SLB9673
	 * Firmware upgrade only supported by these chips */
	#define WOLFTPM_FIRMWARE_UPGRADE
	#define WOLFTPM_SLB9672
	/* #define WOLFTPM_SLB9673 */
#endif

/* Include delay.h and types.h for
 * U-boot time delay and types */
#include <linux/delay.h>
#include <linux/types.h>
#include <stdint.h>

/* wolfCrypt disabled - pcr_setauthpolicy/pcr_setauthvalue not available
 * To enable wolfCrypt, you would need to:
 * 1. Uncomment the line below to undefine WOLFTPM2_NO_WOLFCRYPT
 * 2. Add wolfCrypt source files to the U-Boot build (lib/Makefile)
 * 3. Add wolfCrypt settings for embedded/no-OS use
 */
#undef  WOLFTPM2_NO_WOLFCRYPT
#define WOLFTPM2_NO_WOLFCRYPT

/* =========================================================================
 * TPM Communication Mode Selection (Auto-detected based on chip type)
 * =========================================================================
 *
 * For real SPI hardware (SLB9672/SLB9673):
 *   - Uses wolfTPM's native TIS layer with raw SPI via tpm_io_uboot.c
 *   - Requires CONFIG_SPI and CONFIG_DM_SPI enabled in U-Boot
 *
 * For swtpm/QEMU testing (no specific chip defined):
 *   - Uses WOLFTPM_LINUX_DEV mode with U-Boot's TPM driver (tpm_xfer())
 *   - Works with MMIO-based TPM via tpm2_tis_mmio.c
 */

#if defined(WOLFTPM_SLB9672) || defined(WOLFTPM_SLB9673)
	/* Real SPI hardware - use native wolfTPM TIS with raw SPI */
	/* WOLFTPM_LINUX_DEV is NOT defined */
	#define WOLFTPM_EXAMPLE_HAL

	/* SPI bus and chip select for TPM
	 * Official Raspberry Pi tpm-slb9670 overlay uses CE1 (GPIO7)
	 * This matches LetsTrust and most Infineon evaluation boards */
	#ifndef TPM_SPI_BUS
		#define TPM_SPI_BUS 0
	#endif
	#ifndef TPM_SPI_CS
		#define TPM_SPI_CS 1   /* CE1/GPIO7 - official RPi TPM overlay setting */
	#endif
#else
	/* swtpm/QEMU - use U-Boot's TPM driver with MMIO communication mode */
	#define WOLFTPM_LINUX_DEV
#endif

#define XSLEEP_MS(ms) udelay(ms * 1000)

/* Timeout configuration */
#ifdef WOLFTPM_FIRMWARE_UPGRADE
	/* Firmware update requires much longer timeout for TPM processing */
	#define TPM_TIMEOUT_TRIES 2000000
#else
	/* Normal operations - reduce from default 1,000,000 to prevent long hangs */
	#define TPM_TIMEOUT_TRIES 10000
#endif

/* Add small delay between poll attempts to avoid tight spin loop */
#define XTPM_WAIT() udelay(100)

/* Do not include API's that use heap(), they are not required */
#define WOLFTPM2_NO_HEAP

/* Debugging - disabled for clean output */
/* #define DEBUG_WOLFTPM */
/* #define WOLFTPM_DEBUG_VERBOSE */
/* #define WOLFTPM_DEBUG_IO */
/* #define WOLFTPM_DEBUG_TIMEOUT */

/* SPI Wait state checking - most TPMs use this */
#define WOLFTPM_CHECK_WAIT_STATE

/******************************************************************************/
/* --- END wolfTPM U-boot Settings -- */
/******************************************************************************/

#ifdef __cplusplus
}
#endif

#endif /* USER_SETTINGS_H */
