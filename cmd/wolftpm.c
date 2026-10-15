// SPDX-License-Identifier: GPL-2.0+
/*
 * TPM2 command implementation using wolfTPM library
 *
 * Copyright (C) 2025 wolfSSL Inc.
 * Author: Aidan Garske <aidan@wolfssl.com>
 */

#define LOG_CATEGORY UCLASS_BOOTSTD

#include <wolftpm/tpm2.h>
#include <wolftpm/tpm2_wrap.h>
#include <wolftpm/tpm2_packet.h>
#include <wolftpm.h>

#include <stdio.h>
#include <hash.h>
#ifndef WOLFTPM2_NO_WRAPPER

#include <hal/tpm_io.h>
#include <examples/wrap/wrap_test.h>
#include <wolftpm/tpm2_asn.h>

/* U-boot specific includes */
#include <command.h>
#include <tpm-common.h>
#include <vsprintf.h>
#include <mapmem.h>
#include <env.h>
#include <malloc.h>
#include <errno.h>
#include <log.h>
#include <string.h>

/* Firmware update info structure for Infineon TPM */
#ifdef WOLFTPM_FIRMWARE_UPGRADE
#if defined(WOLFTPM_SLB9672) || defined(WOLFTPM_SLB9673)
struct fw_info {
	byte *manifest_buf;
	byte *firmware_buf;
	size_t manifest_bufSz;
	size_t firmware_bufSz;
};
#endif
#endif

/******************************************************************************/
/* --- BEGIN Common Commands -- */
/******************************************************************************/

int do_tpm2_device(struct cmd_tbl *cmdtp, int flag,
	int argc, char *const argv[])
{
	WOLFTPM2_DEV dev;
	WOLFTPM2_CAPS caps;
	int rc;

	/* Expected 1 arg only in native SPI mode (no device switching) */
	if (argc != 1)
		return CMD_RET_USAGE;

	/* Try to initialize and get device info */
	rc = wolfTPM2_Init(&dev, TPM2_IoCb, NULL);
	if (!rc) {
		rc = wolfTPM2_GetCapabilities(&dev, &caps);
		if (!rc) {
			printf("TPM Device 0: %s (%s) FW=%d.%d\n",
				   caps.mfgStr, caps.vendorStr,
				   caps.fwVerMajor, caps.fwVerMinor);
		}
		wolfTPM2_Cleanup(&dev);
	}

	if (rc != 0) {
		printf("No TPM device found (rc=%d: %s)\n", rc, TPM2_GetRCString(rc));
		return CMD_RET_FAILURE;
	}

	return 0;
}

int do_tpm2_info(struct cmd_tbl *cmdtp, int flag,
	int argc, char *const argv[])
{
	WOLFTPM2_DEV dev;
	WOLFTPM2_CAPS caps;
	int rc;

	if (argc != 1)
		return CMD_RET_USAGE;

	/* Init the TPM2 device */
	rc = wolfTPM2_Init(&dev, TPM2_IoCb, NULL);
	if (!rc) {
		rc = wolfTPM2_GetCapabilities(&dev, &caps);
		if (!rc) {
			printf("TPM 2.0: %s (%s)\n", caps.mfgStr, caps.vendorStr);
			printf("  Firmware: %d.%d (0x%08X)\n",
				   caps.fwVerMajor, caps.fwVerMinor, caps.fwVerVendor);
			printf("  Type: 0x%08X\n", caps.tpmType);
		}
		wolfTPM2_Cleanup(&dev);
	}

	if (rc != 0) {
		printf("Couldn't get TPM info (rc=%d: %s)\n", rc, TPM2_GetRCString(rc));
		return CMD_RET_FAILURE;
	}

	log_debug("tpm2 info: rc = %d (%s)\n", rc, TPM2_GetRCString(rc));
	return 0;
}

int do_tpm2_state(struct cmd_tbl *cmdtp, int flag,
	int argc, char *const argv[])
{
	WOLFTPM2_DEV dev;
	WOLFTPM2_CAPS caps;
	int rc;

	if (argc != 1)
		return CMD_RET_USAGE;

	/* Init the TPM2 device */
	rc = wolfTPM2_Init(&dev, TPM2_IoCb, NULL);
	if (!rc) {
		rc = wolfTPM2_GetCapabilities(&dev, &caps);
		if (!rc) {
			printf("TPM State:\n");
			printf("  Manufacturer: %s\n", caps.mfgStr);
			printf("  Vendor: %s\n", caps.vendorStr);
			printf("  Firmware: %d.%d\n", caps.fwVerMajor, caps.fwVerMinor);
#if defined(WOLFTPM_SLB9672) || defined(WOLFTPM_SLB9673)
			printf("  Mode: Infineon SLB967x (Native SPI)\n");
			printf("  OpMode: %d\n", caps.opMode);
#else
			printf("  Mode: Native wolfTPM SPI\n");
#endif
		}
		wolfTPM2_Cleanup(&dev);
	}

	if (rc != 0) {
		printf("Couldn't get TPM state (rc=%d: %s)\n", rc, TPM2_GetRCString(rc));
		return CMD_RET_FAILURE;
	}

	log_debug("tpm2 state: rc = %d (%s)\n", rc, TPM2_GetRCString(rc));
	return 0;
}

int do_tpm2_init(struct cmd_tbl *cmdtp, int flag, int argc,
	char *const argv[])
{
	WOLFTPM2_DEV dev;

	if (argc != 1)
		return CMD_RET_USAGE;

	/* Init the TPM2 device */
	return TPM2_Init_Device(&dev, NULL);
}

int do_tpm2_autostart(struct cmd_tbl *cmdtp, int flag, int argc,
	char *const argv[])
{
	int rc;
	WOLFTPM2_DEV dev;

	if (argc != 1)
		return CMD_RET_USAGE;

	rc = TPM2_Autostart_Device(&dev);

	log_debug("tpm2 autostart: rc = %d (%s)\n", rc, TPM2_GetRCString(rc));

	return rc;
}

/******************************************************************************/
/* --- END Common Commands -- */
/******************************************************************************/

/******************************************************************************/
/* --- START TPM 2.0 Commands -- */
/******************************************************************************/

int do_tpm2_get_capability(struct cmd_tbl *cmdtp, int flag,
	int argc, char *const argv[])
{
	GetCapability_In  in;
	GetCapability_Out out;
	u32 capability, property, rc;
	u8 *data;
	size_t count;
	int i, j;

	if (argc != 5)
		return CMD_RET_USAGE;

	capability = simple_strtoul(argv[1], NULL, 0);
	property = simple_strtoul(argv[2], NULL, 0);
	data = map_sysmem(simple_strtoul(argv[3], NULL, 0), 0);
	count = simple_strtoul(argv[4], NULL, 0);

	memset(&in, 0, sizeof(in));
	memset(&out, 0, sizeof(out));
	in.capability = capability;
	in.property = property;
	in.propertyCount = count;
	rc = TPM2_GetCapability(&in, &out);
	if (!rc) {
		memcpy(data, &out.capabilityData.data, sizeof(out.capabilityData.data));

		printf("Capabilities read from TPM:\n");
		for (i = 0; i < count; i++) {
			printf("Property 0x");
			for (j = 0; j < 4; j++)
				printf("%02x", data[(i * 8) + j + sizeof(u32)]);
			printf(": 0x");
			for (j = 4; j < 8; j++)
				printf("%02x", data[(i * 8) + j + sizeof(u32)]);
			printf("\n");
		}
	}

	unmap_sysmem(data);

	log_debug("tpm2 get_capability: rc = %d (%s)\n", rc, TPM2_GetRCString(rc));

	return rc;
}

int do_tpm2_caps(struct cmd_tbl *cmdtp, int flag,
	int argc, char *const argv[])
{
	int rc;
	WOLFTPM2_DEV dev;
	WOLFTPM2_CAPS caps;

	if (argc != 1)
		return CMD_RET_USAGE;

	/* Init the TPM2 device */
	rc = TPM2_Init_Device(&dev, NULL);
	if (rc != TPM_RC_SUCCESS)
		return rc;

	rc = wolfTPM2_GetCapabilities(&dev, &caps);
	if (rc != TPM_RC_SUCCESS)
		goto cleanup;

	log_debug("Mfg %s (%d), Vendor %s, Fw %u.%u (0x%x), "
		"FIPS 140-2 %d, CC-EAL4 %d\n",
		caps.mfgStr, caps.mfg, caps.vendorStr, caps.fwVerMajor,
		caps.fwVerMinor, caps.fwVerVendor, caps.fips140_2, caps.cc_eal4);
#if defined(WOLFTPM_SLB9672) || defined(WOLFTPM_SLB9673)
	log_debug("Operational mode: %s (0x%x)\n",
		TPM2_IFX_GetOpModeStr(caps.opMode), caps.opMode);
	log_debug("KeyGroupId 0x%x, FwCounter %d (%d same)\n",
		caps.keyGroupId, caps.fwCounter, caps.fwCounterSame);
#endif

	/* List the active persistent handles */
	rc = wolfTPM2_GetHandles(PERSISTENT_FIRST, NULL);
	if (rc >= TPM_RC_SUCCESS)
		log_debug("Found %d persistent handles\n", rc);

	/* Print the available PCR's */
	rc = TPM2_PCRs_Print();

cleanup:
	/* Only doShutdown=1: Just shut down the TPM */
	wolfTPM2_Reset(&dev, 1, 0);
	wolfTPM2_Cleanup(&dev);

	log_debug("tpm2 caps: rc = %d (%s)\n", rc, TPM2_GetRCString(rc));

	return rc;
}

#ifdef WOLFTPM_FIRMWARE_UPGRADE
#if defined(WOLFTPM_SLB9672) || defined(WOLFTPM_SLB9673)
int do_tpm2_firmware_update(struct cmd_tbl *cmdtp, int flag,
	int argc, char *const argv[])
{
	int rc;
	WOLFTPM2_DEV dev;
	WOLFTPM2_CAPS caps;
	struct fw_info fwinfo;
	ulong manifest_addr, firmware_addr;
	size_t manifest_sz, firmware_sz;
	uint8_t manifest_hash[TPM_SHA384_DIGEST_SIZE];
	int recovery = 0;

	memset(&fwinfo, 0, sizeof(fwinfo));

	/* Need 5 args: command + 4 arguments */
	if (argc != 5) {
		log_debug("Error: Expected 5 arguments but got %d\n", argc);
		return CMD_RET_USAGE;
	}
	printf("TPM2 Firmware Update\n");

	/* Convert all arguments from strings to numbers */
	manifest_addr = simple_strtoul(argv[1], NULL, 0);
	manifest_sz = simple_strtoul(argv[2], NULL, 0);
	firmware_addr = simple_strtoul(argv[3], NULL, 0);
	firmware_sz = simple_strtoul(argv[4], NULL, 0);

	/* Map the memory addresses */
	fwinfo.manifest_buf = map_sysmem(manifest_addr, manifest_sz);
	fwinfo.firmware_buf = map_sysmem(firmware_addr, firmware_sz);
	fwinfo.manifest_bufSz = manifest_sz;
	fwinfo.firmware_bufSz = firmware_sz;

	if (fwinfo.manifest_buf == NULL || fwinfo.firmware_buf == NULL) {
		log_debug("Error: Invalid memory addresses\n");
		return CMD_RET_FAILURE;
	}

	printf("Infineon Firmware Update Tool\n");
	printf("\tManifest Address: 0x%lx (size: %zu)\n",
		manifest_addr, manifest_sz);
	printf("\tFirmware Address: 0x%lx (size: %zu)\n",
		firmware_addr, firmware_sz);

	rc = TPM2_Init_Device(&dev, NULL);
	if (rc != TPM_RC_SUCCESS)
		goto fw_cleanup;

	rc = wolfTPM2_GetCapabilities(&dev, &caps);
	if (rc != TPM_RC_SUCCESS)
		goto fw_cleanup;

	TPM2_IFX_PrintInfo(&caps);
	if (caps.keyGroupId == 0)
		log_debug("Error getting key group id from TPM!\n");
	if (caps.opMode == 0x02 || (caps.opMode & 0x80))
		recovery = 1;

	if (recovery) {
		printf("Firmware Update (recovery mode):\n");
		rc = wolfTPM2_FirmwareUpgradeRecover(&dev,
			fwinfo.manifest_buf, (uint32_t)fwinfo.manifest_bufSz,
			TPM2_IFX_FwData_Cb, &fwinfo);
	} else {
		/* Normal mode - hash with wc_Sha384Hash */
		printf("Firmware Update (normal mode):\n");
		rc = wc_Sha384Hash(fwinfo.manifest_buf,
			(uint32_t)fwinfo.manifest_bufSz, manifest_hash);
		if (rc != TPM_RC_SUCCESS)
			goto fw_cleanup;
		rc = wolfTPM2_FirmwareUpgradeHash(&dev, TPM_ALG_SHA384,
			manifest_hash, (uint32_t)sizeof(manifest_hash),
			fwinfo.manifest_buf, (uint32_t)fwinfo.manifest_bufSz,
			TPM2_IFX_FwData_Cb, &fwinfo);
	}

	if (!rc)
		TPM2_IFX_PrintInfo(&caps);

fw_cleanup:
	if (fwinfo.manifest_buf)
		unmap_sysmem(fwinfo.manifest_buf);
	if (fwinfo.firmware_buf)
		unmap_sysmem(fwinfo.firmware_buf);

	if (rc != TPM_RC_SUCCESS)
		log_debug("Infineon firmware update failed 0x%x: %s\n",
			rc, TPM2_GetRCString(rc));

	wolfTPM2_Cleanup(&dev);

	log_debug("tpm2 firmware_update: rc=%d (%s)\n", rc, TPM2_GetRCString(rc));

	return rc;
}

int do_tpm2_firmware_cancel(struct cmd_tbl *cmdtp, int flag,
	int argc, char *const argv[])
{
	int rc;
	WOLFTPM2_DEV dev;
	uint8_t cmd[TPM2_HEADER_SIZE + 2];
	uint16_t val16;

	if (argc != 1)
		return CMD_RET_USAGE;

	/* Init the TPM2 device */
	rc = TPM2_Init_Device(&dev, NULL);
	if (rc == TPM_RC_SUCCESS) {
		/* Setup command size in header */
		val16 = TPM2_HEADER_SIZE + 2;
		memcpy(cmd, &val16, sizeof(val16));
		val16 = 0;
		memcpy(&cmd[TPM2_HEADER_SIZE], &val16, sizeof(val16));

		rc = TPM2_IFX_FieldUpgradeCommand(TPM_CC_FieldUpgradeAbandonVendor,
			cmd, sizeof(cmd));
		if (rc != TPM_RC_SUCCESS) {
			log_debug("Firmware abandon failed 0x%x: %s\n",
				rc, TPM2_GetRCString(rc));
		}
	}

	wolfTPM2_Cleanup(&dev);

	log_debug("tpm2 firmware_cancel: rc=%d (%s)\n", rc, TPM2_GetRCString(rc));

	return rc;
}
#endif /* WOLFTPM_SLB9672 || WOLFTPM_SLB9673 */
#endif /* WOLFTPM_FIRMWARE_UPGRADE */

int do_tpm2_startup(struct cmd_tbl *cmdtp, int flag,
	int argc, char *const argv[])
{
	int rc;
	WOLFTPM2_DEV dev;
	Startup_In startupIn;
	Shutdown_In shutdownIn;
	int doStartup = YES;

	/* startup TPM2_SU_CLEAR|TPM2_SU_STATE [off] */
	if (argc < 2 || argc > 3)
		return CMD_RET_USAGE;
	/* Check if shutdown requested */
	if (argc == 3) {
		if (strcmp(argv[2], "off") != 0)
			return CMD_RET_USAGE;
		doStartup = NO; /* shutdown */
	}
	printf("TPM2 Startup\n");

	memset(&startupIn, 0, sizeof(startupIn));
	memset(&shutdownIn, 0, sizeof(shutdownIn));

	/* Init the TPM2 device */
	rc = TPM2_Init_Device(&dev, NULL);
	if (rc != TPM_RC_SUCCESS)
		return rc;

	if (!strcmp(argv[1], "TPM2_SU_CLEAR")) {
		if (doStartup == YES)
			startupIn.startupType = TPM_SU_CLEAR;
		else
			shutdownIn.shutdownType = TPM_SU_CLEAR;
	} else if (!strcmp(argv[1], "TPM2_SU_STATE")) {
		if (doStartup == YES)
			startupIn.startupType = TPM_SU_STATE;
		else
			shutdownIn.shutdownType = TPM_SU_STATE;
	} else {
		log_debug("Couldn't recognize mode string: %s\n", argv[1]);
		wolfTPM2_Cleanup(&dev);
		return CMD_RET_FAILURE;
	}

	/* startup */
	if (doStartup == YES) {
		rc = TPM2_Startup(&startupIn);
		/* TPM_RC_INITIALIZE = Already started */
		if (rc != TPM_RC_SUCCESS && rc != TPM_RC_INITIALIZE) {
			log_debug("TPM2 Startup: Result = 0x%x (%s)\n", rc,
				TPM2_GetRCString(rc));
		}
	/* shutdown */
	} else {
		rc = TPM2_Shutdown(&shutdownIn);
		if (rc != TPM_RC_SUCCESS) {
			log_debug("TPM2 Shutdown: Result = 0x%x (%s)\n", rc,
				TPM2_GetRCString(rc));
		}
	}

	wolfTPM2_Cleanup(&dev);

	if (rc >= 0)
		rc = 0;

	log_debug("tpm2 startup (%s): rc = %d (%s)\n",
		doStartup ? "startup" : "shutdown", rc, TPM2_GetRCString(rc));

	return rc;
}

int do_tpm2_selftest(struct cmd_tbl *cmdtp, int flag,
	int argc, char *const argv[])
{
	int rc;
	WOLFTPM2_DEV dev;
	TPMI_YES_NO fullTest = YES;

	/* Need 2 arg: command + type */
	if (argc != 2)
		return CMD_RET_USAGE;

	/* Init the TPM2 device */
	rc = TPM2_Init_Device(&dev, NULL);
	if (rc == TPM_RC_SUCCESS) {
		if (!strcmp(argv[1], "full")) {
			fullTest = YES;
		} else if (!strcmp(argv[1], "continue")) {
			fullTest = NO;
		} else {
			log_debug("Couldn't recognize test mode: %s\n", argv[1]);
			wolfTPM2_Cleanup(&dev);
			return CMD_RET_FAILURE;
		}

		/* full test */
		if (fullTest == YES) {
			rc = wolfTPM2_SelfTest(&dev);
			if (rc != TPM_RC_SUCCESS) {
				log_debug("TPM2 Self Test: Result = 0x%x (%s)\n", rc,
					TPM2_GetRCString(rc));
			}
		/* continue test */
		} else {
			rc = wolfTPM2_SelfTest(&dev);
			if (rc != TPM_RC_SUCCESS) {
				log_debug("TPM2 Self Test: Result = 0x%x (%s)\n", rc,
					TPM2_GetRCString(rc));
			}
		}
	}

	wolfTPM2_Cleanup(&dev);

	log_debug("tpm2 selftest (%s): rc = %d (%s)\n",
		fullTest ? "full" : "continue", rc, TPM2_GetRCString(rc));

	return rc;
}

int do_tpm2_clear(struct cmd_tbl *cmdtp, int flag,
	int argc, char *const argv[])
{
	int rc;
	WOLFTPM2_DEV dev;
	Clear_In clearIn;
	TPMI_RH_CLEAR handle;

	/* Need 2 arg: command + type */
	if (argc != 2)
		return CMD_RET_USAGE;

	if (!strcasecmp("TPM2_RH_LOCKOUT", argv[1]))
		handle = TPM_RH_LOCKOUT;
	else if (!strcasecmp("TPM2_RH_PLATFORM", argv[1]))
		handle = TPM_RH_PLATFORM;
	else
		return CMD_RET_USAGE;

	/* Init the TPM2 device */
	rc = TPM2_Init_Device(&dev, NULL);
	if (rc == TPM_RC_SUCCESS) {
		/* Set up clear */
		memset(&clearIn, 0, sizeof(clearIn));
		clearIn.authHandle = handle;

		rc = TPM2_Clear(&clearIn);
		if (rc != TPM_RC_SUCCESS) {
			log_debug("TPM2 Clear: Result = 0x%x (%s)\n", rc,
				TPM2_GetRCString(rc));
		}
	}

	wolfTPM2_Cleanup(&dev);

	log_debug("tpm2 clear (%s): rc = %d (%s)\n",
		handle == TPM_RH_LOCKOUT ? "TPM2_RH_LOCKOUT" : "TPM2_RH_PLATFORM",
		rc, TPM2_GetRCString(rc));

	return rc;
}

int do_tpm2_pcr_extend(struct cmd_tbl *cmdtp, int flag,
	int argc, char *const argv[])
{
	int rc;
	WOLFTPM2_DEV dev;
	uint32_t pcrIndex;
	int algo = TPM_ALG_SHA256;
	int digestLen;
	void *digest;
	ulong digest_addr;

	/* Need 3-4 args: command + pcr + digest_addr + [algo] */
	if (argc < 3 || argc > 4)
		return CMD_RET_USAGE;
	printf("TPM2 PCR Extend\n");

	pcrIndex = simple_strtoul(argv[1], NULL, 0);
	digest_addr = simple_strtoul(argv[2], NULL, 0);

	/* Optional algorithm */
	if (argc == 4) {
		algo = TPM2_GetAlgId(argv[3]);
		if (algo < 0) {
			log_debug("Couldn't recognize algorithm: %s\n", argv[3]);
			return CMD_RET_FAILURE;
		}
		log_debug("Using algorithm: %s\n", TPM2_GetAlgName(algo));
	}

	/* Get digest length based on algorithm */
	digestLen = TPM2_GetHashDigestSize(algo);
	if (digestLen <= 0) {
		log_debug("Invalid algorithm digest length\n");
		return CMD_RET_FAILURE;
	}

	/* Map digest from memory address */
	digest = map_sysmem(digest_addr, digestLen);
	if (digest == NULL) {
		log_debug("Error: Invalid digest memory address\n");
		return CMD_RET_FAILURE;
	}

	log_debug("TPM2 PCR Extend: PCR %u with %s digest\n",
		(unsigned int)pcrIndex, TPM2_GetAlgName(algo));

	/* Init the TPM2 device */
	rc = TPM2_Init_Device(&dev, NULL);
	if (rc != TPM_RC_SUCCESS) {
		unmap_sysmem(digest);
		return rc;
	}

	/* Extend the PCR */
	rc = wolfTPM2_ExtendPCR(&dev, pcrIndex, algo, digest, digestLen);
	if (rc != TPM_RC_SUCCESS) {
		log_debug("TPM2_PCR_Extend failed 0x%x: %s\n", rc,
			TPM2_GetRCString(rc));
	}

	unmap_sysmem(digest);
	wolfTPM2_Cleanup(&dev);

	log_debug("tpm2 pcr_extend: rc = %d (%s)\n", rc, TPM2_GetRCString(rc));

	return rc;
}

int do_tpm2_pcr_read(struct cmd_tbl *cmdtp, int flag,
	int argc, char *const argv[])
{
	int rc;
	WOLFTPM2_DEV dev;
	uint32_t pcrIndex;
	int algo = TPM_ALG_SHA256;
	void *digest;
	ulong digest_addr;
	int digestLen;

	/* Need 3-4 args: command + pcr + digest_addr + [algo] */
	if (argc < 3 || argc > 4)
		return CMD_RET_USAGE;

	pcrIndex = simple_strtoul(argv[1], NULL, 0);
	digest_addr = simple_strtoul(argv[2], NULL, 0);

	/* Optional algorithm */
	if (argc == 4) {
		algo = TPM2_GetAlgId(argv[3]);
		if (algo < 0) {
			log_debug("Couldn't recognize algorithm: %s\n", argv[3]);
			return CMD_RET_FAILURE;
		}
		log_debug("Using algorithm: %s\n", TPM2_GetAlgName(algo));
	}

	/* Get digest length based on algorithm */
	digestLen = TPM2_GetHashDigestSize(algo);
	if (digestLen <= 0) {
		log_debug("Invalid algorithm digest length\n");
		return CMD_RET_FAILURE;
	}

	/* Map digest from memory address */
	digest = map_sysmem(digest_addr, digestLen);
	if (digest == NULL) {
		log_debug("Error: Invalid digest memory address\n");
		return CMD_RET_FAILURE;
	}

	log_debug("TPM2 PCR Read: PCR %u to %s digest\n",
		(unsigned int)pcrIndex, TPM2_GetAlgName(algo));

	/* Init the TPM2 device */
	rc = TPM2_Init_Device(&dev, NULL);
	if (rc != TPM_RC_SUCCESS) {
		unmap_sysmem(digest);
		return rc;
	}

	/* Read the PCR */
	rc = wolfTPM2_ReadPCR(&dev, pcrIndex, algo, digest, &digestLen);
	if (rc != TPM_RC_SUCCESS) {
		log_debug("TPM2_PCR_Read failed 0x%x: %s\n", rc,
			TPM2_GetRCString(rc));
	}

	unmap_sysmem(digest);
	wolfTPM2_Cleanup(&dev);

	log_debug("tpm2 pcr_read: rc = %d (%s)\n", rc, TPM2_GetRCString(rc));

	return rc;
}

int do_tpm2_pcr_allocate(struct cmd_tbl *cmdtp, int flag,
	int argc, char *const argv[])
{
	int rc;
	WOLFTPM2_DEV dev;
	PCR_Allocate_In in;
	PCR_Allocate_Out out;
	TPM2B_AUTH auth;

	/* Need 3-4 args: command + algorithm + on/off + [password] */
	if (argc < 3 || argc > 4)
		return CMD_RET_USAGE;

	/* Init the TPM2 device */
	rc = TPM2_Init_Device(&dev, NULL);
	if (rc != TPM_RC_SUCCESS)
		return rc;

	/* Setup PCR Allocation command */
	memset(&in, 0, sizeof(in));
	in.authHandle = TPM_RH_PLATFORM;

	/* Single PCR bank allocation */
	in.pcrAllocation.count = 1; /* Change only one bank */
	in.pcrAllocation.pcrSelections[0].hash = TPM2_GetAlgId(argv[1]);
	in.pcrAllocation.pcrSelections[0].sizeofSelect = PCR_SELECT_MAX;

	/* Set all PCRs for this algorithm */
	if (!strcmp(argv[2], "on")) {
		memset(in.pcrAllocation.pcrSelections[0].pcrSelect, 0xFF,
			PCR_SELECT_MAX);
	} else if (!strcmp(argv[2], "off")) {
		/* Clear all PCRs for this algorithm */
		memset(in.pcrAllocation.pcrSelections[0].pcrSelect, 0x00,
			PCR_SELECT_MAX);
	} else {
		log_debug("Couldn't recognize allocate mode: %s\n", argv[2]);
		wolfTPM2_Cleanup(&dev);
		return CMD_RET_USAGE;
	}
	log_debug("Attempting to set %s bank to %s\n",
		TPM2_GetAlgName(in.pcrAllocation.pcrSelections[0].hash),
		argv[2]);

	/* Set auth password if provided */
	if (argc == 4) {
		memset(&auth, 0, sizeof(auth));
		auth.size = strlen(argv[3]);
		memcpy(auth.buffer, argv[3], auth.size);
		rc = wolfTPM2_SetAuth(&dev, 0, TPM_RH_PLATFORM, &auth, 0, NULL);
		if (rc != TPM_RC_SUCCESS) {
			log_debug("wolfTPM2_SetAuth failed 0x%x: %s\n", rc,
				TPM2_GetRCString(rc));
			wolfTPM2_Cleanup(&dev);
			return rc;
		}
	}

	/* Allocate the PCR */
	rc = TPM2_PCR_Allocate(&in, &out);
	if (rc != TPM_RC_SUCCESS) {
		log_debug("TPM2_PCR_Allocate failed 0x%x: %s\n", rc,
			TPM2_GetRCString(rc));
	}

	/* Print current PCR state */
	printf("\n\tNOTE: A TPM restart is required for changes to take effect\n");
	printf("\nCurrent PCR state:\n");
	TPM2_PCRs_Print();

	wolfTPM2_Cleanup(&dev);

	printf("Allocation Success: %s\n",
		out.allocationSuccess ? "YES" : "NO");
	log_debug("tpm2 pcr_allocate %s (%s): rc = %d (%s)\n",
		TPM2_GetAlgName(in.pcrAllocation.pcrSelections[0].hash),
		argv[2], rc, TPM2_GetRCString(rc));

	return rc;
}

/*
 * Without wolfCrypt, parameter encryption is not available.
 * A session is required to protect the new platform auth.
 */
#ifndef WOLFTPM2_NO_WOLFCRYPT
static int TPM2_PCR_SetAuth(int argc, char *const argv[],
	int isPolicy)
{
	int rc;
	WOLFTPM2_DEV dev;
	WOLFTPM2_SESSION session;
	TPM2B_AUTH auth;
	const char *pw = (argc < 4) ? NULL : argv[3];
	const char *key = argv[2];
	const ssize_t key_sz = strlen(key);
	u32 pcrIndex = simple_strtoul(argv[1], NULL, 0);

	/* Need 3-4 args: command + pcr + auth + [platform_auth] */
	if (argc < 3 || argc > 4)
		return CMD_RET_USAGE;

	/* Init the TPM2 device for value/policy */
	rc = TPM2_Init_Device(&dev, NULL);
	if (rc != TPM_RC_SUCCESS)
		return rc;

	/* Start the session */
	rc = wolfTPM2_StartSession(&dev, &session, NULL, NULL,
		isPolicy ? TPM_SE_POLICY : TPM_SE_HMAC, TPM_ALG_NULL);
	if (rc != TPM_RC_SUCCESS) {
		log_debug("wolfTPM2_StartSession failed 0x%x: %s\n", rc,
			TPM2_GetRCString(rc));
		wolfTPM2_Cleanup(&dev);
		return rc;
	}

	/* Set the platform auth if provided */
	if (pw) {
		TPM2B_AUTH platformAuth;

		memset(&platformAuth, 0, sizeof(platformAuth));
		platformAuth.size = strlen(pw);
		memcpy(platformAuth.buffer, pw, platformAuth.size);
		rc = wolfTPM2_SetAuth(&dev, 0, TPM_RH_PLATFORM,
			&platformAuth, 0, NULL);
		if (rc != TPM_RC_SUCCESS) {
			log_debug("wolfTPM2_SetAuth failed 0x%x: %s\n", rc,
				TPM2_GetRCString(rc));
			wolfTPM2_UnloadHandle(&dev, &session.handle);
			wolfTPM2_Cleanup(&dev);
			return rc;
		}
	}

	printf("Setting %s auth for PCR %u\n",
		isPolicy ? "policy" : "value", pcrIndex);

	/* Set up the auth value/policy */
	memset(&auth, 0, sizeof(auth));
	auth.size = key_sz;
	memcpy(auth.buffer, key, key_sz);

	if (isPolicy) {
		/* Use TPM2_PCR_SetAuthPolicy command */
		PCR_SetAuthPolicy_In in;

		memset(&in, 0, sizeof(in));
		in.authHandle = TPM_RH_PLATFORM;
		in.authPolicy = auth;
		in.hashAlg = TPM_ALG_SHA256; /* Default to SHA256 */
		in.pcrNum = pcrIndex;
		rc = TPM2_PCR_SetAuthPolicy(&in);
	} else {
		/* Use TPM2_PCR_SetAuthValue command */
		PCR_SetAuthValue_In in;

		memset(&in, 0, sizeof(in));
		in.pcrHandle = pcrIndex;
		in.auth = auth;
		rc = TPM2_PCR_SetAuthValue(&in);
	}

	if (rc != TPM_RC_SUCCESS) {
		log_debug("TPM2_PCR_SetAuth%s failed 0x%x: %s\n",
			isPolicy ? "Policy" : "Value",
			rc, TPM2_GetRCString(rc));
	}

	wolfTPM2_UnloadHandle(&dev, &session.handle);
	wolfTPM2_Cleanup(&dev);

	log_debug("tpm2 set_auth %s: rc = %d (%s)\n",
		isPolicy ? "Policy" : "Value", rc, TPM2_GetRCString(rc));

	return rc;
}

int do_tpm2_pcr_setauthpolicy(struct cmd_tbl *cmdtp, int flag,
	int argc, char *const argv[])
{
	return TPM2_PCR_SetAuth(argc, argv, YES);
}

int do_tpm2_pcr_setauthvalue(struct cmd_tbl *cmdtp, int flag,
	int argc, char *const argv[])
{
	return TPM2_PCR_SetAuth(argc, argv, NO);
}

int do_tpm2_change_auth(struct cmd_tbl *cmdtp, int flag,
	int argc, char *const argv[])
{
	int rc;
	WOLFTPM2_DEV dev;
	WOLFTPM2_SESSION session;
	const char *newpw = argv[2];
	const char *oldpw = (argc == 4) ? argv[3] : NULL;
	const ssize_t newpw_sz = strlen(newpw);
	const ssize_t oldpw_sz = oldpw ? strlen(oldpw) : 0;
	HierarchyChangeAuth_In in;
	TPM2B_AUTH newAuth;

	/* Need 3-4 args: command + hierarchy + new_pw + [old_pw] */
	if (argc < 3 || argc > 4)
		return CMD_RET_USAGE;

	/* Init the TPM2 device */
	rc = TPM2_Init_Device(&dev, NULL);
	if (rc != TPM_RC_SUCCESS)
		return rc;

	memset(&in, 0, sizeof(in));

	/* Set the handle */
	if (!strcmp(argv[1], "TPM2_RH_LOCKOUT"))
		in.authHandle = TPM_RH_LOCKOUT;
	else if (!strcmp(argv[1], "TPM2_RH_ENDORSEMENT"))
		in.authHandle = TPM_RH_ENDORSEMENT;
	else if (!strcmp(argv[1], "TPM2_RH_OWNER"))
		in.authHandle = TPM_RH_OWNER;
	else if (!strcmp(argv[1], "TPM2_RH_PLATFORM"))
		in.authHandle = TPM_RH_PLATFORM;
	else {
		wolfTPM2_Cleanup(&dev);
		return CMD_RET_USAGE;
	}

	/* Validate password length if provided */
	if (newpw_sz > TPM_SHA256_DIGEST_SIZE ||
		oldpw_sz > TPM_SHA256_DIGEST_SIZE) {
		wolfTPM2_Cleanup(&dev);
		return -EINVAL;
	}

	/* Start auth session */
	rc = wolfTPM2_StartSession(&dev, &session, NULL, NULL,
		TPM_SE_HMAC, TPM_ALG_CFB);
	if (rc != TPM_RC_SUCCESS) {
		log_debug("wolfTPM2_StartSession failed 0x%x: %s\n", rc,
			TPM2_GetRCString(rc));
		wolfTPM2_Cleanup(&dev);
		return rc;
	}

	/* If old password exists then set it as the current auth */
	if (oldpw) {
		TPM2B_AUTH oldAuth;

		memset(&oldAuth, 0, sizeof(oldAuth));
		oldAuth.size = oldpw_sz;
		memcpy(oldAuth.buffer, oldpw, oldpw_sz);
		rc = wolfTPM2_SetAuthPassword(&dev, 0, &oldAuth);
		if (rc != TPM_RC_SUCCESS) {
			log_debug("wolfTPM2_SetAuthPassword failed 0x%x: %s\n", rc,
				TPM2_GetRCString(rc));
			wolfTPM2_UnloadHandle(&dev, &session.handle);
			wolfTPM2_Cleanup(&dev);
			return rc;
		}
	}

	memset(&newAuth, 0, sizeof(newAuth));
	newAuth.size = newpw_sz;
	memcpy(newAuth.buffer, newpw, newpw_sz);
	in.newAuth = newAuth;

	/* Change the auth based on the hierarchy */
	rc = wolfTPM2_ChangeHierarchyAuth(&dev, &session, in.authHandle);
	if (rc != TPM_RC_SUCCESS) {
		log_debug("wolfTPM2_ChangeHierarchyAuth failed 0x%x: %s\n", rc,
			TPM2_GetRCString(rc));
	} else {
		log_debug("Successfully changed auth for %s\n", argv[1]);
	}

	wolfTPM2_UnloadHandle(&dev, &session.handle);
	wolfTPM2_Cleanup(&dev);

	log_debug("tpm2 change_auth: rc = %d (%s)\n", rc, TPM2_GetRCString(rc));

	return rc;
}
#else /* WOLFTPM2_NO_WOLFCRYPT */
int do_tpm2_change_auth(struct cmd_tbl *cmdtp, int flag,
	int argc, char *const argv[])
{
	printf("wolfCrypt support required for change_auth\n");
	return CMD_RET_FAILURE;
}

int do_tpm2_pcr_setauthpolicy(struct cmd_tbl *cmdtp, int flag,
	int argc, char *const argv[])
{
	printf("wolfCrypt support required for pcr_setauthpolicy\n");
	return CMD_RET_FAILURE;
}

int do_tpm2_pcr_setauthvalue(struct cmd_tbl *cmdtp, int flag,
	int argc, char *const argv[])
{
	printf("wolfCrypt support required for pcr_setauthvalue\n");
	return CMD_RET_FAILURE;
}
#endif /* !WOLFTPM2_NO_WOLFCRYPT */

int do_tpm2_pcr_print(struct cmd_tbl *cmdtp, int flag, int argc, char *const argv[])
{
	int rc;
	WOLFTPM2_DEV dev;

	/* Need 1 arg: command */
	if (argc != 1)
		return CMD_RET_USAGE;

	/* Init the TPM2 device */
	rc = TPM2_Init_Device(&dev, NULL);
	if (rc == TPM_RC_SUCCESS) {
		/* Print the current PCR state */
		TPM2_PCRs_Print();
	}
	wolfTPM2_Cleanup(&dev);

	log_debug("tpm2 pcr_print: rc = %d (%s)\n", rc, TPM2_GetRCString(rc));

	return rc;
}

static void tpm2_print_name(const char *label, const byte *name, word32 nameSz)
{
	static const struct {
		const char *str;
		byte oid[3];
	} attrs[] = {
		{ "CN", { 0x55, 0x04, 0x03 } },
		{ "serialNumber", { 0x55, 0x04, 0x05 } },
		{ "O", { 0x55, 0x04, 0x0a } },
		{ "OU", { 0x55, 0x04, 0x0b } },
	};
	const byte *val;
	word32 valSz;
	int i;

	printf("%s:", label);
	for (i = 0; i < ARRAY_SIZE(attrs); i++) {
		if (TPM2_ASN_GetNameAttr(name, nameSz, attrs[i].oid,
					 sizeof(attrs[i].oid), &val, &valSz) == 0)
			printf(" %s=%.*s", attrs[i].str, (int)valSz, val);
	}
	printf("\n");
}

int do_tpm2_nv_read_cert(struct cmd_tbl *cmdtp, int flag, int argc,
			 char *const argv[])
{
	int rc;
	WOLFTPM2_DEV dev;
	DecodedX509 x509;
	TPM_HANDLE handle;
	ulong addr = 0;
	uint32_t size = 0;
	byte *buf = NULL;

	if (argc < 2 || argc > 3)
		return CMD_RET_USAGE;

	handle = simple_strtoul(argv[1], NULL, 0);
	if (argc == 3)
		addr = simple_strtoul(argv[2], NULL, 0);

	rc = TPM2_Init_Device(&dev, NULL);
	if (rc != TPM_RC_SUCCESS) {
		printf("Couldn't init TPM (rc=%d: %s)\n", rc,
		       TPM2_GetRCString(rc));
		return CMD_RET_FAILURE;
	}

	/* A NULL buffer only returns the size of the NV index */
	rc = wolfTPM2_NVReadCert(&dev, handle, NULL, &size);
	if (rc == TPM_RC_SUCCESS && size == 0)
		rc = BUFFER_E;
	if (rc == TPM_RC_SUCCESS) {
		buf = argc == 3 ? map_sysmem(addr, size) : malloc(size);
		if (!buf)
			rc = MEMORY_E;
	}
	if (rc == TPM_RC_SUCCESS)
		rc = wolfTPM2_NVReadCert(&dev, handle, buf, &size);

	if (rc == TPM_RC_SUCCESS) {
		printf("NV index 0x%08x: %u bytes\n", handle, size);
		memset(&x509, 0, sizeof(x509));
		if (TPM2_ASN_DecodeX509Cert(buf, size, &x509) == 0) {
			tpm2_print_name("Subject", x509.subject,
					x509.subjectSz);
			tpm2_print_name("Issuer", x509.issuer, x509.issuerSz);
		} else {
			printf("Not an X.509 certificate\n");
		}
		if (argc == 3)
			env_set_hex("filesize", size);
	}

	if (argc == 3) {
		if (buf)
			unmap_sysmem(buf);
	} else {
		free(buf);
	}
	wolfTPM2_Cleanup(&dev);

	if (rc != TPM_RC_SUCCESS) {
		printf("Couldn't read certificate from NV index 0x%08x (rc=%d: %s)\n",
		       handle, rc, TPM2_GetRCString(rc));
		return CMD_RET_FAILURE;
	}

	return CMD_RET_SUCCESS;
}

int do_tpm2_dam_reset(struct cmd_tbl *cmdtp, int flag,
	int argc, char *const argv[])
{
	int rc;
	WOLFTPM2_DEV dev;
	const char *pw = (argc < 2) ? NULL : argv[1];
	const ssize_t pw_sz = pw ? strlen(pw) : 0;
	DictionaryAttackLockReset_In in;
	TPM2_AUTH_SESSION session[MAX_SESSION_NUM];

	/* Need 1-2 args: command + [password] */
	if (argc > 2)
		return CMD_RET_USAGE;

	/* Validate password length if provided */
	if (pw && pw_sz > TPM_SHA256_DIGEST_SIZE) {
		log_debug("Error: Password too long\n");
		return -EINVAL;
	}

	/* Init the TPM2 device */
	rc = TPM2_Init_Device(&dev, NULL);
	if (rc == TPM_RC_SUCCESS) {
		/* set lock handle */
		memset(&in, 0, sizeof(in));
		in.lockHandle = TPM_RH_LOCKOUT;

		/* Setup auth session only if password provided */
		memset(session, 0, sizeof(session));
		session[0].sessionHandle = TPM_RS_PW;
		if (pw) {
			session[0].auth.size = pw_sz;
			memcpy(session[0].auth.buffer, pw, pw_sz);
		}
		TPM2_SetSessionAuth(session);

		rc = TPM2_DictionaryAttackLockReset(&in);
		log_debug("TPM2_Dam_Reset: Result = 0x%x (%s)\n", rc,
			TPM2_GetRCString(rc));
	}
	wolfTPM2_Cleanup(&dev);

	log_debug("tpm2 dam_reset: rc = %d (%s)\n", rc, TPM2_GetRCString(rc));

	return rc;
}

int do_tpm2_dam_parameters(struct cmd_tbl *cmdtp, int flag,
	int argc, char *const argv[])
{
	int rc;
	WOLFTPM2_DEV dev;
	const char *pw = (argc < 5) ? NULL : argv[4];
	const ssize_t pw_sz = pw ? strlen(pw) : 0;
	DictionaryAttackParameters_In in;
	TPM2_AUTH_SESSION session[MAX_SESSION_NUM];

	/*
	 * Need 4-5 args: command + max_tries + recovery_time +
	 * lockout_recovery + [password]
	 */
	if (argc < 4 || argc > 5)
		return CMD_RET_USAGE;

	/* Validate password length if provided */
	if (pw && pw_sz > TPM_SHA256_DIGEST_SIZE) {
		log_debug("Error: Password too long\n");
		return -EINVAL;
	}

	/* Init the TPM2 device */
	rc = TPM2_Init_Device(&dev, NULL);
	if (rc == TPM_RC_SUCCESS) {
		/* Set parameters */
		memset(&in, 0, sizeof(in));
		in.newMaxTries = simple_strtoul(argv[1], NULL, 0);
		in.newRecoveryTime = simple_strtoul(argv[2], NULL, 0);
		in.lockoutRecovery = simple_strtoul(argv[3], NULL, 0);

		/* set lock handle */
		in.lockHandle = TPM_RH_LOCKOUT;

		/* Setup auth session only if password provided */
		memset(session, 0, sizeof(session));
		session[0].sessionHandle = TPM_RS_PW;
		if (pw) {
			session[0].auth.size = pw_sz;
			memcpy(session[0].auth.buffer, pw, pw_sz);
		}
		TPM2_SetSessionAuth(session);

		/* Set DAM parameters */
		rc = TPM2_DictionaryAttackParameters(&in);
		if (rc != TPM_RC_SUCCESS) {
			log_debug("TPM2_DictionaryAttackParameters failed 0x%x: %s\n", rc,
				TPM2_GetRCString(rc));
		}

		printf("Changing dictionary attack parameters:\n");
		printf("  maxTries: %u\n", in.newMaxTries);
		printf("  recoveryTime: %u\n", in.newRecoveryTime);
		printf("  lockoutRecovery: %u\n", in.lockoutRecovery);
	}
	wolfTPM2_Cleanup(&dev);

	log_debug("tpm2 dam_parameters: rc = %d (%s)\n", rc, TPM2_GetRCString(rc));

	return rc;
}

#endif /* !WOLFTPM2_NO_WRAPPER */
