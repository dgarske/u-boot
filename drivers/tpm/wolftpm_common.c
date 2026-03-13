// SPDX-License-Identifier: GPL-2.0+
/*
 * wolfTPM common helper functions for U-Boot
 *
 * Copyright (C) 2025 wolfSSL Inc.
 * Author: Aidan Garske <aidan@wolfssl.com>
 */

#define LOG_CATEGORY UCLASS_BOOTSTD

#include <wolftpm.h>
#include <wolftpm/tpm2.h>
#include <wolftpm/tpm2_wrap.h>
#include <wolftpm/tpm2_packet.h>
#include <hal/tpm_io.h>
#include <stdio.h>
#include <string.h>
#include <log.h>
#include <hash.h>
#include <examples/wrap/wrap_test.h>

#ifndef WOLFTPM2_NO_WRAPPER
#ifdef WOLFTPM_FIRMWARE_UPGRADE

/******************************************************************************/
/* --- BEGIN helper functions -- */
/******************************************************************************/

struct fw_info {
	byte *manifest_buf;
	byte *firmware_buf;
	size_t manifest_bufSz;
	size_t firmware_bufSz;
};

int TPM2_IFX_FwData_Cb(uint8_t *data, uint32_t data_req_sz,
			uint32_t offset, void *cb_ctx)
{
	struct fw_info *fwinfo = (struct fw_info *)cb_ctx;

	if (offset > fwinfo->firmware_bufSz)
		return BUFFER_E;
	if (offset + data_req_sz > (uint32_t)fwinfo->firmware_bufSz)
		data_req_sz = (uint32_t)fwinfo->firmware_bufSz - offset;
	if (data_req_sz > 0)
		memcpy(data, &fwinfo->firmware_buf[offset], data_req_sz);
	return data_req_sz;
}

const char *TPM2_IFX_GetOpModeStr(int opMode)
{
	const char *opModeStr = "Unknown";

	switch (opMode) {
	case 0x00:
		opModeStr = "Normal TPM operational mode";
		break;
	case 0x01:
		opModeStr = "TPM firmware update mode (abandon possible)";
		break;
	case 0x02:
		opModeStr = "TPM firmware update mode (abandon not possible)";
		break;
	case 0x03:
		opModeStr = "After successful update, but before finalize";
		break;
	case 0x04:
		opModeStr = "After finalize or abandon, reboot required";
		break;
	default:
		break;
	}
	return opModeStr;
}

void TPM2_IFX_PrintInfo(WOLFTPM2_CAPS *caps)
{
	printf("Mfg %s (%d), Vendor %s, Fw %u.%u (0x%x)\n",
		caps->mfgStr, caps->mfg, caps->vendorStr, caps->fwVerMajor,
		caps->fwVerMinor, caps->fwVerVendor);
	printf("Operational mode: %s (0x%x)\n",
		TPM2_IFX_GetOpModeStr(caps->opMode), caps->opMode);
	printf("KeyGroupId 0x%x, FwCounter %d (%d same)\n",
		caps->keyGroupId, caps->fwCounter, caps->fwCounterSame);
}
#endif /* WOLFTPM_FIRMWARE_UPGRADE */

int TPM2_PCRs_Print(void)
{
	int rc;
	int pcrCount, pcrIndex;
	GetCapability_In  capIn;
	GetCapability_Out capOut;
	TPML_PCR_SELECTION *pcrSel;

	memset(&capIn, 0, sizeof(capIn));
	capIn.capability = TPM_CAP_PCRS;
	capIn.property = 0;
	capIn.propertyCount = 1;
	rc = TPM2_GetCapability(&capIn, &capOut);
	if (rc != TPM_RC_SUCCESS) {
		log_debug("TPM2_GetCapability failed rc=%d (%s)\n",
			  rc, TPM2_GetRCString(rc));
		return rc;
	}
	pcrSel = &capOut.capabilityData.data.assignedPCR;
	printf("Assigned PCR's:\n");
	for (pcrCount = 0; pcrCount < (int)pcrSel->count; pcrCount++) {
		printf("\t%s: ",
		       TPM2_GetAlgName(pcrSel->pcrSelections[pcrCount].hash));
		for (pcrIndex = 0;
		     pcrIndex < pcrSel->pcrSelections[pcrCount].sizeofSelect * 8;
		     pcrIndex++) {
			if ((pcrSel->pcrSelections[pcrCount].pcrSelect[pcrIndex / 8] &
			     ((1 << (pcrIndex % 8)))) != 0)
				printf(" %d", pcrIndex);
		}
		printf("\n");
	}
	return TPM_RC_SUCCESS;
}

int TPM2_Init_Device(WOLFTPM2_DEV *dev, void *userCtx)
{
	int rc;

	/* Use TPM2_IoCb callback for packet-level access */
	rc = wolfTPM2_Init(dev, TPM2_IoCb, userCtx);
	log_debug("tpm2 init: rc = %d (%s)\n", rc, TPM2_GetRCString(rc));
	return rc;
}

#endif /* WOLFTPM2_NO_WRAPPER */

/******************************************************************************/
/* --- END helper functions -- */
/******************************************************************************/
