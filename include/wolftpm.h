/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * wolfTPM integration header for U-Boot
 *
 * Copyright (C) 2025 wolfSSL Inc.
 * Author: Aidan Garske <aidan@wolfssl.com>
 */

#ifndef __WOLFTPM_H__
#define __WOLFTPM_H__

#include <wolftpm/tpm2.h>
#include <wolftpm/tpm2_wrap.h>
#include <wolftpm/tpm2_packet.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifdef WOLFTPM_FIRMWARE_UPGRADE
int TPM2_IFX_FwData_Cb(uint8_t *data, uint32_t data_req_sz,
			uint32_t offset, void *cb_ctx);
const char *TPM2_IFX_GetOpModeStr(int opMode);
void TPM2_IFX_PrintInfo(WOLFTPM2_CAPS *caps);
#endif

int TPM2_PCRs_Print(void);
int TPM2_Init_Device(WOLFTPM2_DEV *dev, void *userCtx);

#ifdef __cplusplus
}
#endif

#endif /* __WOLFTPM_H__ */
