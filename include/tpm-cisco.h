/* SPDX-License-Identifier: GPL-2.0+ */

#ifndef __TPM_CISCO_H
#define __TPM_CISCO_H

/**
 * cisco_tpm_init() - start the TPM and read the SUDI certificate
 *
 * Sets the "tpmstatus" environment variable to "success", "fail-no-sudi"
 * or "failed".
 *
 * Return: 0 if the TPM started (whether or not a SUDI certificate was
 * found), -EIO if the TPM could not be started
 */
int cisco_tpm_init(void);

#endif /* __TPM_CISCO_H */
