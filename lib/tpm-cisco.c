// SPDX-License-Identifier: GPL-2.0+
/*
 * Cisco TPM init: start the TPM and report the identity in the SUDI
 * certificate. The result is stored in the "tpmstatus" environment variable,
 * which is passed to Linux user space.
 */

#include <command.h>
#include <env.h>
#include <tpm-cisco.h>
#include <wolftpm.h>
#include <wolftpm/tpm2_asn.h>
#include <linux/errno.h>
#include <linux/string.h>

/* NV indices that may hold the SUDI certificate, tried in order */
static const TPM_HANDLE cisco_sudi_index[] = {
	0x01c30143, 0x01c30147, 0x01c30145, 0x01c3014b,
	0x01c90200, 0x01c90100,
};

/* Subject attributes that may hold "PID:<pid> SN:<sn>", tried in order */
static const byte cisco_oid_serial[] = { 0x55, 0x04, 0x05 };
static const byte cisco_oid_cn[] = { 0x55, 0x04, 0x03 };

/*
 * Find @tag in the attribute value and return the length of the token that
 * follows it, which ends at a space, a '/' or the end of the value.
 */
static int cisco_find_field(const byte *val, word32 val_sz, const char *tag,
			    const char **field)
{
	word32 tag_len = strlen(tag);
	word32 i, n;

	for (i = 0; i + tag_len <= val_sz; i++) {
		if (memcmp(val + i, tag, tag_len))
			continue;
		i += tag_len;
		for (n = 0; i + n < val_sz; n++) {
			if (val[i + n] == ' ' || val[i + n] == '/')
				break;
		}
		*field = (const char *)val + i;
		return n;
	}

	return -ENOENT;
}

static int cisco_print_udi(const byte *subject, word32 subject_sz)
{
	const byte *oids[] = { cisco_oid_serial, cisco_oid_cn };
	const char *pid, *sn;
	const byte *val;
	word32 val_sz;
	int pid_len, sn_len;
	int i;

	for (i = 0; i < ARRAY_SIZE(oids); i++) {
		if (TPM2_ASN_GetNameAttr(subject, subject_sz, oids[i], 3, &val,
					 &val_sz))
			continue;
		pid_len = cisco_find_field(val, val_sz, "PID:", &pid);
		sn_len = cisco_find_field(val, val_sz, "SN:", &sn);
		if (pid_len < 0 || sn_len < 0)
			continue;
		printf("TPM: pid: %.*s, sn: %.*s\n", pid_len, pid, sn_len, sn);
		return 0;
	}

	return -ENOENT;
}

static int cisco_tpm_read_udi(WOLFTPM2_DEV *dev, TPM_HANDLE index)
{
	byte der[MAX_CERT_SZ];
	uint32_t size = sizeof(der);
	DecodedX509 cert;
	int rc;

	rc = wolfTPM2_NVReadCert(dev, index, der, &size);
	if (rc)
		return rc;

	memset(&cert, 0, sizeof(cert));
	rc = TPM2_ASN_DecodeX509Cert(der, size, &cert);
	if (rc)
		return rc;

	return cisco_print_udi(cert.subject, cert.subjectSz);
}

static void cisco_tpm_set_status(const char *value)
{
	if (env_set("tpmstatus", value))
		printf("TPM: could not set tpmstatus=%s\n", value);
}

int cisco_tpm_init(void)
{
	WOLFTPM2_DEV dev;
	int rc, i;

	rc = TPM2_Autostart_Device(&dev);
	if (rc) {
		printf("Error: TPM initialization failed. rc = %d (%s)\n", rc,
		       TPM2_GetRCString(rc));
		cisco_tpm_set_status("failed");
		wolfTPM2_Cleanup_ex(&dev, 0);
		return -EIO;
	}

	for (i = 0; i < ARRAY_SIZE(cisco_sudi_index); i++) {
		rc = cisco_tpm_read_udi(&dev, cisco_sudi_index[i]);
		if (!rc)
			break;
		printf("TPM: certificate index 0x%08x failed. rc = %d\n",
		       cisco_sudi_index[i], rc);
	}
	if (rc)
		printf("Error: no readable SUDI certificate. rc = %d\n", rc);
	cisco_tpm_set_status(rc ? "fail-no-sudi" : "success");

	wolfTPM2_Cleanup_ex(&dev, 0);
	return 0;
}

/* Board code calls cisco_tpm_init(); the command is for testing it */
static int do_tpm_cisco(struct cmd_tbl *cmdtp, int flag, int argc,
			char *const argv[])
{
	return cisco_tpm_init() ? CMD_RET_FAILURE : CMD_RET_SUCCESS;
}

U_BOOT_CMD(
	tpm_cisco, 1, 0, do_tpm_cisco,
	"Initialize the TPM and read the Cisco SUDI certificate",
	""
);
