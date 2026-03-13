// SPDX-License-Identifier: GPL-2.0+
/*
 * Native TPM2 backend implementation
 *
 * Copyright (c) 2018 Bootlin
 * Author: Miquel Raynal <miquel.raynal@bootlin.com>
 */

#include <command.h>
#include <dm.h>
#include <log.h>
#include <mapmem.h>
#include <tpm-common.h>
#include <tpm-v2.h>
#include "tpm-user-utils.h"

/* Wrappers for common commands - delegate to tpm-common.c */
int do_tpm2_device(struct cmd_tbl *cmdtp, int flag, int argc,
		   char *const argv[])
{
	return do_tpm_device(cmdtp, flag, argc, argv);
}

int do_tpm2_info(struct cmd_tbl *cmdtp, int flag, int argc,
		 char *const argv[])
{
	return do_tpm_info(cmdtp, flag, argc, argv);
}

int do_tpm2_state(struct cmd_tbl *cmdtp, int flag, int argc,
		  char *const argv[])
{
	return do_tpm_report_state(cmdtp, flag, argc, argv);
}

int do_tpm2_init(struct cmd_tbl *cmdtp, int flag, int argc,
		 char *const argv[])
{
	return do_tpm_init(cmdtp, flag, argc, argv);
}

int do_tpm2_autostart(struct cmd_tbl *cmdtp, int flag, int argc,
		      char *const argv[])
{
	return do_tpm_autostart(cmdtp, flag, argc, argv);
}

int do_tpm2_startup(struct cmd_tbl *cmdtp, int flag, int argc,
		    char *const argv[])
{
	enum tpm2_startup_types mode;
	struct udevice *dev;
	int ret;
	bool bon = true;

	ret = get_tpm(&dev);
	if (ret)
		return ret;

	/* argv[2] is optional to perform a TPM2_CC_SHUTDOWN */
	if (argc > 3 || (argc == 3 && strcasecmp("off", argv[2])))
		return CMD_RET_USAGE;

	if (!strcasecmp("TPM2_SU_CLEAR", argv[1])) {
		mode = TPM2_SU_CLEAR;
	} else if (!strcasecmp("TPM2_SU_STATE", argv[1])) {
		mode = TPM2_SU_STATE;
	} else {
		printf("Couldn't recognize mode string: %s\n", argv[1]);
		return CMD_RET_FAILURE;
	}

	if (argv[2])
		bon = false;

	return report_return_code(tpm2_startup(dev, bon, mode));
}

int do_tpm2_selftest(struct cmd_tbl *cmdtp, int flag, int argc,
		     char *const argv[])
{
	enum tpm2_yes_no full_test;
	struct udevice *dev;
	int ret;

	ret = get_tpm(&dev);
	if (ret)
		return ret;
	if (argc != 2)
		return CMD_RET_USAGE;

	if (!strcasecmp("full", argv[1])) {
		full_test = TPMI_YES;
	} else if (!strcasecmp("continue", argv[1])) {
		full_test = TPMI_NO;
	} else {
		printf("Couldn't recognize test mode: %s\n", argv[1]);
		return CMD_RET_FAILURE;
	}

	return report_return_code(tpm2_self_test(dev, full_test));
}

int do_tpm2_clear(struct cmd_tbl *cmdtp, int flag, int argc,
		  char *const argv[])
{
	u32 handle = 0;
	const char *pw = (argc < 3) ? NULL : argv[2];
	const ssize_t pw_sz = pw ? strlen(pw) : 0;
	struct udevice *dev;
	int ret;

	ret = get_tpm(&dev);
	if (ret)
		return ret;

	if (argc < 2 || argc > 3)
		return CMD_RET_USAGE;

	if (pw_sz > TPM2_DIGEST_LEN)
		return -EINVAL;

	if (!strcasecmp("TPM2_RH_LOCKOUT", argv[1]))
		handle = TPM2_RH_LOCKOUT;
	else if (!strcasecmp("TPM2_RH_PLATFORM", argv[1]))
		handle = TPM2_RH_PLATFORM;
	else
		return CMD_RET_USAGE;

	return report_return_code(tpm2_clear(dev, handle, pw, pw_sz));
}

int do_tpm2_pcr_extend(struct cmd_tbl *cmdtp, int flag, int argc,
		       char *const argv[])
{
	struct udevice *dev;
	struct tpm_chip_priv *priv;
	u32 index = simple_strtoul(argv[1], NULL, 0);
	void *digest = map_sysmem(simple_strtoul(argv[2], NULL, 0), 0);
	int algo = TPM2_ALG_SHA256;
	int algo_len;
	int ret;
	u32 rc;

	if (argc < 3 || argc > 4)
		return CMD_RET_USAGE;
	if (argc == 4) {
		algo = tpm2_name_to_algorithm(argv[3]);
		if (algo == TPM2_ALG_INVAL)
			return CMD_RET_FAILURE;
	}
	algo_len = tpm2_algorithm_to_len(algo);

	ret = get_tpm(&dev);
	if (ret)
		return ret;

	priv = dev_get_uclass_priv(dev);
	if (!priv)
		return -EINVAL;

	if (index >= priv->pcr_count)
		return -EINVAL;

	rc = tpm2_pcr_extend(dev, index, algo, digest, algo_len);
	if (!rc) {
		printf("PCR #%u extended with %d byte %s digest\n", index,
		       algo_len, tpm2_algorithm_name(algo));
		print_byte_string(digest, algo_len);
	}

	unmap_sysmem(digest);

	return report_return_code(rc);
}

int do_tpm2_pcr_read(struct cmd_tbl *cmdtp, int flag, int argc,
		     char *const argv[])
{
	enum tpm2_algorithms algo = TPM2_ALG_SHA256;
	struct udevice *dev;
	struct tpm_chip_priv *priv;
	u32 index, rc;
	int algo_len;
	unsigned int updates;
	void *data;
	int ret;

	if (argc < 3 || argc > 4)
		return CMD_RET_USAGE;
	if (argc == 4) {
		algo = tpm2_name_to_algorithm(argv[3]);
		if (algo == TPM2_ALG_INVAL)
			return CMD_RET_FAILURE;
	}
	algo_len = tpm2_algorithm_to_len(algo);

	ret = get_tpm(&dev);
	if (ret)
		return ret;

	priv = dev_get_uclass_priv(dev);
	if (!priv)
		return -EINVAL;

	index = simple_strtoul(argv[1], NULL, 0);
	if (index >= priv->pcr_count)
		return -EINVAL;

	data = map_sysmem(simple_strtoul(argv[2], NULL, 0), 0);

	rc = tpm2_pcr_read(dev, index, priv->pcr_select_min, algo,
			   data, algo_len, &updates);
	if (!rc) {
		printf("PCR #%u %s %d byte content (%u known updates):\n", index,
		       tpm2_algorithm_name(algo), algo_len, updates);
		print_byte_string(data, algo_len);
	}

	unmap_sysmem(data);

	return report_return_code(rc);
}

int do_tpm2_get_capability(struct cmd_tbl *cmdtp, int flag, int argc,
			   char *const argv[])
{
	u32 capability, property, rc;
	u8 *data;
	size_t count;
	int i, j;
	struct udevice *dev;
	int ret;

	ret = get_tpm(&dev);
	if (ret)
		return ret;

	if (argc != 5)
		return CMD_RET_USAGE;

	capability = simple_strtoul(argv[1], NULL, 0);
	property = simple_strtoul(argv[2], NULL, 0);
	data = map_sysmem(simple_strtoul(argv[3], NULL, 0), 0);
	count = simple_strtoul(argv[4], NULL, 0);

	rc = tpm2_get_capability(dev, capability, property, data, count);
	if (rc)
		goto unmap_data;

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

unmap_data:
	unmap_sysmem(data);

	return report_return_code(rc);
}

static u32 select_mask(u32 mask, enum tpm2_algorithms algo, bool select)
{
	size_t i;

	for (i = 0; i < ARRAY_SIZE(hash_algo_list); i++) {
		if (hash_algo_list[i].hash_alg != algo)
			continue;

		if (select)
			mask |= hash_algo_list[i].hash_mask;
		else
			mask &= ~hash_algo_list[i].hash_mask;

		break;
	}

	return mask;
}

static bool
is_algo_in_pcrs(enum tpm2_algorithms algo, struct tpml_pcr_selection *pcrs)
{
	size_t i;

	for (i = 0; i < pcrs->count; i++) {
		if (algo == pcrs->selection[i].hash)
			return true;
	}

	return false;
}

int do_tpm2_pcr_allocate(struct cmd_tbl *cmdtp, int flag, int argc,
			 char *const argv[])
{
	struct udevice *dev;
	int ret;
	enum tpm2_algorithms algo;
	const char *pw = (argc < 4) ? NULL : argv[3];
	const ssize_t pw_sz = pw ? strlen(pw) : 0;
	static struct tpml_pcr_selection pcr = { 0 };
	u32 pcr_len = 0;
	bool bon = false;
	static u32 mask;
	int i;

	/* argv[1]: algorithm (bank), argv[2]: on/off */
	if (argc < 3 || argc > 4)
		return CMD_RET_USAGE;

	if (!strcasecmp("on", argv[2]))
		bon = true;
	else if (strcasecmp("off", argv[2]))
		return CMD_RET_USAGE;

	algo = tpm2_name_to_algorithm(argv[1]);
	if (algo == TPM2_ALG_INVAL)
		return CMD_RET_USAGE;

	ret = get_tpm(&dev);
	if (ret)
		return ret;

	if (!pcr.count) {
		/*
		 * Get current active algorithms (banks), PCRs and mask via the
		 * first call
		 */
		ret = tpm2_get_pcr_info(dev, &pcr);
		if (ret)
			return ret;

		for (i = 0; i < pcr.count; i++) {
			struct tpms_pcr_selection *sel = &pcr.selection[i];
			const char *name;

			if (!tpm2_is_active_bank(sel))
				continue;

			mask = select_mask(mask, sel->hash, true);
			name = tpm2_algorithm_name(sel->hash);
			if (name)
				printf("Active bank[%d]: %s\n", i, name);
		}
	}

	if (!is_algo_in_pcrs(algo, &pcr)) {
		printf("%s is not supported by the tpm device\n", argv[1]);
		return CMD_RET_USAGE;
	}

	mask = select_mask(mask, algo, bon);
	ret = tpm2_pcr_config_algo(dev, mask, &pcr, &pcr_len);
	if (ret)
		return ret;

	return report_return_code(tpm2_send_pcr_allocate(dev, pw, pw_sz, &pcr,
							 pcr_len));
}

int do_tpm2_dam_reset(struct cmd_tbl *cmdtp, int flag, int argc,
		      char *const argv[])
{
	const char *pw = (argc < 2) ? NULL : argv[1];
	const ssize_t pw_sz = pw ? strlen(pw) : 0;
	struct udevice *dev;
	int ret;

	ret = get_tpm(&dev);
	if (ret)
		return ret;

	if (argc > 2)
		return CMD_RET_USAGE;

	if (pw_sz > TPM2_DIGEST_LEN)
		return -EINVAL;

	return report_return_code(tpm2_dam_reset(dev, pw, pw_sz));
}

int do_tpm2_dam_parameters(struct cmd_tbl *cmdtp, int flag, int argc,
			   char *const argv[])
{
	const char *pw = (argc < 5) ? NULL : argv[4];
	const ssize_t pw_sz = pw ? strlen(pw) : 0;
	/*
	 * No Dictionary Attack Mitigation (DAM) means:
	 * maxtries = 0xFFFFFFFF, recovery_time = 1, lockout_recovery = 0
	 */
	unsigned long int max_tries;
	unsigned long int recovery_time;
	unsigned long int lockout_recovery;
	struct udevice *dev;
	int ret;

	ret = get_tpm(&dev);
	if (ret)
		return ret;

	if (argc < 4 || argc > 5)
		return CMD_RET_USAGE;

	if (pw_sz > TPM2_DIGEST_LEN)
		return -EINVAL;

	if (strict_strtoul(argv[1], 0, &max_tries))
		return CMD_RET_USAGE;

	if (strict_strtoul(argv[2], 0, &recovery_time))
		return CMD_RET_USAGE;

	if (strict_strtoul(argv[3], 0, &lockout_recovery))
		return CMD_RET_USAGE;

	log(LOGC_NONE, LOGL_INFO, "Changing dictionary attack parameters:\n");
	log(LOGC_NONE, LOGL_INFO, "- maxTries: %lu", max_tries);
	log(LOGC_NONE, LOGL_INFO, "- recoveryTime: %lu\n", recovery_time);
	log(LOGC_NONE, LOGL_INFO, "- lockoutRecovery: %lu\n", lockout_recovery);

	return report_return_code(tpm2_dam_parameters(dev, pw, pw_sz, max_tries,
						      recovery_time,
						      lockout_recovery));
}

int do_tpm2_change_auth(struct cmd_tbl *cmdtp, int flag, int argc,
			char *const argv[])
{
	u32 handle;
	const char *newpw = argv[2];
	const char *oldpw = (argc == 3) ? NULL : argv[3];
	const ssize_t newpw_sz = strlen(newpw);
	const ssize_t oldpw_sz = oldpw ? strlen(oldpw) : 0;
	struct udevice *dev;
	int ret;

	ret = get_tpm(&dev);
	if (ret)
		return ret;

	if (argc < 3 || argc > 4)
		return CMD_RET_USAGE;

	if (newpw_sz > TPM2_DIGEST_LEN || oldpw_sz > TPM2_DIGEST_LEN)
		return -EINVAL;

	if (!strcasecmp("TPM2_RH_LOCKOUT", argv[1]))
		handle = TPM2_RH_LOCKOUT;
	else if (!strcasecmp("TPM2_RH_ENDORSEMENT", argv[1]))
		handle = TPM2_RH_ENDORSEMENT;
	else if (!strcasecmp("TPM2_RH_OWNER", argv[1]))
		handle = TPM2_RH_OWNER;
	else if (!strcasecmp("TPM2_RH_PLATFORM", argv[1]))
		handle = TPM2_RH_PLATFORM;
	else
		return CMD_RET_USAGE;

	return report_return_code(tpm2_change_auth(dev, handle, newpw, newpw_sz,
						   oldpw, oldpw_sz));
}

int do_tpm2_pcr_setauthpolicy(struct cmd_tbl *cmdtp, int flag, int argc,
			      char *const argv[])
{
	u32 index = simple_strtoul(argv[1], NULL, 0);
	char *key = argv[2];
	const char *pw = (argc < 4) ? NULL : argv[3];
	const ssize_t pw_sz = pw ? strlen(pw) : 0;
	struct udevice *dev;
	int ret;

	ret = get_tpm(&dev);
	if (ret)
		return ret;

	if (strlen(key) != TPM2_DIGEST_LEN)
		return -EINVAL;

	if (argc < 3 || argc > 4)
		return CMD_RET_USAGE;

	return report_return_code(tpm2_pcr_setauthpolicy(dev, pw, pw_sz, index,
							 key));
}

int do_tpm2_pcr_setauthvalue(struct cmd_tbl *cmdtp, int flag,
			     int argc, char *const argv[])
{
	u32 index = simple_strtoul(argv[1], NULL, 0);
	char *key = argv[2];
	const ssize_t key_sz = strlen(key);
	const char *pw = (argc < 4) ? NULL : argv[3];
	const ssize_t pw_sz = pw ? strlen(pw) : 0;
	struct udevice *dev;
	int ret;

	ret = get_tpm(&dev);
	if (ret)
		return ret;

	if (strlen(key) != TPM2_DIGEST_LEN)
		return -EINVAL;

	if (argc < 3 || argc > 4)
		return CMD_RET_USAGE;

	return report_return_code(tpm2_pcr_setauthvalue(dev, pw, pw_sz, index,
							key, key_sz));
}
