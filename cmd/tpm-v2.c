// SPDX-License-Identifier: GPL-2.0+
/*
 * TPM2 command frontend - command table, dispatcher, and help text
 *
 * The actual command implementations are provided by the backend:
 *   - native_tpm2.c: U-Boot native TPM2 APIs (driver model)
 *   - wolftpm.c: wolfTPM library APIs
 *
 * Copyright (c) 2018 Bootlin
 * Author: Miquel Raynal <miquel.raynal@bootlin.com>
 */

#include <command.h>
#include <tpm-common.h>
#include "tpm2-backend.h"

static struct cmd_tbl tpm2_commands[] = {
	U_BOOT_CMD_MKENT(device, 0, 1, do_tpm2_device, "", ""),
	U_BOOT_CMD_MKENT(info, 0, 1, do_tpm2_info, "", ""),
	U_BOOT_CMD_MKENT(state, 0, 1, do_tpm2_state, "", ""),
	U_BOOT_CMD_MKENT(init, 0, 1, do_tpm2_init, "", ""),
	U_BOOT_CMD_MKENT(autostart, 0, 1, do_tpm2_autostart, "", ""),
	U_BOOT_CMD_MKENT(startup, 0, 1, do_tpm2_startup, "", ""),
	U_BOOT_CMD_MKENT(self_test, 0, 1, do_tpm2_selftest, "", ""),
	U_BOOT_CMD_MKENT(clear, 0, 1, do_tpm2_clear, "", ""),
	U_BOOT_CMD_MKENT(pcr_extend, 0, 1, do_tpm2_pcr_extend, "", ""),
	U_BOOT_CMD_MKENT(pcr_read, 0, 1, do_tpm2_pcr_read, "", ""),
	U_BOOT_CMD_MKENT(get_capability, 0, 1, do_tpm2_get_capability, "", ""),
	U_BOOT_CMD_MKENT(dam_reset, 0, 1, do_tpm2_dam_reset, "", ""),
	U_BOOT_CMD_MKENT(dam_parameters, 0, 1, do_tpm2_dam_parameters, "", ""),
	U_BOOT_CMD_MKENT(change_auth, 0, 1, do_tpm2_change_auth, "", ""),
	U_BOOT_CMD_MKENT(pcr_setauthpolicy, 0, 1,
			 do_tpm2_pcr_setauthpolicy, "", ""),
	U_BOOT_CMD_MKENT(pcr_setauthvalue, 0, 1,
			 do_tpm2_pcr_setauthvalue, "", ""),
	U_BOOT_CMD_MKENT(pcr_allocate, 0, 1, do_tpm2_pcr_allocate, "", ""),
#ifdef CONFIG_TPM_WOLF
	U_BOOT_CMD_MKENT(caps, 0, 1, do_tpm2_caps, "", ""),
	U_BOOT_CMD_MKENT(pcr_print, 0, 1, do_tpm2_pcr_print, "", ""),
#ifdef WOLFTPM_FIRMWARE_UPGRADE
#if defined(WOLFTPM_SLB9672) || defined(WOLFTPM_SLB9673)
	U_BOOT_CMD_MKENT(firmware_update, 0, 1,
			 do_tpm2_firmware_update, "", ""),
	U_BOOT_CMD_MKENT(firmware_cancel, 0, 1,
			 do_tpm2_firmware_cancel, "", ""),
#endif /* WOLFTPM_SLB9672 || WOLFTPM_SLB9673 */
#endif /* WOLFTPM_FIRMWARE_UPGRADE */
#endif /* CONFIG_TPM_WOLF */
};

struct cmd_tbl *get_tpm2_commands(unsigned int *size)
{
	*size = ARRAY_SIZE(tpm2_commands);

	return tpm2_commands;
}

static int do_tpm2(struct cmd_tbl *cmdtp, int flag, int argc,
		   char *const argv[])
{
	struct cmd_tbl *cmd;

	if (argc < 2)
		return CMD_RET_USAGE;

	cmd = find_cmd_tbl(argv[1], tpm2_commands, ARRAY_SIZE(tpm2_commands));
	if (!cmd)
		return CMD_RET_USAGE;

	return cmd->cmd(cmdtp, flag, argc - 1, argv + 1);
}

U_BOOT_CMD(tpm2, CONFIG_SYS_MAXARGS, 1, do_tpm2, "Issue a TPMv2.x command",
"<command> [<arguments>]\n"
"\n"
"device [num device]\n"
"    Show all devices or set the specified device\n"
"info\n"
"    Show information about the TPM.\n"
"state\n"
"    Show internal state from the TPM (if available)\n"
"autostart\n"
"    Initialize the tpm, perform a Startup(clear) and run a full selftest\n"
"    sequence\n"
"init\n"
"    Initialize the software stack. Always the first command to issue.\n"
"    'tpm startup' is the only acceptable command after a 'tpm init' has been\n"
"    issued\n"
"startup <mode> [<op>]\n"
"    Issue a TPM2_Startup command.\n"
"    <mode> is one of:\n"
"        * TPM2_SU_CLEAR (reset state)\n"
"        * TPM2_SU_STATE (preserved state)\n"
"    <op>:\n"
"        * off - To shutdown the TPM\n"
"self_test <type>\n"
"    Test the TPM capabilities.\n"
"    <type> is one of:\n"
"        * full (perform all tests)\n"
"        * continue (only check untested tests)\n"
"clear <hierarchy>\n"
"    Issue a TPM2_Clear command.\n"
"    <hierarchy> is one of:\n"
"        * TPM2_RH_LOCKOUT\n"
"        * TPM2_RH_PLATFORM\n"
"pcr_extend <pcr> <digest_addr> [<digest_algo>]\n"
"    Extend PCR #<pcr> with digest at <digest_addr> with digest_algo.\n"
"    <pcr>: index of the PCR\n"
"    <digest_addr>: address of digest of digest_algo type (defaults to SHA256)\n"
"pcr_read <pcr> <digest_addr> [<digest_algo>]\n"
"    Read PCR #<pcr> to memory address <digest_addr> with <digest_algo>.\n"
"    <pcr>: index of the PCR\n"
"    <digest_addr>: address of digest of digest_algo type (defaults to SHA256)\n"
"get_capability <capability> <property> <addr> <count>\n"
"    Read and display <count> entries indexed by <capability>/<property>.\n"
"    Values are 4 bytes long and are written at <addr>.\n"
"    <capability>: capability\n"
"    <property>: property\n"
"    <addr>: address to store <count> entries of 4 bytes\n"
"    <count>: number of entries to retrieve\n"
"dam_reset [<password>]\n"
"    If the TPM is not in a LOCKOUT state, reset the internal error counter.\n"
"    <password>: optional password\n"
"dam_parameters <max_tries> <recovery_time> <lockout_recovery> [<password>]\n"
"    If the TPM is not in a LOCKOUT state, set the DAM parameters\n"
"    <maxTries>: maximum number of failures before lockout,\n"
"                0 means always locking\n"
"    <recoveryTime>: time before decrement of the error counter,\n"
"                    0 means no lockout\n"
"    <lockoutRecovery>: time of a lockout (before the next try),\n"
"                       0 means a reboot is needed\n"
"    <password>: optional password of the LOCKOUT hierarchy\n"
"change_auth <hierarchy> <new_pw> [<old_pw>]\n"
"    <hierarchy>: the hierarchy\n"
"        * TPM2_RH_LOCKOUT\n"
"        * TPM2_RH_ENDORSEMENT\n"
"        * TPM2_RH_OWNER\n"
"        * TPM2_RH_PLATFORM\n"
"    <new_pw>: new password for <hierarchy>\n"
"    <old_pw>: optional previous password of <hierarchy>\n"
"pcr_setauthpolicy|pcr_setauthvalue <pcr> <key> [<password>]\n"
"    Change the <key> to access PCR #<pcr>.\n"
"    hierarchy and may be empty.\n"
"    /!\\WARNING: untested function, use at your own risks !\n"
"    <pcr>: index of the PCR\n"
"    <key>: secret to protect the access of PCR #<pcr>\n"
"    <password>: optional password of the PLATFORM hierarchy\n"
"pcr_allocate <algorithm> <on/off> [<password>]\n"
"    Issue a TPM2_PCR_Allocate Command to reconfig PCR bank algorithm.\n"
"    <algorithm> is one of:\n"
"        * sha1\n"
"        * sha256\n"
"        * sha384\n"
"        * sha512\n"
"        * sm3_256\n"
"    <on|off> is one of:\n"
"        * on  - Select all available PCRs associated with the specified\n"
"                algorithm (bank)\n"
"        * off - Clear all available PCRs associated with the specified\n"
"                algorithm (bank)\n"
"    <password>: optional password\n"
#ifdef CONFIG_TPM_WOLF
"caps\n"
"    Show TPM capabilities and info\n"
"pcr_print\n"
"    Prints the current PCR state\n"
#ifdef WOLFTPM_FIRMWARE_UPGRADE
#if defined(WOLFTPM_SLB9672) || defined(WOLFTPM_SLB9673)
"firmware_update <manifest_addr> <manifest_sz> <firmware_addr> <firmware_sz>\n"
"    Update TPM firmware\n"
"firmware_cancel\n"
"    Cancel TPM firmware update\n"
#endif /* WOLFTPM_SLB9672 || WOLFTPM_SLB9673 */
#endif /* WOLFTPM_FIRMWARE_UPGRADE */
#endif /* CONFIG_TPM_WOLF */
);
