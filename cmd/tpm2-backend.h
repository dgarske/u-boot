/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * TPM2 backend function declarations
 *
 * Each backend (native_tpm2.c or wolftpm.c) implements these functions.
 * The frontend (tpm-v2.c) references them in the command table.
 */

#ifndef __TPM2_BACKEND_H
#define __TPM2_BACKEND_H

#include <command.h>

/* Common TPM2 command handlers - both backends must implement these */
int do_tpm2_device(struct cmd_tbl *cmdtp, int flag, int argc,
		   char *const argv[]);
int do_tpm2_info(struct cmd_tbl *cmdtp, int flag, int argc,
		 char *const argv[]);
int do_tpm2_state(struct cmd_tbl *cmdtp, int flag, int argc,
		  char *const argv[]);
int do_tpm2_init(struct cmd_tbl *cmdtp, int flag, int argc,
		 char *const argv[]);
int do_tpm2_autostart(struct cmd_tbl *cmdtp, int flag, int argc,
		      char *const argv[]);
int do_tpm2_startup(struct cmd_tbl *cmdtp, int flag, int argc,
		    char *const argv[]);
int do_tpm2_selftest(struct cmd_tbl *cmdtp, int flag, int argc,
		     char *const argv[]);
int do_tpm2_clear(struct cmd_tbl *cmdtp, int flag, int argc,
		  char *const argv[]);
int do_tpm2_pcr_extend(struct cmd_tbl *cmdtp, int flag, int argc,
		       char *const argv[]);
int do_tpm2_pcr_read(struct cmd_tbl *cmdtp, int flag, int argc,
		     char *const argv[]);
int do_tpm2_get_capability(struct cmd_tbl *cmdtp, int flag, int argc,
			   char *const argv[]);
int do_tpm2_dam_reset(struct cmd_tbl *cmdtp, int flag, int argc,
		      char *const argv[]);
int do_tpm2_dam_parameters(struct cmd_tbl *cmdtp, int flag, int argc,
			   char *const argv[]);
int do_tpm2_change_auth(struct cmd_tbl *cmdtp, int flag, int argc,
			char *const argv[]);
int do_tpm2_pcr_setauthpolicy(struct cmd_tbl *cmdtp, int flag, int argc,
			      char *const argv[]);
int do_tpm2_pcr_setauthvalue(struct cmd_tbl *cmdtp, int flag, int argc,
			     char *const argv[]);
int do_tpm2_pcr_allocate(struct cmd_tbl *cmdtp, int flag, int argc,
			 char *const argv[]);

/* wolfTPM-only command handlers */
#ifdef CONFIG_TPM_WOLF
int do_tpm2_caps(struct cmd_tbl *cmdtp, int flag, int argc,
		 char *const argv[]);
int do_tpm2_pcr_print(struct cmd_tbl *cmdtp, int flag, int argc,
		      char *const argv[]);
#ifdef WOLFTPM_FIRMWARE_UPGRADE
#if defined(WOLFTPM_SLB9672) || defined(WOLFTPM_SLB9673)
int do_tpm2_firmware_update(struct cmd_tbl *cmdtp, int flag, int argc,
			    char *const argv[]);
int do_tpm2_firmware_cancel(struct cmd_tbl *cmdtp, int flag, int argc,
			    char *const argv[]);
#endif /* WOLFTPM_SLB9672 || WOLFTPM_SLB9673 */
#endif /* WOLFTPM_FIRMWARE_UPGRADE */
#endif /* CONFIG_TPM_WOLF */

#endif /* __TPM2_BACKEND_H */
