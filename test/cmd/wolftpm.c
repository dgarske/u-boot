// SPDX-License-Identifier: GPL-2.0+
/*
 * Tests for wolfTPM commands
 *
 * Copyright (C) 2025 wolfSSL Inc.
 * Author: Aidan Garske <aidan@wolfssl.com>
 *
 * Based on test/py/tests/test_tpm2.py and test/dm/tpm.c
 *
 * Note: These tests verify command success via return code only.
 * Console output is not checked since it varies with debug levels.
 * Run with: ut cmd
 */

#include <command.h>
#include <dm.h>
#include <dm/test.h>
#include <test/cmd.h>
#include <test/test.h>
#include <test/ut.h>

/**
 * Test wolfTPM autostart command
 *
 * This initializes the TPM, performs startup and self-test
 */
static int cmd_test_wolftpm_autostart(struct unit_test_state *uts)
{
	/* Initialize and autostart the TPM */
	ut_assertok(run_command("tpm2 autostart", 0));

	return 0;
}
CMD_TEST(cmd_test_wolftpm_autostart, 0);

/**
 * Test wolfTPM init command
 */
static int cmd_test_wolftpm_init(struct unit_test_state *uts)
{
	ut_assertok(run_command("tpm2 init", 0));

	return 0;
}
CMD_TEST(cmd_test_wolftpm_init, 0);

/**
 * Test wolfTPM info command
 *
 * Display TPM device information
 */
static int cmd_test_wolftpm_info(struct unit_test_state *uts)
{
	/* First autostart to ensure TPM is ready */
	ut_assertok(run_command("tpm2 autostart", 0));

	/* Get TPM info */
	ut_assertok(run_command("tpm2 info", 0));

	return 0;
}
CMD_TEST(cmd_test_wolftpm_info, 0);

/**
 * Test wolfTPM state command
 *
 * Display TPM internal state
 */
static int cmd_test_wolftpm_state(struct unit_test_state *uts)
{
	/* First autostart to ensure TPM is ready */
	ut_assertok(run_command("tpm2 autostart", 0));

	/* Get TPM state */
	ut_assertok(run_command("tpm2 state", 0));

	return 0;
}
CMD_TEST(cmd_test_wolftpm_state, 0);

/**
 * Test wolfTPM device command
 *
 * Show all TPM devices
 */
static int cmd_test_wolftpm_device(struct unit_test_state *uts)
{
	/* Show TPM devices - no autostart needed */
	ut_assertok(run_command("tpm2 device", 0));

	return 0;
}
CMD_TEST(cmd_test_wolftpm_device, 0);

/**
 * Test wolfTPM self_test command
 */
static int cmd_test_wolftpm_self_test(struct unit_test_state *uts)
{
	/* First autostart to ensure TPM is ready */
	ut_assertok(run_command("tpm2 autostart", 0));

	/* Run full self test */
	ut_assertok(run_command("tpm2 self_test full", 0));

	return 0;
}
CMD_TEST(cmd_test_wolftpm_self_test, 0);

/**
 * Test wolfTPM self_test continue command
 */
static int cmd_test_wolftpm_self_test_continue(struct unit_test_state *uts)
{
	/* First autostart to ensure TPM is ready */
	ut_assertok(run_command("tpm2 autostart", 0));

	/* Run continue self test */
	ut_assertok(run_command("tpm2 self_test continue", 0));

	return 0;
}
CMD_TEST(cmd_test_wolftpm_self_test_continue, 0);

/**
 * Test wolfTPM startup command with TPM2_SU_CLEAR
 *
 * Issue TPM2_Startup with CLEAR mode (reset state)
 */
static int cmd_test_wolftpm_startup_clear(struct unit_test_state *uts)
{
	/* First init to prepare TPM */
	ut_assertok(run_command("tpm2 init", 0));

	/* Issue startup with CLEAR mode */
	ut_assertok(run_command("tpm2 startup TPM2_SU_CLEAR", 0));

	return 0;
}
CMD_TEST(cmd_test_wolftpm_startup_clear, 0);

/**
 * Test wolfTPM startup command with TPM2_SU_STATE
 *
 * Issue TPM2_Startup with STATE mode (preserved state)
 */
static int cmd_test_wolftpm_startup_state(struct unit_test_state *uts)
{
	/* First autostart to ensure TPM has state */
	ut_assertok(run_command("tpm2 autostart", 0));

	/* Shutdown first to prepare for STATE startup */
	run_command("tpm2 startup TPM2_SU_STATE off", 0);

	/* Re-init */
	ut_assertok(run_command("tpm2 init", 0));

	/* Issue startup with STATE mode - may return already started */
	run_command("tpm2 startup TPM2_SU_STATE", 0);

	return 0;
}
CMD_TEST(cmd_test_wolftpm_startup_state, 0);

/**
 * Test wolfTPM get_capability command
 *
 * Read TPM capabilities by property
 */
static int cmd_test_wolftpm_get_capability(struct unit_test_state *uts)
{
	/* First autostart to ensure TPM is ready */
	ut_assertok(run_command("tpm2 autostart", 0));

	/* Get capability - property 0x6 (TPM_CAP_TPM_PROPERTIES), 0x20e (PT_MANUFACTURER) */
	ut_assertok(run_command("tpm2 get_capability 0x6 0x20e 0x1000000 1", 0));

	return 0;
}
CMD_TEST(cmd_test_wolftpm_get_capability, 0);

/**
 * Test wolfTPM caps command (get capabilities)
 *
 * Display TPM capabilities and vendor info
 */
static int cmd_test_wolftpm_caps(struct unit_test_state *uts)
{
	/* First autostart to ensure TPM is ready */
	ut_assertok(run_command("tpm2 autostart", 0));

	/* Get TPM capabilities */
	ut_assertok(run_command("tpm2 caps", 0));

	return 0;
}
CMD_TEST(cmd_test_wolftpm_caps, 0);

/**
 * Test wolfTPM clear command
 *
 * Reset TPM internal state using LOCKOUT hierarchy
 */
static int cmd_test_wolftpm_clear(struct unit_test_state *uts)
{
	/* First autostart to ensure TPM is ready */
	ut_assertok(run_command("tpm2 autostart", 0));

	/* Clear using LOCKOUT hierarchy */
	ut_assertok(run_command("tpm2 clear TPM2_RH_LOCKOUT", 0));

	return 0;
}
CMD_TEST(cmd_test_wolftpm_clear, 0);

/**
 * Test wolfTPM pcr_read command
 *
 * Read PCR value from a specific index to a memory address
 */
static int cmd_test_wolftpm_pcr_read(struct unit_test_state *uts)
{
	/* First autostart to ensure TPM is ready */
	ut_assertok(run_command("tpm2 autostart", 0));

	/* Read PCR 0 with SHA256 to memory address 0x1000000 */
	ut_assertok(run_command("tpm2 pcr_read 0 0x1000000 SHA256", 0));

	return 0;
}
CMD_TEST(cmd_test_wolftpm_pcr_read, 0);

/**
 * Test wolfTPM pcr_extend command
 *
 * Extend a PCR with a digest value
 */
static int cmd_test_wolftpm_pcr_extend(struct unit_test_state *uts)
{
	/* First autostart to ensure TPM is ready */
	ut_assertok(run_command("tpm2 autostart", 0));

	/* Clear to start fresh */
	run_command("tpm2 clear TPM2_RH_LOCKOUT", 0);

	/* Extend PCR 16 (resettable PCR) with digest from memory
	 * PCR 16-23 are typically available for debug/testing
	 */
	ut_assertok(run_command("tpm2 pcr_extend 16 0x1000000 SHA256", 0));

	return 0;
}
CMD_TEST(cmd_test_wolftpm_pcr_extend, 0);

/**
 * Test wolfTPM pcr_print command
 *
 * Print all PCR values
 */
static int cmd_test_wolftpm_pcr_print(struct unit_test_state *uts)
{
	/* First autostart to ensure TPM is ready */
	ut_assertok(run_command("tpm2 autostart", 0));

	/* Print all PCRs */
	ut_assertok(run_command("tpm2 pcr_print", 0));

	return 0;
}
CMD_TEST(cmd_test_wolftpm_pcr_print, 0);

/**
 * Test wolfTPM pcr_allocate command
 *
 * Reconfigure PCR bank algorithm. Note: A TPM restart is required
 * for changes to take effect, so we just verify the command succeeds.
 */
static int cmd_test_wolftpm_pcr_allocate(struct unit_test_state *uts)
{
	/* First autostart to ensure TPM is ready */
	ut_assertok(run_command("tpm2 autostart", 0));

	/* Allocate SHA256 bank on - this should succeed */
	ut_assertok(run_command("tpm2 pcr_allocate SHA256 on", 0));

	return 0;
}
CMD_TEST(cmd_test_wolftpm_pcr_allocate, 0);

/**
 * Test wolfTPM dam_reset command
 *
 * Reset Dictionary Attack Mitigation counter
 */
static int cmd_test_wolftpm_dam_reset(struct unit_test_state *uts)
{
	/* First autostart to ensure TPM is ready */
	ut_assertok(run_command("tpm2 autostart", 0));

	/* Reset DAM counter */
	ut_assertok(run_command("tpm2 dam_reset", 0));

	return 0;
}
CMD_TEST(cmd_test_wolftpm_dam_reset, 0);

/**
 * Test wolfTPM dam_parameters command
 *
 * Set Dictionary Attack Mitigation parameters
 */
static int cmd_test_wolftpm_dam_parameters(struct unit_test_state *uts)
{
	/* First autostart to ensure TPM is ready */
	ut_assertok(run_command("tpm2 autostart", 0));

	/* Set DAM parameters:
	 * - max_tries: 3
	 * - recovery_time: 10 seconds
	 * - lockout_recovery: 0 seconds
	 */
	ut_assertok(run_command("tpm2 dam_parameters 3 10 0", 0));

	return 0;
}
CMD_TEST(cmd_test_wolftpm_dam_parameters, 0);

/**
 * Test wolfTPM change_auth command
 *
 * Change hierarchy authorization password
 * Note: Requires WOLFTPM2_NO_WOLFCRYPT to NOT be defined
 */
static int cmd_test_wolftpm_change_auth(struct unit_test_state *uts)
{
	/* First autostart and clear to ensure clean state */
	ut_assertok(run_command("tpm2 autostart", 0));
	run_command("tpm2 clear TPM2_RH_LOCKOUT", 0);

	/* Change LOCKOUT password to "testpw"
	 * This may fail if WOLFTPM2_NO_WOLFCRYPT is defined
	 */
	if (run_command("tpm2 change_auth TPM2_RH_LOCKOUT testpw", 0) == 0) {
		/* Clear with new password to verify it worked */
		ut_assertok(run_command("tpm2 clear TPM2_RH_LOCKOUT testpw", 0));
	}

	return 0;
}
CMD_TEST(cmd_test_wolftpm_change_auth, 0);

/**
 * Cleanup test - ensure TPM is cleared after tests
 */
static int cmd_test_wolftpm_cleanup(struct unit_test_state *uts)
{
	/* Clear TPM to reset any passwords or test state */
	run_command("tpm2 autostart", 0);
	run_command("tpm2 clear TPM2_RH_LOCKOUT", 0);
	run_command("tpm2 clear TPM2_RH_PLATFORM", 0);

	return 0;
}
CMD_TEST(cmd_test_wolftpm_cleanup, 0);
