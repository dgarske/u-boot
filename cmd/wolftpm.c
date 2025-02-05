/* wolftpm.c
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
 *
 * This file is part of wolfTPM.
 *
 * wolfTPM is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfTPM is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

/* U-boot wolfTPM commands. These include:
 * - get Capability
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolftpm/tpm2.h>
#include <wolftpm/tpm2_wrap.h>

#include <stdio.h>
#include <command.h>

#ifndef WOLFTPM2_NO_WRAPPER

#include <hal/tpm_io.h>
#include <examples/wrap/wrap_test.h>


/******************************************************************************/
/* --- BEGIN Command Examples -- */
/******************************************************************************/

/* Usage */ 
static void usage(void)
{
    printf("Expected Usage:\n");
    printf("./examples/wrap/caps\n");
}

/* Print available PCR's */
static int TPM2_PCRs_Print(void)
{
    int rc;
    int pcrCount, pcrIndex;
    GetCapability_In  capIn;
    GetCapability_Out capOut;
    TPML_PCR_SELECTION* pcrSel;

    /* List available PCR's */
    XMEMSET(&capIn, 0, sizeof(capIn));
    capIn.capability = TPM_CAP_PCRS;
    capIn.property = 0;
    capIn.propertyCount = 1;
    rc = TPM2_GetCapability(&capIn, &capOut);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_GetCapability failed 0x%x: %s\n", rc,
            TPM2_GetRCString(rc));
        return rc;
    }
    pcrSel = &capOut.capabilityData.data.assignedPCR;
    printf("Assigned PCR's:\n");
    for (pcrCount=0; pcrCount < (int)pcrSel->count; pcrCount++) {
        printf("\t%s: ", TPM2_GetAlgName(pcrSel->pcrSelections[pcrCount].hash));
        for (pcrIndex=0;
             pcrIndex<pcrSel->pcrSelections[pcrCount].sizeofSelect*8;
             pcrIndex++) {
            if ((pcrSel->pcrSelections[pcrCount].pcrSelect[pcrIndex/8] &
                    ((1 << (pcrIndex % 8)))) != 0) {
                printf(" %d", pcrIndex);
            }
        }
        printf("\n");
    }
    return 0;
}

/* Get TPM2 capabilities */
static int do_TPM2_Wrapper_CapsArgs(void* userCtx, int argc, char *argv[])
{
    int rc;
    WOLFTPM2_DEV dev;
    WOLFTPM2_CAPS caps;

    if (argc > 1) {
        if (XSTRCMP(argv[1], "-?") == 0 ||
            XSTRCMP(argv[1], "-h") == 0 ||
            XSTRCMP(argv[1], "--help") == 0) {
            usage();
            return 0;
        }
    }

    printf("TPM2 Get Capabilities\n");

    /* Init the TPM2 device */
    rc = wolfTPM2_Init(&dev, TPM2_IoCb, userCtx);
    if (rc != 0) return rc;

    rc = wolfTPM2_GetCapabilities(&dev, &caps);
    if (rc != 0) goto exit;

    printf("Mfg %s (%d), Vendor %s, Fw %u.%u (0x%x), "
        "FIPS 140-2 %d, CC-EAL4 %d\n",
        caps.mfgStr, caps.mfg, caps.vendorStr, caps.fwVerMajor,
        caps.fwVerMinor, caps.fwVerVendor, caps.fips140_2, caps.cc_eal4);
#if defined(WOLFTPM_SLB9672) || defined(WOLFTPM_SLB9673)
    printf("\tKeyGroupId 0x%x, Operational Mode 0x%x, FwCounter %d (%d same)\n",
        caps.keyGroupId, caps.opMode, caps.fwCounter, caps.fwCounterSame);
#endif

    /* List the active persistent handles */
    rc = wolfTPM2_GetHandles(PERSISTENT_FIRST, NULL);
    if (rc >= 0) {
        printf("Found %d persistent handles\n", rc);
    }

    /* Print the available PCR's */
    TPM2_PCRs_Print();

exit:
    wolfTPM2_Shutdown(&dev, 0); /* 0=just shutdown, no startup */

    wolfTPM2_Cleanup(&dev);

    return rc;
}

/* Main command handler for wolfTPM U-boot commands */
static int do_wolftpm(struct cmd_tbl *cmdtp, int flag, int argc, char *const argv[])
{
    if (argc < 2)
        return CMD_RET_USAGE;

    if (strcmp(argv[1], "caps") == 0)
        return do_TPM2_Wrapper_CapsArgs(NULL, argc-1, (char **)&argv[1]);
    
    return CMD_RET_USAGE;
}

U_BOOT_CMD(
    wolftpm,                /* name of cmd */
    CONFIG_SYS_MAXARGS,     /* max args    */
    1,                      /* repeatable  */
    do_wolftpm,             /* function    */
    "wolfTPM TPM 2.0 commands",
    "wolftpm <command> [arguments]\n"
    "\n"
    "Commands:\n"
    "  caps                 - Show TPM capabilities and info\n"
    "  help                 - Show this help text\n"
);

#endif /* !WOLFTPM2_NO_WRAPPER */

/******************************************************************************/
/* --- END Command Examples -- */
/******************************************************************************/
