/* wolftpm.c
 *
 * SPDX-License-Identifier: GPL-2.0+
 *
 * (C) Copyright 2025
 * Aidan Garske <aidan@wolfssl.com>
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolftpm/tpm2.h>
#include <wolftpm/tpm2_wrap.h>
#include <wolftpm/tpm2_packet.h>

#include <stdio.h>
#include <hash.h>
#ifndef WOLFTPM2_NO_WRAPPER

#include <hal/tpm_io.h>
#include <examples/wrap/wrap_test.h>

/* U-boot specific includes */
#include <command.h>
#include <tpm-common.h>
#include <vsprintf.h>
#include <mapmem.h>
#include <errno.h>

/******************************************************************************/
/* --- BEGIN Helper Functions -- */
/******************************************************************************/

#ifdef WOLFTPM_FIRMWARE_UPGRADE

typedef struct {
    byte*  manifest_buf;
    byte*  firmware_buf;
    size_t manifest_bufSz;
    size_t firmware_bufSz;
} fw_info_t;

static int TPM2_IFX_FwData_Cb(uint8_t* data, uint32_t data_req_sz,
    uint32_t offset, void* cb_ctx)
{
    fw_info_t* fwinfo = (fw_info_t*)cb_ctx;
    if (offset > fwinfo->firmware_bufSz) {
        return BUFFER_E;
    }
    if (offset + data_req_sz > (uint32_t)fwinfo->firmware_bufSz) {
        data_req_sz = (uint32_t)fwinfo->firmware_bufSz - offset;
    }
    if (data_req_sz > 0) {
        XMEMCPY(data, &fwinfo->firmware_buf[offset], data_req_sz);
    }
    return data_req_sz;
}

static const char* TPM2_IFX_GetOpModeStr(int opMode)
{
    const char* opModeStr = "Unknown";
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

static void TPM2_IFX_PrintInfo(WOLFTPM2_CAPS* caps)
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
    return TPM_RC_SUCCESS;
}

/* Helper function to init/cleanup TPM device */
static int TPM2_Init_Device(WOLFTPM2_DEV* dev, void* userCtx)
{
    int rc = wolfTPM2_Init(dev, TPM2_IoCb, userCtx);
    printf("tpm2 init: rc = %d (%s)\n", rc, TPM2_GetRCString(rc));
    return rc;
}

/******************************************************************************/
/* --- END Helper Functions -- */
/******************************************************************************/


/******************************************************************************/
/* --- BEGIN Common Commands -- */
/******************************************************************************/

static int do_TPM2_Device(void* userCtx, int argc, char *argv[])
{
    int rc;
    unsigned long num;

    /* Expected 1-2 arg: command + [num device] */
    if (argc < 1 || argc > 2) {
        return CMD_RET_USAGE;
    }

    if (argc == 2) {
		num = dectoul(argv[1], NULL);
		rc = tpm_set_device(num);
		if (rc)
			printf("Couldn't set TPM %lu (rc = %d)\n", num, rc);
	} else {
		rc = tpm_show_device();
	}

    printf("tpm device: rc = %d (%s)\n", rc, TPM2_GetRCString(rc));

    return rc;
}

static int do_TPM2_Info(void* userCtx, int argc, char *argv[])
{
    int rc;
    char buf[80];
    struct udevice *dev;

    if (argc != 1) {
        return CMD_RET_USAGE;
    }

    /* Init the TPM2 device */
    rc = get_tpm(&dev);
    if (rc == 0) {
        /* Get the current TPM's description */
        rc = tpm_get_desc(dev, buf, sizeof(buf));
        if (rc < 0) {
            printf("Couldn't get TPM info (%d)\n", rc);
            rc = CMD_RET_FAILURE;
        }
        else {
            printf("%s\n", buf);
        }
    }

    printf("tpm2 info: rc = %d (%s)\n", rc, TPM2_GetRCString(rc));

    return rc;
}

static int do_TPM2_State(void* userCtx, int argc, char *argv[])
{
    int rc;
    char buf[80];
    struct udevice *dev;

    if (argc != 1) {
        return CMD_RET_USAGE;
    }

    /* Init the TPM2 device */
    rc = get_tpm(&dev);
    if (rc == 0) {
        /* Get the current TPM's state */
        rc = tpm_report_state(dev, buf, sizeof(buf));
        if (rc < 0) {
            printf("Couldn't get TPM state (%d)\n", rc);
            rc = CMD_RET_FAILURE;
        }
        else {
            printf("%s\n", buf);
        }
    }

    printf("tpm2 state: rc = %d (%s)\n", rc, TPM2_GetRCString(rc));

    return rc;
}

static int do_TPM2_Init(void* userCtx, int argc, char *argv[])
{
    WOLFTPM2_DEV dev;

    if (argc != 1) {
        return CMD_RET_USAGE;
    }

    /* Init the TPM2 device */
    return TPM2_Init_Device(&dev, userCtx);
}


static int do_TPM2_AutoStart(void* userCtx, int argc, char *argv[])
{
    int rc;
    WOLFTPM2_DEV dev;

    if (argc != 1) {
        return CMD_RET_USAGE;
    }

    /* Init the TPM2 device */
    rc = TPM2_Init_Device(&dev, userCtx);
    if (rc == TPM_RC_SUCCESS) {
        /* Perform a startup clear
        * doStartup=1: Just starts up the TPM */
        rc = wolfTPM2_Reset(&dev, 0, 1);
        if (rc != TPM_RC_SUCCESS && rc != TPM_RC_INITIALIZE) {
            printf("wolfTPM2_Reset failed 0x%x: %s\n", rc,
                TPM2_GetRCString(rc));
        }
    }
    if (rc == TPM_RC_SUCCESS) {
        /* Perform a full self test */
        rc = wolfTPM2_SelfTest(&dev);
        if (rc != TPM_RC_SUCCESS) {
            printf("wolfTPM2_SelfTest failed 0x%x: %s\n", rc,
                TPM2_GetRCString(rc));
        }
    }

    printf("tpm2 autostart: rc = %d (%s)\n", rc, TPM2_GetRCString(rc));

    return rc;
}

/******************************************************************************/
/* --- END Common Commands -- */
/******************************************************************************/


/******************************************************************************/
/* --- START TPM 2.0 Commands -- */
/******************************************************************************/

static int do_TPM2_Wrapper_GetCapsArgs(void* userCtx, int argc, char *argv[])
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

    XMEMSET(&in, 0, sizeof(in));
    XMEMSET(&out, 0, sizeof(out));
    in.capability = capability;
    in.property = property;
    in.propertyCount = count;
    rc = TPM2_GetCapability(&in, &out);
    if (rc == 0) {
        XMEMCPY(data, &out.capabilityData.data, sizeof(out.capabilityData.data));

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

    printf("tpm2 get_capability: rc = %d (%s)\n", rc, TPM2_GetRCString(rc));

    return rc;
}

static int do_TPM2_Wrapper_CapsArgs(void* userCtx, int argc, char *argv[])
{
    int rc;
    WOLFTPM2_DEV dev;
    WOLFTPM2_CAPS caps;

    if (argc != 1) {
        return CMD_RET_USAGE;
    }

    /* Init the TPM2 device */
    rc = TPM2_Init_Device(&dev, userCtx);
    if (rc == TPM_RC_SUCCESS) {
        rc = wolfTPM2_GetCapabilities(&dev, &caps);
    }
    if (rc == TPM_RC_SUCCESS) {
        printf("Mfg %s (%d), Vendor %s, Fw %u.%u (0x%x), "
            "FIPS 140-2 %d, CC-EAL4 %d\n",
            caps.mfgStr, caps.mfg, caps.vendorStr, caps.fwVerMajor,
            caps.fwVerMinor, caps.fwVerVendor, caps.fips140_2, caps.cc_eal4);
#if defined(WOLFTPM_SLB9672) || defined(WOLFTPM_SLB9673)
        printf("Operational mode: %s (0x%x)\n",
            TPM2_IFX_GetOpModeStr(caps.opMode), caps.opMode);
        printf("KeyGroupId 0x%x, FwCounter %d (%d same)\n",
            caps.keyGroupId, caps.fwCounter, caps.fwCounterSame);
#endif
    }

    /* List the active persistent handles */
    if (rc == TPM_RC_SUCCESS) {
        rc = wolfTPM2_GetHandles(PERSISTENT_FIRST, NULL);
        if (rc >= TPM_RC_SUCCESS) {
            printf("Found %d persistent handles\n", rc);
        }
    }

    /* Print the available PCR's */
    if (rc == TPM_RC_SUCCESS) {
        rc = TPM2_PCRs_Print();
    }

    /* Only doShutdown=1: Just shut down the TPM */
    wolfTPM2_Reset(&dev, 1, 0);

    wolfTPM2_Cleanup(&dev);

    printf("tpm2 caps: rc = %d (%s)\n", rc, TPM2_GetRCString(rc));

    return rc;
}

#ifdef WOLFTPM_FIRMWARE_UPGRADE
#if defined(WOLFTPM_SLB9672) || defined(WOLFTPM_SLB9673)
static int do_TPM2_Firmware_Update(void* userCtx, int argc, char *argv[])
{
    int rc;
    WOLFTPM2_DEV dev;
    WOLFTPM2_CAPS caps;
    fw_info_t fwinfo;
    ulong manifest_addr, firmware_addr;
    size_t manifest_sz, firmware_sz;
    uint8_t manifest_hash[TPM_SHA384_DIGEST_SIZE];
    int recovery = 0;

    XMEMSET(&fwinfo, 0, sizeof(fwinfo));

    /* Need 5 args: command + 4 arguments */
    if (argc != 5) {
        printf("Error: Expected 5 arguments but got %d\n", argc);
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
        printf("Error: Invalid memory addresses\n");
        return CMD_RET_FAILURE;
    }

    printf("Infineon Firmware Update Tool\n");
    printf("\tManifest Address: 0x%lx (size: %zu)\n",
        manifest_addr, manifest_sz);
    printf("\tFirmware Address: 0x%lx (size: %zu)\n",
        firmware_addr, firmware_sz);

    rc = TPM2_Init_Device(&dev, userCtx);
    if (rc == TPM_RC_SUCCESS) {
        rc = wolfTPM2_GetCapabilities(&dev, &caps);
    }

    if (rc == TPM_RC_SUCCESS) {
        TPM2_IFX_PrintInfo(&caps);
        if (caps.keyGroupId == 0) {
            printf("Error getting key group id from TPM!\n");
        }
        if (caps.opMode == 0x02 || (caps.opMode & 0x80)) {
            /* if opmode == 2 or 0x8x then we need to use recovery mode */
            recovery = 1;
        }
    }

    if (rc == TPM_RC_SUCCESS) {
        if (recovery) {
            printf("Firmware Update (recovery mode):\n");
            rc = wolfTPM2_FirmwareUpgradeRecover(&dev,
                fwinfo.manifest_buf, (uint32_t)fwinfo.manifest_bufSz,
                TPM2_IFX_FwData_Cb, &fwinfo);
        }
        else {
            /* Normal mode - hash with wc_Sha384Hash */
            printf("Firmware Update (normal mode):\n");
            rc = wc_Sha384Hash(fwinfo.manifest_buf,
                (uint32_t)fwinfo.manifest_bufSz, manifest_hash);
            if (rc == TPM_RC_SUCCESS) {
                rc = wolfTPM2_FirmwareUpgradeHash(&dev, TPM_ALG_SHA384,
                    manifest_hash, (uint32_t)sizeof(manifest_hash),
                    fwinfo.manifest_buf, (uint32_t)fwinfo.manifest_bufSz,
                    TPM2_IFX_FwData_Cb, &fwinfo);
            }
        }
    }
    if (rc == TPM_RC_SUCCESS) {
        TPM2_IFX_PrintInfo(&caps);
    }

    if (fwinfo.manifest_buf)
        unmap_sysmem(fwinfo.manifest_buf);
    if (fwinfo.firmware_buf)
        unmap_sysmem(fwinfo.firmware_buf);

    if (rc != TPM_RC_SUCCESS) {
        printf("Infineon firmware update failed 0x%x: %s\n",
            rc, TPM2_GetRCString(rc));
    }

    wolfTPM2_Cleanup(&dev);

    printf("tpm2 firmware_update: rc=%d (%s)\n", rc, TPM2_GetRCString(rc));

    return rc;
}

static int do_TPM2_Firmware_Cancel(void* userCtx, int argc, char *argv[])
{
    int rc;
    WOLFTPM2_DEV dev;
    uint8_t cmd[TPM2_HEADER_SIZE + 2];
    uint16_t val16;

    if (argc != 1) {
        return CMD_RET_USAGE;
    }

    /* Init the TPM2 device */
    rc = TPM2_Init_Device(&dev, userCtx);
    if (rc == TPM_RC_SUCCESS) {
        /* Setup command size in header */
        val16 = TPM2_HEADER_SIZE + 2;
        XMEMCPY(cmd, &val16, sizeof(val16));
        val16 = 0;
        XMEMCPY(&cmd[TPM2_HEADER_SIZE], &val16, sizeof(val16));

        rc = TPM2_IFX_FieldUpgradeCommand(TPM_CC_FieldUpgradeAbandonVendor,
            cmd, sizeof(cmd));
        if (rc != TPM_RC_SUCCESS) {
            printf("Firmware abandon failed 0x%x: %s\n",
                rc, TPM2_GetRCString(rc));
        }
    }

    wolfTPM2_Cleanup(&dev);

    printf("tpm2 firmware_cancel: rc=%d (%s)\n", rc, TPM2_GetRCString(rc));

    return rc;
}
#endif /* WOLFTPM_SLB9672 || WOLFTPM_SLB9673 */
#endif /* WOLFTPM_FIRMWARE_UPGRADE */

static int do_TPM2_Startup(void* userCtx, int argc, char *const argv[])
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

    XMEMSET(&startupIn, 0, sizeof(startupIn));
    XMEMSET(&shutdownIn, 0, sizeof(shutdownIn));

    /* Init the TPM2 device */
    rc = TPM2_Init_Device(&dev, userCtx);
    if (rc != TPM_RC_SUCCESS) return rc;

    if (!strcmp(argv[1], "TPM2_SU_CLEAR")) {
        if (doStartup == YES) {
            startupIn.startupType = TPM_SU_CLEAR;
        } else {
            shutdownIn.shutdownType = TPM_SU_CLEAR;
        }
    } else if (!strcmp(argv[1], "TPM2_SU_STATE")) {
        if (doStartup == YES) {
            startupIn.startupType = TPM_SU_STATE;
        } else {
            shutdownIn.shutdownType = TPM_SU_STATE;
        }
    } else {
        printf("Couldn't recognize mode string: %s\n", argv[1]);
        wolfTPM2_Cleanup(&dev);
        return CMD_RET_FAILURE;
    }

    /* startup */
    if (doStartup == YES) {
        rc = TPM2_Startup(&startupIn);
        /* TPM_RC_INITIALIZE = Already started */
        if (rc != TPM_RC_SUCCESS && rc != TPM_RC_INITIALIZE) {
            printf("TPM2 Startup: Result = 0x%x (%s)\n", rc,
                TPM2_GetRCString(rc));
        }
    /* shutdown */
    } else {
        rc = TPM2_Shutdown(&shutdownIn);
        if (rc != TPM_RC_SUCCESS) {
            printf("TPM2 Shutdown: Result = 0x%x (%s)\n", rc,
                TPM2_GetRCString(rc));
        }
    }

    wolfTPM2_Cleanup(&dev);

    if (rc >= 0)
        rc = 0;

    printf("tpm2 startup (%s): rc = %d (%s)\n",
        doStartup ? "startup" : "shutdown", rc, TPM2_GetRCString(rc));

    return rc;
}

static int do_TPM2_SelfTest(void* userCtx, int argc, char *const argv[])
{
    int rc;
    WOLFTPM2_DEV dev;
    TPMI_YES_NO fullTest = YES;

    /* Need 2 arg: command + type */
    if (argc != 2) {
        return CMD_RET_USAGE;
    }

    /* Init the TPM2 device */
    rc = TPM2_Init_Device(&dev, userCtx);
    if (rc == TPM_RC_SUCCESS) {
        if (!strcmp(argv[1], "full")) {
            fullTest = YES;
        } else if (!strcmp(argv[1], "continue")) {
            fullTest = NO;
        } else {
            printf("Couldn't recognize test mode: %s\n", argv[1]);
            wolfTPM2_Cleanup(&dev);
            return CMD_RET_FAILURE;
        }

        /* full test */
        if (fullTest == YES) {
            rc = wolfTPM2_SelfTest(&dev);
            if (rc != TPM_RC_SUCCESS) {
                printf("TPM2 Self Test: Result = 0x%x (%s)\n", rc,
                    TPM2_GetRCString(rc));
            }
        /* continue test */
        } else {
            rc = wolfTPM2_SelfTest(&dev);
            if (rc != TPM_RC_SUCCESS) {
                printf("TPM2 Self Test: Result = 0x%x (%s)\n", rc,
                    TPM2_GetRCString(rc));
            }
        }
    }

    wolfTPM2_Cleanup(&dev);

    printf("tpm2 selftest (%s): rc = %d (%s)\n",
        fullTest ? "full" : "continue", rc, TPM2_GetRCString(rc));

    return rc;
}

static int do_TPM2_Clear(void* userCtx, int argc, char *const argv[])
{
    int rc;
    WOLFTPM2_DEV dev;
    Clear_In clearIn;
    TPMI_RH_CLEAR handle;

    /* Need 2 arg: command + type */
    if (argc != 2) {
        return CMD_RET_USAGE;
    }

    if (!strcasecmp("TPM2_RH_LOCKOUT", argv[1])) {
        handle = TPM_RH_LOCKOUT;
    } else if (!strcasecmp("TPM2_RH_PLATFORM", argv[1])) {
        handle = TPM_RH_PLATFORM;
    } else {
        return CMD_RET_USAGE;
    }

    /* Init the TPM2 device */
    rc = TPM2_Init_Device(&dev, userCtx);
    if (rc == TPM_RC_SUCCESS) {
        /* Set up clear */
        XMEMSET(&clearIn, 0, sizeof(clearIn));
        clearIn.authHandle = handle;

        rc = TPM2_Clear(&clearIn);
        if (rc != TPM_RC_SUCCESS) {
            printf("TPM2 Clear: Result = 0x%x (%s)\n", rc,
                TPM2_GetRCString(rc));
        }
    }

    wolfTPM2_Cleanup(&dev);

    printf("tpm2 clear (%s): rc = %d (%s)\n",
        handle == TPM_RH_LOCKOUT ? "TPM2_RH_LOCKOUT" : "TPM2_RH_PLATFORM",
        rc, TPM2_GetRCString(rc));

    return rc;
}

static int do_TPM2_PCR_Extend(void* userCtx, int argc, char *const argv[])
{
    int rc;
    WOLFTPM2_DEV dev;
    uint32_t pcrIndex;
    int algo = TPM_ALG_SHA256;
    int digestLen;
    void *digest;
    ulong digest_addr;

    /* Need 3-4 args: command + pcr + digest_addr + [algo] */
    if (argc < 3 || argc > 4) {
        return CMD_RET_USAGE;
    }
    printf("TPM2 PCR Extend\n");

    pcrIndex = simple_strtoul(argv[1], NULL, 0);
    digest_addr = simple_strtoul(argv[2], NULL, 0);

    /* Optional algorithm */
    if (argc == 4) {
        algo = TPM2_GetAlgId(argv[3]);
        if (algo < 0) {
            printf("Couldn't recognize algorithm: %s\n", argv[3]);
            return CMD_RET_FAILURE;
        }
        printf("Using algorithm: %s\n", TPM2_GetAlgName(algo));
    }

    /* Get digest length based on algorithm */
    digestLen = TPM2_GetHashDigestSize(algo);
    if (digestLen <= 0) {
        printf("Invalid algorithm digest length\n");
        return CMD_RET_FAILURE;
    }

    /* Map digest from memory address */
    digest = map_sysmem(digest_addr, digestLen);
    if (digest == NULL) {
        printf("Error: Invalid digest memory address\n");
        return CMD_RET_FAILURE;
    }

    printf("TPM2 PCR Extend: PCR %u with %s digest\n",
        (unsigned int)pcrIndex, TPM2_GetAlgName(algo));

    /* Init the TPM2 device */
    rc = TPM2_Init_Device(&dev, userCtx);
    if (rc != TPM_RC_SUCCESS) {
        unmap_sysmem(digest);
        return rc;
    }

    /* Extend the PCR */
    rc = wolfTPM2_ExtendPCR(&dev, pcrIndex, algo, digest, digestLen);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_PCR_Extend failed 0x%x: %s\n", rc,
            TPM2_GetRCString(rc));
    }

    unmap_sysmem(digest);
    wolfTPM2_Cleanup(&dev);

    printf("tpm2 pcr_extend: rc = %d (%s)\n", rc, TPM2_GetRCString(rc));

    return rc;
}

static int do_TPM2_PCR_Read(void* userCtx, int argc, char *const argv[])
{
    int rc;
    WOLFTPM2_DEV dev;
    uint32_t pcrIndex;
    int algo = TPM_ALG_SHA256;
    void *digest;
    ulong digest_addr;
    int digestLen;

    /* Need 3-4 args: command + pcr + digest_addr + [algo] */
    if (argc < 3 || argc > 4) {
        return CMD_RET_USAGE;
    }

    pcrIndex = simple_strtoul(argv[1], NULL, 0);
    digest_addr = simple_strtoul(argv[2], NULL, 0);

    /* Optional algorithm */
    if (argc == 4) {
        algo = TPM2_GetAlgId(argv[3]);
        if (algo < 0) {
            printf("Couldn't recognize algorithm: %s\n", argv[3]);
            return CMD_RET_FAILURE;
        }
        printf("Using algorithm: %s\n", TPM2_GetAlgName(algo));
    }

    /* Get digest length based on algorithm */
    digestLen = TPM2_GetHashDigestSize(algo);
    if (digestLen <= 0) {
        printf("Invalid algorithm digest length\n");
        return CMD_RET_FAILURE;
    }

    /* Map digest from memory address */
    digest = map_sysmem(digest_addr, digestLen);
    if (digest == NULL) {
        printf("Error: Invalid digest memory address\n");
        return CMD_RET_FAILURE;
    }

    printf("TPM2 PCR Read: PCR %u to %s digest\n",
        (unsigned int)pcrIndex, TPM2_GetAlgName(algo));

    /* Init the TPM2 device */
    rc = TPM2_Init_Device(&dev, userCtx);
    if (rc != TPM_RC_SUCCESS) {
        unmap_sysmem(digest);
        return rc;
    }

    /* Read the PCR */
    rc = wolfTPM2_ReadPCR(&dev, pcrIndex, algo, digest, &digestLen);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_PCR_Read failed 0x%x: %s\n", rc,
            TPM2_GetRCString(rc));
    }

    unmap_sysmem(digest);
    wolfTPM2_Cleanup(&dev);

    printf("tpm2 pcr_read: rc = %d (%s)\n", rc, TPM2_GetRCString(rc));

    return rc;
}

static int do_TPM2_PCR_Allocate(void* userCtx, int argc, char *const argv[])
{
    int rc;
    WOLFTPM2_DEV dev;
    PCR_Allocate_In in;
    PCR_Allocate_Out out;
    TPM2B_AUTH auth;

    /* Need 3-4 args: command + algorithm + on/off + [password] */
    if (argc < 3 || argc > 4) {
        return CMD_RET_USAGE;
    }

    /* Init the TPM2 device */
    rc = TPM2_Init_Device(&dev, userCtx);
    if (rc != TPM_RC_SUCCESS) return rc;

    /* Setup PCR Allocation command */
    XMEMSET(&in, 0, sizeof(in));
    in.authHandle = TPM_RH_PLATFORM;

    /* Single PCR bank allocation */
    in.pcrAllocation.count = 1; /* Change only one bank */
    in.pcrAllocation.pcrSelections[0].hash = TPM2_GetAlgId(argv[1]);
    in.pcrAllocation.pcrSelections[0].sizeofSelect = PCR_SELECT_MAX;

    /* Set all PCRs for this algorithm */
    if (!strcmp(argv[2], "on")) {
        XMEMSET(in.pcrAllocation.pcrSelections[0].pcrSelect, 0xFF,
            PCR_SELECT_MAX);
    }
    /* Clear all PCRs for this algorithm */
    else if (!strcmp(argv[2], "off")) {
        XMEMSET(in.pcrAllocation.pcrSelections[0].pcrSelect, 0x00,
            PCR_SELECT_MAX);
    }
    else {
        printf("Couldn't recognize allocate mode: %s\n", argv[2]);
        wolfTPM2_Cleanup(&dev);
        return CMD_RET_USAGE;
    }
    printf("Attempting to set %s bank to %s\n",
        TPM2_GetAlgName(in.pcrAllocation.pcrSelections[0].hash),
        argv[2]);

    /* Set auth password if provided */
    if (argc == 4) {
        XMEMSET(&auth, 0, sizeof(auth));
        auth.size = strlen(argv[3]);
        XMEMCPY(auth.buffer, argv[3], auth.size);
        rc = wolfTPM2_SetAuth(&dev, 0, TPM_RH_PLATFORM, &auth, 0, NULL);
        if (rc != TPM_RC_SUCCESS) {
            printf("wolfTPM2_SetAuth failed 0x%x: %s\n", rc,
                TPM2_GetRCString(rc));
            wolfTPM2_Cleanup(&dev);
            return rc;
        }
    }

    /* Allocate the PCR */
    rc = TPM2_PCR_Allocate(&in, &out);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_PCR_Allocate failed 0x%x: %s\n", rc,
            TPM2_GetRCString(rc));
    }

    /* Print current PCR state */
    printf("\n\tNOTE: A TPM restart is required for changes to take effect\n");
    printf("\nCurrent PCR state:\n");
    TPM2_PCRs_Print();

    wolfTPM2_Cleanup(&dev);

    printf("Allocation Success: %s\n",
        out.allocationSuccess ? "YES" : "NO");
    printf("tpm2 pcr_allocate %s (%s): rc = %d (%s)\n",
        TPM2_GetAlgName(in.pcrAllocation.pcrSelections[0].hash),
        argv[2], rc, TPM2_GetRCString(rc));

    return rc;
}

/* We dont have parameter encryption enabled when WOLFTPM2_NO_WOLFCRYPT
 * is defined. If the session isn't used then the new password is not
 * encrypted in transit over the bus: "a session is required to protect
 * the new platform auth" */
#ifndef WOLFTPM2_NO_WOLFCRYPT
static int TPM2_PCR_SetAuth(void* userCtx, int argc, char *argv[],
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
    if (argc < 3 || argc > 4) {
        return CMD_RET_USAGE;
    }

    /* Init the TPM2 device for value/policy */
    rc = TPM2_Init_Device(&dev, userCtx);
    if (rc != TPM_RC_SUCCESS) return rc;

    /* Start the session */
    rc = wolfTPM2_StartSession(&dev, &session, NULL, NULL,
        isPolicy ? TPM_SE_POLICY : TPM_SE_HMAC, TPM_ALG_NULL);
    if (rc != TPM_RC_SUCCESS) {
        printf("wolfTPM2_StartSession failed 0x%x: %s\n", rc,
            TPM2_GetRCString(rc));
        wolfTPM2_Cleanup(&dev);
        return rc;
    }

    /* Set the platform auth if provided */
    if (pw) {
        TPM2B_AUTH platformAuth;
        XMEMSET(&platformAuth, 0, sizeof(platformAuth));
        platformAuth.size = strlen(pw);
        XMEMCPY(platformAuth.buffer, pw, platformAuth.size);
        rc = wolfTPM2_SetAuth(&dev, 0, TPM_RH_PLATFORM,
            &platformAuth, 0, NULL);
        if (rc != TPM_RC_SUCCESS) {
            printf("wolfTPM2_SetAuth failed 0x%x: %s\n", rc,
                TPM2_GetRCString(rc));
            wolfTPM2_UnloadHandle(&dev, &session.handle);
            wolfTPM2_Cleanup(&dev);
            return rc;
        }
    }

    printf("Setting %s auth for PCR %u\n",
        isPolicy ? "policy" : "value", pcrIndex);

    /* Set up the auth value/policy */
    XMEMSET(&auth, 0, sizeof(auth));
    auth.size = key_sz;
    XMEMCPY(auth.buffer, key, key_sz);

    if (isPolicy) {
        /* Use TPM2_PCR_SetAuthPolicy command */
        PCR_SetAuthPolicy_In in;
        XMEMSET(&in, 0, sizeof(in));
        in.authHandle = TPM_RH_PLATFORM;
        in.authPolicy = auth;
        in.hashAlg = TPM_ALG_SHA256; /* Default to SHA256 */
        in.pcrNum = pcrIndex;
        rc = TPM2_PCR_SetAuthPolicy(&in);
    } else {
        /* Use TPM2_PCR_SetAuthValue command */
        PCR_SetAuthValue_In in;
        XMEMSET(&in, 0, sizeof(in));
        in.pcrHandle = pcrIndex;
        in.auth = auth;
        rc = TPM2_PCR_SetAuthValue(&in);
    }

    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_PCR_SetAuth%s failed 0x%x: %s\n",
            isPolicy ? "Policy" : "Value",
            rc, TPM2_GetRCString(rc));
    }

    wolfTPM2_UnloadHandle(&dev, &session.handle);
    wolfTPM2_Cleanup(&dev);

    printf("tpm2 set_auth %s: rc = %d (%s)\n",
        isPolicy ? "Policy" : "Value", rc, TPM2_GetRCString(rc));

    return rc;
}

static int do_TPM2_PCR_SetAuthPolicy(void* userCtx, int argc, char *argv[])
{
    return TPM2_PCR_SetAuth(userCtx, argc, argv, YES);
}

static int do_TPM2_PCR_SetAuthValue(void* userCtx, int argc, char *argv[])
{
    return TPM2_PCR_SetAuth(userCtx, argc, argv, NO);
}

static int do_TPM2_Change_Auth(void* userCtx, int argc, char *const argv[])
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
    if (argc < 3 || argc > 4) {
        return CMD_RET_USAGE;
    }

    /* Init the TPM2 device */
    rc = TPM2_Init_Device(&dev, userCtx);
    if (rc != TPM_RC_SUCCESS) return rc;

    XMEMSET(&in, 0, sizeof(in));

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
        printf("wolfTPM2_StartSession failed 0x%x: %s\n", rc,
            TPM2_GetRCString(rc));
        wolfTPM2_Cleanup(&dev);
        return rc;
    }

    /* If old password exists then set it as the current auth */
    if (oldpw) {
        TPM2B_AUTH oldAuth;
        XMEMSET(&oldAuth, 0, sizeof(oldAuth));
        oldAuth.size = oldpw_sz;
        XMEMCPY(oldAuth.buffer, oldpw, oldpw_sz);
        rc = wolfTPM2_SetAuthPassword(&dev, 0, &oldAuth);
        if (rc != TPM_RC_SUCCESS) {
            printf("wolfTPM2_SetAuthPassword failed 0x%x: %s\n", rc,
                TPM2_GetRCString(rc));
            wolfTPM2_UnloadHandle(&dev, &session.handle);
            wolfTPM2_Cleanup(&dev);
            return rc;
        }
    }

    XMEMSET(&newAuth, 0, sizeof(newAuth));
    newAuth.size = newpw_sz;
    XMEMCPY(newAuth.buffer, newpw, newpw_sz);
    in.newAuth = newAuth;

    /* Change the auth based on the hierarchy */
    rc = wolfTPM2_ChangeHierarchyAuth(&dev, &session, in.authHandle);
    if (rc != TPM_RC_SUCCESS) {
        printf("wolfTPM2_ChangeHierarchyAuth failed 0x%x: %s\n", rc,
            TPM2_GetRCString(rc));
    } else {
        printf("Successfully changed auth for %s\n", argv[1]);
    }

    wolfTPM2_UnloadHandle(&dev, &session.handle);
    wolfTPM2_Cleanup(&dev);

    printf("tpm2 change_auth: rc = %d (%s)\n", rc, TPM2_GetRCString(rc));

    return rc;
}
#endif /* !WOLFTPM2_NO_WOLFCRYPT */

static int do_TPM2_PCR_Print(void* userCtx, int argc, char *argv[])
{
    int rc;
    WOLFTPM2_DEV dev;

    /* Need 1 arg: command */
    if (argc != 1) {
        return CMD_RET_USAGE;
    }

    /* Init the TPM2 device */
    rc = TPM2_Init_Device(&dev, userCtx);
    if (rc == TPM_RC_SUCCESS) {
        /* Print the current PCR state */
        TPM2_PCRs_Print();
    }
    wolfTPM2_Cleanup(&dev);

    printf("tpm2 pcr_print: rc = %d (%s)\n", rc, TPM2_GetRCString(rc));

    return rc;
}

static int do_TPM2_Dam_Reset(void* userCtx, int argc, char *const argv[])
{
    int rc;
    WOLFTPM2_DEV dev;
    const char *pw = (argc < 2) ? NULL : argv[1];
    const ssize_t pw_sz = pw ? strlen(pw) : 0;
    DictionaryAttackLockReset_In in;
    TPM2_AUTH_SESSION session[MAX_SESSION_NUM];

    /* Need 1-2 args: command + [password] */
    if (argc > 2) {
        return CMD_RET_USAGE;
    }

    /* Validate password length if provided */
    if (pw && pw_sz > TPM_SHA256_DIGEST_SIZE) {
        printf("Error: Password too long\n");
        return -EINVAL;
    }

    /* Init the TPM2 device */
    rc = TPM2_Init_Device(&dev, userCtx);
    if (rc == TPM_RC_SUCCESS) {
        /* set lock handle */
        XMEMSET(&in, 0, sizeof(in));
        in.lockHandle = TPM_RH_LOCKOUT;

        /* Setup auth session only if password provided */
        XMEMSET(session, 0, sizeof(session));
        session[0].sessionHandle = TPM_RS_PW;
        if (pw) {
            session[0].auth.size = pw_sz;
            XMEMCPY(session[0].auth.buffer, pw, pw_sz);
        }
        TPM2_SetSessionAuth(session);

        rc = TPM2_DictionaryAttackLockReset(&in);
        printf("TPM2_Dam_Reset: Result = 0x%x (%s)\n", rc,
            TPM2_GetRCString(rc));
    }
    wolfTPM2_Cleanup(&dev);

    printf("tpm2 dam_reset: rc = %d (%s)\n", rc, TPM2_GetRCString(rc));

    return rc;
}

static int do_TPM2_Dam_Parameters(void* userCtx, int argc, char *const argv[])
{
    int rc;
    WOLFTPM2_DEV dev;
    const char *pw = (argc < 5) ? NULL : argv[4];
	const ssize_t pw_sz = pw ? strlen(pw) : 0;
    DictionaryAttackParameters_In in;
    TPM2_AUTH_SESSION session[MAX_SESSION_NUM];

    /* Need 4-5 args: command + max_tries + recovery_time +
     * lockout_recovery + [password] */
    if (argc < 4 || argc > 5) {
        return CMD_RET_USAGE;
    }

    /* Validate password length if provided */
    if (pw && pw_sz > TPM_SHA256_DIGEST_SIZE) {
        printf("Error: Password too long\n");
        return -EINVAL;
    }

    /* Init the TPM2 device */
    rc = TPM2_Init_Device(&dev, userCtx);
    if (rc == TPM_RC_SUCCESS) {
        /* Set parameters */
        XMEMSET(&in, 0, sizeof(in));
        in.newMaxTries = simple_strtoul(argv[1], NULL, 0);
        in.newRecoveryTime = simple_strtoul(argv[2], NULL, 0);
        in.lockoutRecovery = simple_strtoul(argv[3], NULL, 0);

        /* set lock handle */
        in.lockHandle = TPM_RH_LOCKOUT;

        /* Setup auth session only if password provided */
        XMEMSET(session, 0, sizeof(session));
        session[0].sessionHandle = TPM_RS_PW;
        if (pw) {
            session[0].auth.size = pw_sz;
            XMEMCPY(session[0].auth.buffer, pw, pw_sz);
        }
        TPM2_SetSessionAuth(session);

        /* Set DAM parameters */
        rc = TPM2_DictionaryAttackParameters(&in);
        if (rc != TPM_RC_SUCCESS) {
            printf("TPM2_DictionaryAttackParameters failed 0x%x: %s\n", rc,
                TPM2_GetRCString(rc));
        }

        printf("Changing dictionary attack parameters:\n");
        printf("  maxTries: %u\n", in.newMaxTries);
        printf("  recoveryTime: %u\n", in.newRecoveryTime);
        printf("  lockoutRecovery: %u\n", in.lockoutRecovery);
    }
    wolfTPM2_Cleanup(&dev);

    printf("tpm2 dam_parameters: rc = %d (%s)\n", rc, TPM2_GetRCString(rc));

    return rc;
}

/* Main command handler for wolfTPM U-boot commands */
static int do_wolftpm(struct cmd_tbl *cmdtp, int flag, int argc,
    char *const argv[])
{
    if (argc < 2) {
        return CMD_RET_USAGE;
    }

    /* Common commands */
    if (strcmp(argv[1], "device") == 0) {
        return do_TPM2_Device(NULL, argc-1, (char **)&argv[1]);
    }
    if (strcmp(argv[1], "info") == 0) {
        return do_TPM2_Info(NULL, argc-1, (char **)&argv[1]);
    }
    if (strcmp(argv[1], "state") == 0) {
        return do_TPM2_State(NULL, argc-1, (char **)&argv[1]);
    }
    if (strcmp(argv[1], "init") == 0) {
        return do_TPM2_Init(NULL, argc-1, (char **)&argv[1]);
    }
    if (strcmp(argv[1], "autostart") == 0) {
        return do_TPM2_AutoStart(NULL, argc-1, (char **)&argv[1]);
    }

    /* wolfTPM U-boot commands */
    if (strcmp(argv[1], "startup") == 0) {
        return do_TPM2_Startup(NULL, argc-1, (char **)&argv[1]);
    }
    if (strcmp(argv[1], "self_test") == 0) {
        return do_TPM2_SelfTest(NULL, argc-1, (char **)&argv[1]);
    }
    if (strcmp(argv[1], "clear") == 0) {
        return do_TPM2_Clear(NULL, argc-1, (char **)&argv[1]);
    }
    if (strcmp(argv[1], "pcr_extend") == 0) {
        return do_TPM2_PCR_Extend(NULL, argc-1, (char **)&argv[1]);
    }
    if (strcmp(argv[1], "pcr_read") == 0) {
        return do_TPM2_PCR_Read(NULL, argc-1, (char **)&argv[1]);
    }
    if (strcmp(argv[1], "pcr_allocate") == 0) {
        return do_TPM2_PCR_Allocate(NULL, argc-1, (char **)&argv[1]);
    }
    if (strcmp(argv[1], "pcr_print") == 0) {
        return do_TPM2_PCR_Print(NULL, argc-1, (char **)&argv[1]);
    }
#ifndef WOLFTPM2_NO_WOLFCRYPT
    if (strcmp(argv[1], "change_auth") == 0) {
        return do_TPM2_Change_Auth(NULL, argc-1, (char **)&argv[1]);
    }
    if (strcmp(argv[1], "pcr_setauthpolicy") == 0) {
        return do_TPM2_PCR_SetAuthPolicy(NULL, argc-1, (char **)&argv[1]);
    }
    if (strcmp(argv[1], "pcr_setauthvalue") == 0) {
        return do_TPM2_PCR_SetAuthValue(NULL, argc-1, (char **)&argv[1]);
    }
#endif /* !WOLFTPM2_NO_WOLFCRYPT */
    if (strcmp(argv[1], "get_capability") == 0) {
        return do_TPM2_Wrapper_GetCapsArgs(NULL, argc-1, (char **)&argv[1]);
    }
    if (strcmp(argv[1], "dam_reset") == 0) {
        return do_TPM2_Dam_Reset(NULL, argc-1, (char **)&argv[1]);
    }
    if (strcmp(argv[1], "dam_parameters") == 0) {
        return do_TPM2_Dam_Parameters(NULL, argc-1, (char **)&argv[1]);
    }

    /* New wolfTPM Commands */
    if (strcmp(argv[1], "caps") == 0) {
        return do_TPM2_Wrapper_CapsArgs(NULL, argc-1, (char **)&argv[1]);
    }
#ifdef WOLFTPM_FIRMWARE_UPGRADE
#if defined(WOLFTPM_SLB9672) || defined(WOLFTPM_SLB9673)
    if (strcmp(argv[1], "firmware_update") == 0) {
        return do_TPM2_Firmware_Update(NULL, argc-1, (char **)&argv[1]);
    }
    if (strcmp(argv[1], "firmware_cancel") == 0) {
        return do_TPM2_Firmware_Cancel(NULL, argc-1, (char **)&argv[1]);
    }
#endif
#endif /* WOLFTPM_FIRMWARE_UPGRADE */

    return CMD_RET_USAGE;
}

U_BOOT_CMD(
    tpm2,                   /* name of cmd */
    CONFIG_SYS_MAXARGS,     /* max args    */
    1,                      /* repeatable  */
    do_wolftpm,             /* function    */
    "Issue a TPMv2.x command (using wolfTPM stack)",
    "<command> [<arguments>]\n"
    "\n"
    "Commands:\n"
    "help\n"
    "      Show this help text\n"
    "device [num device]\n"
    "      Show all devices or set the specified device\n"
    "info\n"
    "      Show information about the TPM.\n"
    "state\n"
    "      Show internal state from the TPM (if available)\n"
    "autostart\n"
    "      Initalize the tpm, perform a Startup(clear) and run a full selftest\n"
    "      sequence\n"
    "init\n"
    "      Initialize the software stack. Always the first command to issue.\n"
    "      'tpm startup' is the only acceptable command after a 'tpm init' has been\n"
    "      issued\n"
    "startup <mode> [<op>]\n"
    "      Issue a TPM2_Startup command.\n"
    "      <mode> is one of:\n"
    "          * TPM2_SU_CLEAR (reset state)\n"
    "          * TPM2_SU_STATE (preserved state)\n"
    "      [<op>]: optional shutdown\n"
    "          * off - To shutdown the TPM\n"
    "self_test <type>\n"
    "      Test the TPM capabilities.\n"
    "      <type> is one of:\n"
    "          * full (perform all tests)\n"
    "          * continue (only check untested tests)\n"
    "clear <hierarchy>\n"
    "      Issue a TPM2_Clear command.\n"
    "      <hierarchy> is one of:\n"
    "          * TPM2_RH_LOCKOUT\n"
    "          * TPM2_RH_PLATFORM\n"
    "pcr_extend <pcr> <digest_addr> [<digest_algo>]\n"
    "      Extend PCR #<pcr> with digest at <digest_addr> with digest_algo.\n"
    "      <pcr>: index of the PCR\n"
    "      <digest_addr>: address of digest of digest_algo type (defaults to SHA256)\n"
    "      [<digest_algo>]: algorithm to use for digest\n"
    "pcr_read <pcr> <digest_addr> [<digest_algo>]\n"
    "      Read PCR #<pcr> to memory address <digest_addr> with <digest_algo>.\n"
    "      <pcr>: index of the PCR\n"
    "      <digest_addr>: address of digest of digest_algo type (defaults to SHA256)\n"
    "      [<digest_algo>]: algorithm to use for digest\n"
    "pcr_print\n"
    "      Prints the current PCR state\n"
    "caps\n"
    "      Show TPM capabilities and info\n"
    "get_capability <capability> <property> <addr> <count>\n"
    "    Read and display <count> entries indexed by <capability>/<property>.\n"
    "    Values are 4 bytes long and are written at <addr>.\n"
    "    <capability>: capability\n"
    "    <property>: property\n"
    "    <addr>: address to store <count> entries of 4 bytes\n"
    "    <count>: number of entries to retrieve\n"
    "dam_reset [<password>]\n"
    "      If the TPM is not in a LOCKOUT state, reset the internal error counter.\n"
    "      [<password>]: optional password\n"
    "dam_parameters <max_tries> <recovery_time> <lockout_recovery> [<password>]\n"
    "      If the TPM is not in a LOCKOUT state, sets the DAM parameters\n"
    "      <max_tries>: maximum number of failures before lockout,\n"
    "          0 means always locking\n"
    "      <recovery_time>: time before decrement of the error counter,\n"
    "          0 means no lockout\n"
    "      <lockout_recovery>: time of a lockout (before the next try),\n"
    "          0 means a reboot is needed\n"
    "      [<password>]: optional password of the LOCKOUT hierarchy\n"
    "change_auth <hierarchy> <new_pw> [<old_pw>]\n"
    "      <hierarchy>: the hierarchy\n"
    "          * TPM2_RH_LOCKOUT\n"
    "          * TPM2_RH_ENDORSEMENT\n"
    "          * TPM2_RH_OWNER\n"
    "          * TPM2_RH_PLATFORM\n"
    "      <new_pw>: new password for <hierarchy>\n"
    "      [<old_pw>]: optional previous password of <hierarchy>\n"
    "pcr_setauthpolicy | pcr_setauthvalue <pcr> <key> [<password>]\n"
    "      Change the <key> to access PCR #<pcr>.\n"
    "      <pcr>: index of the PCR\n"
    "      <key>: secret to protect the access of PCR #<pcr>\n"
    "      [<password>]: optional password of the PLATFORM hierarchy\n"
    "pcr_allocate <algorithm> <on/off> [<password>]\n"
    "      Issue a TPM2_PCR_Allocate Command to reconfig PCR bank algorithm.\n"
    "      <algorithm> is one of:\n"
    "          * SHA1\n"
    "          * SHA256\n"
    "          * SHA384\n"
    "          * SHA512\n"
    "      <on|off> is one of:\n"
    "          * on  - Select all available PCRs associated with the specified\n"
    "                  algorithm (bank)\n"
    "          * off - Clear all available PCRs associated with the specified\n"
    "                  algorithm (bank)\n"
    "      [<password>]: optional password\n"

#ifdef WOLFTPM_FIRMWARE_UPGRADE
#if defined(WOLFTPM_SLB9672) || defined(WOLFTPM_SLB9673)
    "firmware_update <manifest_addr> <manifest_sz> <firmware_addr> <firmware_sz>\n"
    "      Update TPM firmware\n"
    "firmware_cancel\n"
    "      Cancel TPM firmware update\n"
#endif
#endif
);

#endif /* !WOLFTPM2_NO_WRAPPER */

/******************************************************************************/
/* --- END TPM 2.0 Commands -- */
/******************************************************************************/
