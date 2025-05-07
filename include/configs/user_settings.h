/* user_settings.h
 *
 * SPDX-License-Identifier: GPL-2.0+
 *
 * (C) Copyright 2025
 * Aidan Garske <aidan@wolfssl.com>
 */

#ifndef USER_SETTINGS_H
#define USER_SETTINGS_H

#ifdef __cplusplus
extern "C" {
#endif

/******************************************************************************/
/* --- BEGIN wolfTPM U-boot Settings -- */
/******************************************************************************/

#ifdef CONFIG_TPM_AUTODETECT
    #define WOLFTPM_AUTODETECT
#else
    /* Firmware upgrade only supported
    * by infineon SLB9672/SLB9673 use
    * this for now */
    #define WOLFTPM_FIRMWARE_UPGRADE
    #define WOLFTPM_SLB9672
    //#define WOLFTPM_SLB9673
#endif

/* Include delay.h and types.h for
 * U-boot time delay and types */
#include <linux/delay.h>
#include <linux/types.h>
#include <stdint.h>

/* No wolfCrypt dependency */
#undef  WOLFTPM2_NO_WOLFCRYPT
#define WOLFTPM2_NO_WOLFCRYPT

/* For U-boot with Linux device */
#define WOLFTPM_LINUX_DEV

#define XSLEEP_MS(ms) udelay(ms * 1000)

/* Just poll without delay by default */
#define XTPM_WAIT()

/* Do not include API's that use heap(), they are not required */
#define WOLFTPM2_NO_HEAP

/* Debugging */
#ifdef CONFIG_TPM_LOG
    #define DEBUG_WOLFTPM
    #define WOLFTPM_DEBUG_VERBOSE
    #define WOLFTPM_DEBUG_IO
#endif

/******************************************************************************/
/* --- END wolfTPM U-boot Settings -- */
/******************************************************************************/

#ifdef __cpluspluss
}
#endif

#endif /* USER_SETTINGS_H */
