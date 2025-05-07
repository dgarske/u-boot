/* wolftpm.c
 *
 * SPDX-License-Identifier: GPL-2.0+
 *
 * (C) Copyright 2025
 * Aidan Garske <aidan@wolfssl.com>
 */

/* wolfTPM wrapper layer to expose U-boot API
 * when wolfCrypt is not available. This is used by
 * the U-boot firmware update command.
 */

#include <hash.h>
#include <linux/types.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <malloc.h>
#include <mapmem.h>
#include <asm/cache.h>
#include <errno.h>

/* Add wolfTPM type definitions */
typedef uint8_t byte;
typedef uint32_t word32;

#ifdef WOLFTPM2_NO_WOLFCRYPT
int wc_Sha384Hash(const byte* data, word32 len, byte* hash)
{
    struct hash_algo *algo;
    u8 *output;
    void *buf;

    if (hash_lookup_algo("sha384", &algo)) {
        printf("Unknown hash algorithm 'sha384'\n");
        return -1;
    }

    output = (u8 *)memalign(ARCH_DMA_MINALIGN,
                algo->digest_size);
    if (!output) {
        return -ENOMEM;
    }

    buf = (void *)map_sysmem((ulong)data, len);
    algo->hash_func_ws(buf, len, output, algo->chunk_size);
    unmap_sysmem(buf);

    memcpy(hash, output, algo->digest_size);

    free(output);
    return 0;
}
#endif /* WOLFTPM2_NO_WOLFCRYPT */
