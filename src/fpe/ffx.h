#ifndef WBCRYPTO_FFX_H
#define WBCRYPTO_FFX_H

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "bn.h"
#include <wbcrypto/modes.h>

#ifdef __cplusplus
extern "C"
{
#endif

    uint8_t *ffx_revb(uint8_t *const dst,
                      const uint8_t *const src, const size_t len);
    static inline char *ffx_revs(char *const dst, const char *const src)
    {
        const size_t len = strlen(src);
        char *const res =
            (char *)ffx_revb((uint8_t *)dst, (const uint8_t *)src, len);
        dst[len] = '\0';
        return res;
    }

    int ffx_str(char *const str, const size_t len,
                const unsigned int m, const unsigned int r, const bigint_t *n);

    void *ffx_memxor(void *d,
                     const void *s1, const void *s2,
                     size_t len);

    struct ffx_ctx
    {
        void *cipher_ctx; // cipher context used
        block128_f block; // encryption algorithm

        unsigned int radix;
        // struct
        // {
        //     size_t min, max;
        // } txtlen, twklen;
        size_t txtminlen;
        size_t txtmaxlen;
        size_t twkminlen;
        size_t twkmaxlen;
        // struct
        // {
        //     uint8_t *buf;
        //     size_t len;
        // } key, twk;
        uint8_t *twk_buf;
        size_t twk_len;
    };

    typedef struct ffx_ctx WBCRYPTO_ffx_context;

    int ffx_prf(WBCRYPTO_ffx_context *ctx,
                uint8_t *const dst, const uint8_t *const src, const size_t len);

    int ffx_ciph(WBCRYPTO_ffx_context *const ctx,
                 uint8_t *const dst, const uint8_t *const src);

    WBCRYPTO_ffx_context *ffx_ctx_create(const uint8_t *const twkbuf, const size_t twklen,
                                        const size_t maxtxtlen, const size_t mintwklen, const size_t maxtwklen,
                                        const unsigned int radix,
                                        const void *cipher_ctx, block128_f block);

    void ffx_ctx_free(WBCRYPTO_ffx_context *ctx);

#ifdef __cplusplus
}
#endif

#endif //WBCRYPTO_FFX_H