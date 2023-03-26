#include <wbcrypto/wbaes.h>

int WBCRYPTO_wbaes_cbc_encrypt(const unsigned char *in, size_t inlen,
                             unsigned char *out, size_t max_olen, size_t *use_olen,
                             const WBCRYPTO_wbaes_context *ctx,
                             unsigned char ivec[16]){
    int ret=0;
    WBCRYPTO_MPI_CHK(
            WBCRYPTO_cbc128_encrypt(in, inlen, out, max_olen, use_olen, ctx, ivec,
                                    (block128_f) WBCRYPTO_wbaes_encrypt)
    );
    ret=1;
cleanup:
    return ret;
}

WBCRYPTO_gcm_context *WBCRYPTO_wbaes_gcm_init(WBCRYPTO_wbaes_context *key){
    WBCRYPTO_gcm_context *ctx=WBCRYPTO_gcm_init(key, (block128_f) WBCRYPTO_wbaes_encrypt);
    return ctx;
}

WBCRYPTO_gcmfile_context *WBCRYPTO_wbaes_gcmfile_init(WBCRYPTO_wbaes_context *key){
    WBCRYPTO_gcmfile_context *ctx=WBCRYPTO_gcmfile_init(key,(block128_f) WBCRYPTO_wbaes_encrypt);
    return ctx;
}

WBCRYPTO_fpe_context *WBCRYPTO_wbaes_fpe_init(WBCRYPTO_wbaes_context *key, const char *twkbuf, size_t twklen, unsigned int radix)
{
    WBCRYPTO_fpe_context *ctx = WBCRYPTO_fpe_init(twkbuf, twklen, radix, key, (block128_f)WBCRYPTO_wbaes_encrypt);
    return ctx;
}
