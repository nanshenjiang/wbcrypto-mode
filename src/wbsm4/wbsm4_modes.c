#include <wbcrypto/wbsm4.h>

int WBCRYPTO_wbsm4_cbc_encrypt(const unsigned char *in, size_t inlen,
                             unsigned char *out, size_t max_olen, size_t *use_olen,
                             const WBCRYPTO_wbsm4_context *ctx,
                             unsigned char ivec[16]){
    int ret=0;
    WBCRYPTO_MPI_CHK(
            WBCRYPTO_cbc128_encrypt(in, inlen, out, max_olen, use_olen, ctx, ivec,
                                    (block128_f) WBCRYPTO_wbsm4_encrypt)
    );
    ret=1;
cleanup:
    return ret;
}

int WBCRYPTO_wbsm4_cbc_decrypt(const unsigned char *in, size_t inlen,
                             unsigned char *out, size_t max_olen, size_t *use_olen,
                             const WBCRYPTO_wbsm4_context *ctx,
                             unsigned char ivec[16]){
    int ret=0;
    WBCRYPTO_MPI_CHK(
            WBCRYPTO_cbc128_decrypt(in, inlen, out, max_olen, use_olen, ctx, ivec,
                                    (block128_f) WBCRYPTO_wbsm4_decrypt)
    );
    *use_olen = WBCRYPTO_padding_pkcs7_separate_length(out, inlen);
    ret=1;
cleanup:
    return ret;
}

WBCRYPTO_gcm_context *WBCRYPTO_wbsm4_gcm_init(WBCRYPTO_wbsm4_context *key){
    WBCRYPTO_gcm_context *ctx=WBCRYPTO_gcm_init(key, (block128_f) WBCRYPTO_wbsm4_encrypt);
    return ctx;
}

WBCRYPTO_gcmfile_context *WBCRYPTO_wbsm4_gcmfile_init(WBCRYPTO_wbsm4_context *key){
    WBCRYPTO_gcmfile_context *ctx=WBCRYPTO_gcmfile_init(key,(block128_f) WBCRYPTO_wbsm4_encrypt);
    return ctx;
}

WBCRYPTO_fpe_context *WBCRYPTO_wbsm4_fpe_init(WBCRYPTO_wbsm4_context *key, const char *twkbuf, size_t twklen, unsigned int radix)
{
    WBCRYPTO_fpe_context *ctx = WBCRYPTO_fpe_init(twkbuf, twklen, radix, key, (block128_f)WBCRYPTO_wbsm4_encrypt);
    return ctx;
}

WBCRYPTO_fpe_mac_context *WBCRYPTO_wbsm4_fpe_mac_init(WBCRYPTO_wbsm4_context *key, const char *twkbuf, size_t twklen, unsigned int radix)
{
    WBCRYPTO_fpe_mac_context *ctx = WBCRYPTO_fpe_mac_init(twkbuf, twklen, radix, key, (block128_f)WBCRYPTO_wbsm4_encrypt);
    return ctx;
}