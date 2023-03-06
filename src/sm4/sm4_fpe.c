#include <wbcrypto/sm4.h>

WBCRYPTO_ff1_context *WBCRYPTO_sm4_ff1_init(WBCRYPTO_sm4_context *key, const char *twkbuf, size_t twklen, unsigned int radix)
{
    WBCRYPTO_ff1_context *ctx = WBCRYPTO_ff1_init(twkbuf, twklen, radix, key, (block128_f)WBCRYPTO_sm4_encrypt);
    return ctx;
}