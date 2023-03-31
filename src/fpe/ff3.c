#include <wbcrypto/fpe.h>
#include "fpe_locl.h"

int WBCRYPTO_ff3_encrypt(WBCRYPTO_fpe_context *ctx, const char *input, char *output) {
    int ret = 0;
    BIGNUM *bnum = BN_new(),
            *y = BN_new(),
            *c = BN_new(),
            *anum = BN_new(),
            *qpow_u = BN_new(),
            *qpow_v = BN_new();
    BN_CTX *bn_ctx = BN_CTX_new();

    unsigned int inlen = strlen(input);
    unsigned int in[inlen], out[inlen];
    map_chars(input, in);

    memcpy(out, in, inlen << 2);
    int u = ceil2(inlen, 1);
    int v = inlen - u;
    unsigned int *A = out, *B = out + u;
    pow_uv(qpow_u, qpow_v, ctx->radix, u, v, bn_ctx);
    unsigned int temp = (unsigned int) ceil(u * log2(ctx->radix));
    const int b = ceil2(temp, 3);

    unsigned char S[16], P[16];
    unsigned char *Bytes = (unsigned char *) OPENSSL_malloc(b);

    for (int i = 0; i < FF3_ROUNDS; ++i) {
        // i
        unsigned int m;
        if (i & 1) {
            m = v;
            memcpy(P, ctx->tweak, 4);
        } else {
            m = u;
            memcpy(P, ctx->tweak + 4, 4);
        }
        P[3] ^= i & 0xff;

        str2num_rev(bnum, B, ctx->radix, inlen - m, bn_ctx);
        memset(Bytes, 0x00, b);
        int BytesLen = BN_bn2bin(bnum, Bytes);
        BytesLen = BytesLen > 12 ? 12 : BytesLen;
        memset(P + 4, 0x00, 12);
        memcpy(P + 16 - BytesLen, Bytes, BytesLen);

        // iii
        rev_bytes(P, 16);
        // AES_encrypt(P, S, &aes_enc_ctx);
        (*ctx->block)(P, S, ctx->cipher_ctx);
        rev_bytes(S, 16);

        // iv
        BN_bin2bn(S, 16, y);

        // v
        str2num_rev(anum, A, ctx->radix, m, bn_ctx);
        if (i & 1) BN_mod_add(c, anum, y, qpow_v, bn_ctx);
        else BN_mod_add(c, anum, y, qpow_u, bn_ctx);

        assert(A != B);
        A = (unsigned int *) ((uintptr_t) A ^ (uintptr_t) B);
        B = (unsigned int *) ((uintptr_t) B ^ (uintptr_t) A);
        A = (unsigned int *) ((uintptr_t) A ^ (uintptr_t) B);

        num2str_rev(c, B, ctx->radix, m, bn_ctx);
    }
    inverse_map_chars(out, output, inlen);

    ret = 1;
cleanup:
    // free the space
    BN_clear_free(anum);
    BN_clear_free(bnum);
    BN_clear_free(c);
    BN_clear_free(y);
    BN_clear_free(qpow_u);
    BN_clear_free(qpow_v);
    BN_CTX_free(bn_ctx);
    OPENSSL_free(Bytes);
    return ret;
}

int WBCRYPTO_ff3_decrypt(WBCRYPTO_fpe_context *ctx, const char *input, char *output) {
    int ret = 0;
    BIGNUM *bnum = BN_new(),
            *y = BN_new(),
            *c = BN_new(),
            *anum = BN_new(),
            *qpow_u = BN_new(),
            *qpow_v = BN_new();
    BN_CTX *bn_ctx = BN_CTX_new();

    unsigned int inlen = strlen(input);
    unsigned int in[inlen], out[inlen];
    map_chars(input, in);

    memcpy(out, in, inlen << 2);
    int u = ceil2(inlen, 1);
    int v = inlen - u;
    unsigned int *A = out, *B = out + u;
    pow_uv(qpow_u, qpow_v, ctx->radix, u, v, bn_ctx);
    unsigned int temp = (unsigned int) ceil(u * log2(ctx->radix));
    const int b = ceil2(temp, 3);

    unsigned char S[16], P[16];
    unsigned char *Bytes = (unsigned char *) OPENSSL_malloc(b);
    for (int i = FF3_ROUNDS - 1; i >= 0; --i) {
        // i
        int m;
        if (i & 1) {
            m = v;
            memcpy(P, ctx->tweak, 4);
        } else {
            m = u;
            memcpy(P, ctx->tweak + 4, 4);
        }
        P[3] ^= i & 0xff;

        // ii

        str2num_rev(anum, A, ctx->radix, inlen - m, bn_ctx);
        memset(Bytes, 0x00, b);
        int BytesLen = BN_bn2bin(anum, Bytes);
        BytesLen = BytesLen > 12 ? 12 : BytesLen;
        memset(P + 4, 0x00, 12);
        memcpy(P + 16 - BytesLen, Bytes, BytesLen);

        // iii
        rev_bytes(P, 16);
        memset(S, 0x00, sizeof(S));
        // AES_encrypt(P, S, &aes_enc_ctx);
        (*ctx->block)(P, S, ctx->cipher_ctx);
        rev_bytes(S, 16);

        // iv
        BN_bin2bn(S, 16, y);

        // v
        str2num_rev(bnum, B, ctx->radix, m, bn_ctx);
        if (i & 1) BN_mod_sub(c, bnum, y, qpow_v, bn_ctx);
        else BN_mod_sub(c, bnum, y, qpow_u, bn_ctx);

        assert(A != B);
        A = (unsigned int *) ((uintptr_t) A ^ (uintptr_t) B);
        B = (unsigned int *) ((uintptr_t) B ^ (uintptr_t) A);
        A = (unsigned int *) ((uintptr_t) A ^ (uintptr_t) B);

        num2str_rev(c, A, ctx->radix, m, bn_ctx);
    }
    inverse_map_chars(out, output, inlen);

    ret = 1;
cleanup:
    BN_clear_free(anum);
    BN_clear_free(bnum);
    BN_clear_free(c);
    BN_clear_free(y);
    BN_clear_free(qpow_u);
    BN_clear_free(qpow_v);
    BN_CTX_free(bn_ctx);
    OPENSSL_free(Bytes);
    return ret;
}