#include <wbcrypto/fpe.h>
#include "fpe_locl.h"

void gmac_mult_H(const uint64_t HH[16], const uint64_t HL[16],
                 const unsigned char x[16], unsigned char output[16]) {
    int i;
    unsigned char lo, hi, rem;
    uint64_t zh, zl;

    lo = (unsigned char) (x[15] & 0x0f);
    hi = (unsigned char) (x[15] >> 4);
    zh = HH[lo];
    zl = HL[lo];

    for (i = 15; i >= 0; i--) {
        lo = (unsigned char) (x[i] & 0x0f);
        hi = (unsigned char) (x[i] >> 4);

        if (i != 15) {
            rem = (unsigned char) (zl & 0x0f);
            zl = (zh << 60) | (zl >> 4);
            zh = (zh >> 4);
            zh ^= (uint64_t) last4[rem] << 48;
            zh ^= HH[lo];
            zl ^= HL[lo];
        }
        rem = (unsigned char) (zl & 0x0f);
        zl = (zh << 60) | (zl >> 4);
        zh = (zh >> 4);
        zh ^= (uint64_t) last4[rem] << 48;
        zh ^= HH[hi];
        zl ^= HL[hi];
    }
    PUT_UINT32_BE(zh >> 32, output, 0);
    PUT_UINT32_BE(zh, output, 4);
    PUT_UINT32_BE(zl >> 32, output, 8);
    PUT_UINT32_BE(zl, output, 12);
}

int gmac_gen_H(WBCRYPTO_fpe_mac_context *ctx, uint64_t *HH, uint64_t *HL) {
    int ret = 0;
    int i, j;
    unsigned char h[16] = {0};
    uint64_t hi, lo;
    uint64_t vl, vh;
    WBCRYPTO_MPI_CHK((*ctx->fpe_ctx->block)(h, h, ctx->fpe_ctx->cipher_ctx));

    GET_UINT32_BE(hi, h, 0);    // pack h as two 64-bit ints, big-endian
    GET_UINT32_BE(lo, h, 4);
    vh = (uint64_t) hi << 32 | lo;

    GET_UINT32_BE(hi, h, 8);
    GET_UINT32_BE(lo, h, 12);
    vl = (uint64_t) hi << 32 | lo;

    HL[8] = vl;                // 8 = 1000 corresponds to 1 in GF(2^128)
    HH[8] = vh;
    HH[0] = 0;                 // 0 corresponds to 0 in GF(2^128)
    HL[0] = 0;

    for (i = 4; i > 0; i >>= 1) {
        uint32_t T = (uint32_t) (vl & 1) * 0xe1000000U;
        vl = (vh << 63) | (vl >> 1);
        vh = (vh >> 1) ^ ((uint64_t) T << 32);
        HL[i] = vl;
        HH[i] = vh;
    }
    for (i = 2; i < 16; i <<= 1) {
        uint64_t *HiL = HL + i, *HiH = HH + i;
        vh = *HiH;
        vl = *HiL;
        for (j = 1; j < i; j++) {
            HiH[j] = vh ^ HH[j];
            HiL[j] = vl ^ HL[j];
        }
    }
    ret = 1;
    cleanup:
    return ret;
}

int WBCRYPTO_ff3_gmac_encrypt(WBCRYPTO_fpe_mac_context *ctx, const char *input, char *output) {
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
    pow_uv(qpow_u, qpow_v, ctx->fpe_ctx->radix, u, v, bn_ctx);
    unsigned int temp = (unsigned int) ceil(u * log2(ctx->fpe_ctx->radix));
    const int b = ceil2(temp, 3);

    unsigned char S[16], P[16];
    unsigned char *Bytes = (unsigned char *) OPENSSL_malloc(b);

    //gmac
    uint64_t HH[16] = {0}, HL[16] = {0};
    gmac_gen_H(ctx, HH, HL);
    unsigned char T[16], M[16];
    memcpy(T, ctx->fpe_ctx->tweak, 16);
    gmac_mult_H(HH, HL, T, M);

    for (int i = 0; i < FF3_ROUNDS; ++i) {
        // i
        unsigned int m;
        if (i & 1) {
            m = v;
            memcpy(P, ctx->fpe_ctx->tweak, 4);
        } else {
            m = u;
            memcpy(P, ctx->fpe_ctx->tweak + 4, 4);
        }
        P[3] ^= i & 0xff;

        // ii
        str2num_rev(bnum, B, ctx->fpe_ctx->radix, inlen - m, bn_ctx);
        memset(Bytes, 0x00, b);
        int BytesLen = BN_bn2bin(bnum, Bytes);
        BytesLen = BytesLen > 12 ? 12 : BytesLen;
        memset(P + 4, 0x00, 12);
        memcpy(P + 16 - BytesLen, Bytes, BytesLen);

        // iii
        rev_bytes(P, 16);
        // AES_encrypt(P, S, &aes_enc_ctx);
        (*ctx->fpe_ctx->block)(P, S, ctx->fpe_ctx->cipher_ctx);
        rev_bytes(S, 16);

        //gmac
        unsigned char M_tmp[16];
        gmac_mult_H(HH, HL, S, M_tmp);
        for (int j = 0; j < 16; j++) {
            M[j] = M[j] ^ M_tmp[j];
        }

        // iv
        BN_bin2bn(S, 16, y);

        // v
        str2num_rev(anum, A, ctx->fpe_ctx->radix, m, bn_ctx);
        if (i & 1) BN_mod_add(c, anum, y, qpow_v, bn_ctx);
        else BN_mod_add(c, anum, y, qpow_u, bn_ctx);

        assert(A != B);
        A = (unsigned int *) ((uintptr_t) A ^ (uintptr_t) B);
        B = (unsigned int *) ((uintptr_t) B ^ (uintptr_t) A);
        A = (unsigned int *) ((uintptr_t) A ^ (uintptr_t) B);

        num2str_rev(c, B, ctx->fpe_ctx->radix, m, bn_ctx);
    }
    inverse_map_chars(out, output, inlen);
    memcpy(ctx->tag, M, 16);

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

int WBCRYPTO_ff3_gmac_decrypt(WBCRYPTO_fpe_mac_context *ctx, const char *input, char *output) {
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
    pow_uv(qpow_u, qpow_v, ctx->fpe_ctx->radix, u, v, bn_ctx);
    unsigned int temp = (unsigned int) ceil(u * log2(ctx->fpe_ctx->radix));
    const int b = ceil2(temp, 3);

    //gmac
    uint64_t HH[16] = {0}, HL[16] = {0};
    gmac_gen_H(ctx, HH, HL);
    unsigned char T[16]={0}, M[16]={0};
    memcpy(T, ctx->fpe_ctx->tweak, 16);
    gmac_mult_H(HH, HL, T, M);

    unsigned char S[16], P[16];
    unsigned char *Bytes = (unsigned char *) OPENSSL_malloc(b);
    for (int i = FF3_ROUNDS - 1; i >= 0; --i) {
        // i
        int m;
        if (i & 1) {
            m = v;
            memcpy(P, ctx->fpe_ctx->tweak, 4);
        } else {
            m = u;
            memcpy(P, ctx->fpe_ctx->tweak + 4, 4);
        }
        P[3] ^= i & 0xff;

        // ii
        str2num_rev(anum, A, ctx->fpe_ctx->radix, inlen - m, bn_ctx);
        memset(Bytes, 0x00, b);
        int BytesLen = BN_bn2bin(anum, Bytes);
        BytesLen = BytesLen > 12 ? 12 : BytesLen;
        memset(P + 4, 0x00, 12);
        memcpy(P + 16 - BytesLen, Bytes, BytesLen);

        // iii
        rev_bytes(P, 16);
        memset(S, 0x00, sizeof(S));
        // AES_encrypt(P, S, &aes_enc_ctx);
        (*ctx->fpe_ctx->block)(P, S, ctx->fpe_ctx->cipher_ctx);
        rev_bytes(S, 16);

        //gmac
        unsigned char M_tmp[16];
        gmac_mult_H(HH, HL, S, M_tmp);
        for (int j = 0; j < 16; j++) {
            M[j] = M[j] ^ M_tmp[j];
        }

        // iv
        BN_bin2bn(S, 16, y);

        // v
        str2num_rev(bnum, B, ctx->fpe_ctx->radix, m, bn_ctx);
        if (i & 1) BN_mod_sub(c, bnum, y, qpow_v, bn_ctx);
        else BN_mod_sub(c, bnum, y, qpow_u, bn_ctx);

        assert(A != B);
        A = (unsigned int *) ((uintptr_t) A ^ (uintptr_t) B);
        B = (unsigned int *) ((uintptr_t) B ^ (uintptr_t) A);
        A = (unsigned int *) ((uintptr_t) A ^ (uintptr_t) B);

        num2str_rev(c, A, ctx->fpe_ctx->radix, m, bn_ctx);
    }
    inverse_map_chars(out, output, inlen);
    memcpy(ctx->tag, M, 16);

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

int WBCRYPTO_ff3_gmac_finish(WBCRYPTO_fpe_mac_context *ctx, char *tag, size_t *len) {
    *len = 16;
    memcpy(tag, ctx->tag, *len);
    return 1;
}