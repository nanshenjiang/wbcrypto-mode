#include <wbcrypto/fpe.h>
#include "fpe_locl.h"

void left_shift_buffer(uint8_t *input, uint8_t *output, uint8_t length) {
    uint8_t overflow = 0;
    uint8_t i;

    for (i = length; i > 0; i--) {
        output[i - 1] = input[i - 1] << 1;
        output[i - 1] |= overflow;
        overflow = (input[i - 1] & 0x80) ? 1 : 0;
    }
}

void generate_cmac_sub_keys(WBCRYPTO_fpe_mac_context *ctx, uint8_t *K1, uint8_t *K2) {
    char msg[16] = {0x00};
    (*ctx->fpe_ctx->block)(msg, K2, ctx->fpe_ctx->cipher_ctx);

    left_shift_buffer(K2, K1, 16);
    if (K2[0] & 0x80) {
        K1[15] = K1[15] ^ 0x87;
    }

    left_shift_buffer(K1, K2, 16);
    if (K1[0] & 0x80) {
        K2[15] = K2[15] ^ 0x87;
    }
}

int WBCRYPTO_ff1_cmac_encrypt(WBCRYPTO_fpe_mac_context *ctx, const char *input, char *output) {
    int ret = 0;
    BIGNUM *bnum = BN_new(),
            *y = BN_new(),
            *c = BN_new(),
            *anum = BN_new(),
            *qpow_u = BN_new(),
            *qpow_v = BN_new();
    BN_CTX *bn_ctx = BN_CTX_new();

    union {
        long one;
        char little;
    } is_endian = {1};

    unsigned int inlen = strlen(input);
    unsigned int in[inlen], out[inlen];
    map_chars(input, in);

    memcpy(out, in, inlen << 2);
    int u = floor2(inlen, 1);
    int v = inlen - u;
    unsigned int *A = out, *B = out + u;
    pow_uv(qpow_u, qpow_v, ctx->fpe_ctx->radix, u, v, bn_ctx);

    unsigned int temp = (unsigned int) ceil(v * log2(ctx->fpe_ctx->radix));
    const int b = ceil2(temp, 3);
    const int d = 4 * ceil2(b, 2) + 4;

    int pad = ((-ctx->fpe_ctx->tweaklen - b - 1) % 16 + 16) % 16;
    int Qlen = ctx->fpe_ctx->tweaklen + pad + 1 + b;
    unsigned char P[16];
    unsigned char *Q = (unsigned char *) malloc(Qlen), *Bytes = (unsigned char *) malloc(b);

    // initialize P
    P[0] = 0x1;
    P[1] = 0x2;
    P[2] = 0x1;
    P[7] = u % 256;
    if (is_endian.little) {
        temp = (ctx->fpe_ctx->radix << 8) | 10;
        P[3] = (temp >> 24) & 0xff;
        P[4] = (temp >> 16) & 0xff;
        P[5] = (temp >> 8) & 0xff;
        P[6] = temp & 0xff;
        P[8] = (inlen >> 24) & 0xff;
        P[9] = (inlen >> 16) & 0xff;
        P[10] = (inlen >> 8) & 0xff;
        P[11] = inlen & 0xff;
        P[12] = (ctx->fpe_ctx->tweaklen >> 24) & 0xff;
        P[13] = (ctx->fpe_ctx->tweaklen >> 16) & 0xff;
        P[14] = (ctx->fpe_ctx->tweaklen >> 8) & 0xff;
        P[15] = ctx->fpe_ctx->tweaklen & 0xff;
    } else {
        *((unsigned int *) (P + 3)) = (ctx->fpe_ctx->radix << 8) | 10;
        *((unsigned int *) (P + 8)) = inlen;
        *((unsigned int *) (P + 12)) = ctx->fpe_ctx->tweaklen;
    }

    // initialize Q
    memcpy(Q, ctx->fpe_ctx->tweak, ctx->fpe_ctx->tweaklen);
    memset(Q + ctx->fpe_ctx->tweaklen, 0x00, pad);
    assert(ctx->fpe_ctx->tweaklen + pad - 1 <= Qlen);

    //cmac key1 and key2
    uint8_t K1[16] = {0}, K2[16] = {0};
    generate_cmac_sub_keys(ctx, K1, K2);
    uint8_t mac[16] = {0};

    unsigned char R[16];
    int cnt = ceil2(d, 4) - 1;
    int Slen = 16 + cnt * 16;
    unsigned char *S = (unsigned char *) malloc(Slen);
    for (int i = 0; i < FF1_ROUNDS; ++i) {
        // v
        int m = (i & 1) ? v : u;

        // i
        Q[ctx->fpe_ctx->tweaklen + pad] = i & 0xff;
        str2num(bnum, B, ctx->fpe_ctx->radix, inlen - m, bn_ctx);
        int BytesLen = BN_bn2bin(bnum, Bytes);
        memset(Q + Qlen - b, 0x00, b);

        int qtmp = Qlen - BytesLen;
        memcpy(Q + qtmp, Bytes, BytesLen);

        // ii PRF(P || Q), P is always 16 bytes long
        // AES_encrypt(P, R, &aes_enc_ctx);
        (*ctx->fpe_ctx->block)(P, R, ctx->fpe_ctx->cipher_ctx);
        int count = Qlen / 16;
        unsigned char Ri[16];
        unsigned char *Qi = Q;
        uint8_t cn_1[16];
        for (int cc = 0; cc < count; ++cc) {
            for (int j = 0; j < 16; ++j) Ri[j] = Qi[j] ^ R[j];
            // AES_encrypt(Ri, R, &aes_enc_ctx);
            (*ctx->fpe_ctx->block)(Ri, R, ctx->fpe_ctx->cipher_ctx);
            Qi += 16;
            if (cc == count - 2) {
                memcpy(cn_1, R, 16);
            }
        }
        //cbc-mac
        uint8_t M_last[16];
        for (int j = 0; j < 16; j++) {
            M_last[j] = K1[j] ^ R[i] ^ cn_1[i];
        }
        uint8_t M_mac[16];
        (*ctx->fpe_ctx->block)(M_last, M_mac, ctx->fpe_ctx->cipher_ctx);
        for (int j = 0; j < 16; j++) {
            mac[j] = mac[j] ^ M_mac[j];
        }

        // iii
        unsigned char tmp[16], SS[16];
        memset(S, 0x00, Slen);
        assert(Slen >= 16);
        memcpy(S, R, 16);
        for (int j = 1; j <= cnt; ++j) {
            memset(tmp, 0x00, 16);

            if (is_endian.little) {
                // convert to big endian
                // full unroll
                tmp[15] = j & 0xff;
                tmp[14] = (j >> 8) & 0xff;
                tmp[13] = (j >> 16) & 0xff;
                tmp[12] = (j >> 24) & 0xff;
            } else *((unsigned int *) tmp + 3) = j;

            for (int k = 0; k < 16; ++k) tmp[k] ^= R[k];
            // AES_encrypt(tmp, SS, &aes_enc_ctx);
            (*ctx->fpe_ctx->block)(tmp, SS, ctx->fpe_ctx->cipher_ctx);
            assert((S + 16 * j)[0] == 0x00);
            assert(16 + 16 * j <= Slen);
            memcpy(S + 16 * j, SS, 16);
        }

        // iv
        BN_bin2bn(S, d, y);
        // vi
        // (num(A, radix, m) + y) % qpow(radix, m);
        str2num(anum, A, ctx->fpe_ctx->radix, m, bn_ctx);
        // anum = (anum + y) mod qpow_uv
        if (m == u) BN_mod_add(c, anum, y, qpow_u, bn_ctx);
        else BN_mod_add(c, anum, y, qpow_v, bn_ctx);

        // swap A and B
        assert(A != B);
        A = (unsigned int *) ((uintptr_t) A ^ (uintptr_t) B);
        B = (unsigned int *) ((uintptr_t) B ^ (uintptr_t) A);
        A = (unsigned int *) ((uintptr_t) A ^ (uintptr_t) B);
        num2str(c, B, ctx->fpe_ctx->radix, m, bn_ctx);
    }
    inverse_map_chars(out, output, inlen);
    memcpy(ctx->tag, mac, 16);

    ret = 1;
cleanup:
    BN_clear_free(anum);
    BN_clear_free(bnum);
    BN_clear_free(c);
    BN_clear_free(y);
    BN_clear_free(qpow_u);
    BN_clear_free(qpow_v);
    BN_CTX_free(bn_ctx);
    free(Bytes);
    free(Q);
    free(S);
    return ret;
}

int WBCRYPTO_ff1_cmac_decrypt(WBCRYPTO_fpe_mac_context *ctx, const char *input, char *output) {
    int ret = 0;
    BIGNUM *bnum = BN_new(),
            *y = BN_new(),
            *c = BN_new(),
            *anum = BN_new(),
            *qpow_u = BN_new(),
            *qpow_v = BN_new();
    BN_CTX *bn_ctx = BN_CTX_new();

    union {
        long one;
        char little;
    } is_endian = {1};

    unsigned int inlen = strlen(input);
    unsigned int in[inlen], out[inlen];
    map_chars(input, in);

    memcpy(out, in, inlen << 2);
    int u = floor2(inlen, 1);
    int v = inlen - u;
    unsigned int *A = out, *B = out + u;
    pow_uv(qpow_u, qpow_v, ctx->fpe_ctx->radix, u, v, bn_ctx);

    unsigned int temp = (unsigned int) ceil(v * log2(ctx->fpe_ctx->radix));
    const int b = ceil2(temp, 3);
    const int d = 4 * ceil2(b, 2) + 4;

    int pad = ((-ctx->fpe_ctx->tweaklen - b - 1) % 16 + 16) % 16;
    int Qlen = ctx->fpe_ctx->tweaklen + pad + 1 + b;
    unsigned char P[16];
    unsigned char *Q = (unsigned char *) malloc(Qlen), *Bytes = (unsigned char *) malloc(b);
    // initialize P
    P[0] = 0x1;
    P[1] = 0x2;
    P[2] = 0x1;
    P[7] = u % 256;
    if (is_endian.little) {
        temp = (ctx->fpe_ctx->radix << 8) | 10;
        P[3] = (temp >> 24) & 0xff;
        P[4] = (temp >> 16) & 0xff;
        P[5] = (temp >> 8) & 0xff;
        P[6] = temp & 0xff;
        P[8] = (inlen >> 24) & 0xff;
        P[9] = (inlen >> 16) & 0xff;
        P[10] = (inlen >> 8) & 0xff;
        P[11] = inlen & 0xff;
        P[12] = (ctx->fpe_ctx->tweaklen >> 24) & 0xff;
        P[13] = (ctx->fpe_ctx->tweaklen >> 16) & 0xff;
        P[14] = (ctx->fpe_ctx->tweaklen >> 8) & 0xff;
        P[15] = ctx->fpe_ctx->tweaklen & 0xff;
    } else {
        *((unsigned int *) (P + 3)) = (ctx->fpe_ctx->radix << 8) | 10;
        *((unsigned int *) (P + 8)) = inlen;
        *((unsigned int *) (P + 12)) = ctx->fpe_ctx->tweaklen;
    }

    // initialize Q
    memcpy(Q, ctx->fpe_ctx->tweak, ctx->fpe_ctx->tweaklen);
    memset(Q + ctx->fpe_ctx->tweaklen, 0x00, pad);
    assert(ctx->fpe_ctx->tweaklen + pad - 1 <= Qlen);

    //cmac key1 and key2
    uint8_t K1[16] = {0}, K2[16] = {0};
    generate_cmac_sub_keys(ctx, K1, K2);
    uint8_t mac[16] = {0};

    unsigned char R[16];
    int cnt = ceil2(d, 4) - 1;
    int Slen = 16 + cnt * 16;
    unsigned char *S = (unsigned char *) malloc(Slen);
    for (int i = FF1_ROUNDS - 1; i >= 0; --i) {
        // v
        int m = (i & 1) ? v : u;

        // i
        Q[ctx->fpe_ctx->tweaklen + pad] = i & 0xff;
        str2num(anum, A, ctx->fpe_ctx->radix, inlen - m, bn_ctx);
        memset(Q + Qlen - b, 0x00, b);
        int BytesLen = BN_bn2bin(anum, Bytes);
        int qtmp = Qlen - BytesLen;
        memcpy(Q + qtmp, Bytes, BytesLen);

        // ii PRF(P || Q)
        memset(R, 0x00, sizeof(R));
        // AES_encrypt(P, R, &aes_enc_ctx);
        (*ctx->fpe_ctx->block)(P, R, ctx->fpe_ctx->cipher_ctx);
        int count = Qlen / 16;
        unsigned char Ri[16];
        unsigned char *Qi = Q;
        uint8_t cn_1[16];
        for (int cc = 0; cc < count; ++cc) {
            for (int j = 0; j < 16; ++j) Ri[j] = Qi[j] ^ R[j];
            // AES_encrypt(Ri, R, &aes_enc_ctx);
            (*ctx->fpe_ctx->block)(Ri, R, ctx->fpe_ctx->cipher_ctx);
            Qi += 16;
            if (cc == count - 2) {
                memcpy(cn_1, R, 16);
            }
        }
        //cbc-mac
        uint8_t M_last[16];
        for (int j = 0; j < 16; j++) {
            M_last[j] = K1[j] ^ R[i] ^ cn_1[i];
        }
        uint8_t M_mac[16];
        (*ctx->fpe_ctx->block)(M_last, M_mac, ctx->fpe_ctx->cipher_ctx);
        for (int j = 0; j < 16; j++) {
            mac[j] = mac[j] ^ M_mac[j];
        }

        // iii
        unsigned char tmp[16], SS[16];
        memset(S, 0x00, Slen);
        memcpy(S, R, 16);
        for (int j = 1; j <= cnt; ++j) {
            memset(tmp, 0x00, 16);

            if (is_endian.little) {
                // convert to big endian
                // full unroll
                tmp[15] = j & 0xff;
                tmp[14] = (j >> 8) & 0xff;
                tmp[13] = (j >> 16) & 0xff;
                tmp[12] = (j >> 24) & 0xff;
            } else *((unsigned int *) tmp + 3) = j;

            for (int k = 0; k < 16; ++k) tmp[k] ^= R[k];
            // AES_encrypt(tmp, SS, &aes_enc_ctx);
            (*ctx->fpe_ctx->block)(tmp, SS, ctx->fpe_ctx->cipher_ctx);
            assert((S + 16 * j)[0] == 0x00);
            memcpy(S + 16 * j, SS, 16);
        }

        // iv
        BN_bin2bn(S, d, y);
        // vi
        // (num(B, radix, m) - y) % qpow(radix, m);
        str2num(bnum, B, ctx->fpe_ctx->radix, m, bn_ctx);
        if (m == u) BN_mod_sub(c, bnum, y, qpow_u, bn_ctx);
        else BN_mod_sub(c, bnum, y, qpow_v, bn_ctx);

        // swap A and B
        assert(A != B);
        A = (unsigned int *) ((uintptr_t) A ^ (uintptr_t) B);
        B = (unsigned int *) ((uintptr_t) B ^ (uintptr_t) A);
        A = (unsigned int *) ((uintptr_t) A ^ (uintptr_t) B);
        num2str(c, A, ctx->fpe_ctx->radix, m, bn_ctx);
    }
    inverse_map_chars(out, output, inlen);
    memcpy(ctx->tag, mac, 16);

    ret = 1;
cleanup:
    BN_clear_free(anum);
    BN_clear_free(bnum);
    BN_clear_free(y);
    BN_clear_free(c);
    BN_clear_free(qpow_u);
    BN_clear_free(qpow_v);
    BN_CTX_free(bn_ctx);
    free(Bytes);
    free(Q);
    free(S);
    return ret;
}

int WBCRYPTO_ff1_cmac_finish(WBCRYPTO_fpe_mac_context *ctx, char *tag, size_t *len) {
    *len = 16;
    memcpy(tag, ctx->tag, *len);
    return 1;
}
