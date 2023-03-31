#include "fpe_locl.h"

// quick power: result = x ^ e
void pow_uv(BIGNUM *pow_u, BIGNUM *pow_v, unsigned int x, int u, int v, BN_CTX *ctx) {
    BN_CTX_start(ctx);
    BIGNUM *base = BN_CTX_get(ctx),
            *e = BN_CTX_get(ctx);

    BN_set_word(base, x);
    if (u > v) {
        BN_set_word(e, v);
        BN_exp(pow_v, base, e, ctx);
        BN_mul(pow_u, pow_v, base, ctx);
    } else {
        BN_set_word(e, u);
        BN_exp(pow_u, base, e, ctx);
        if (u == v) BN_copy(pow_v, pow_u);
        else BN_mul(pow_v, pow_u, base, ctx);
    }

    BN_CTX_end(ctx);
    return;

    /*
    // old veresion, classical quick power
    mpz_t temp;
    mpz_init_set_ui(result, 1);
    mpz_init_set_ui(temp, x);
    while (e) {
        if (e & 1)    mpz_mul(result, result, temp);
        mpz_mul(temp, temp, temp);
        e >>= 1;
    }
    mpz_clear(temp);
    return;
    */
}

void map_chars(const unsigned char str[], unsigned int result[]) {
    int len = strlen(str);

    for (int i = 0; i < len; ++i)
        if (str[i] >= 'a')
            result[i] = str[i] - 'a' + 10;
        else
            result[i] = str[i] - '0';
    return;
}

void inverse_map_chars(unsigned result[], unsigned char str[], int len) {
    for (int i = 0; i < len; ++i)
        if (result[i] < 10)
            str[i] = result[i] + '0';
        else
            str[i] = result[i] - 10 + 'a';

    str[len] = 0x00;
    return;
}

// convert numeral string to number
void str2num(BIGNUM *Y, const unsigned int *X, unsigned long long radix, unsigned int len, BN_CTX *ctx) {
    BN_CTX_start(ctx);
    BIGNUM *r = BN_CTX_get(ctx),
            *x = BN_CTX_get(ctx);

    BN_set_word(Y, 0);
    BN_set_word(r, radix);
    for (int i = 0; i < len; ++i) {
        // Y = Y * radix + X[i]
        BN_set_word(x, X[i]);
        BN_mul(Y, Y, r, ctx);
        BN_add(Y, Y, x);
    }

    BN_CTX_end(ctx);
}

// convert number to numeral string
void num2str(const BIGNUM *X, unsigned int *Y, unsigned int radix, int len, BN_CTX *ctx) {
    BN_CTX_start(ctx);
    BIGNUM *dv = BN_CTX_get(ctx),
            *rem = BN_CTX_get(ctx),
            *r = BN_CTX_get(ctx),
            *XX = BN_CTX_get(ctx);

    BN_copy(XX, X);
    BN_set_word(r, radix);
    memset(Y, 0, len << 2);

    for (int i = len - 1; i >= 0; --i) {
        // XX / r = dv ... rem
        BN_div(dv, rem, XX, r, ctx);
        // Y[i] = XX % r
        Y[i] = BN_get_word(rem);
        // XX = XX / r
        BN_copy(XX, dv);
    }

    BN_CTX_end(ctx);
}

void rev_bytes(unsigned char X[], int len) {
    int hlen = len >> 1;
    for (int i = 0; i < hlen; ++i) {
        unsigned char tmp = X[i];
        X[i] = X[len - i - 1];
        X[len - i - 1] = tmp;
    }
    return;
}

// convert numeral string in reverse order to number
void str2num_rev(BIGNUM *Y, const unsigned int *X, unsigned int radix, unsigned int len, BN_CTX *bn_ctx) {
    BN_CTX_start(bn_ctx);
    BIGNUM *r = BN_CTX_get(bn_ctx),
            *x = BN_CTX_get(bn_ctx);

    BN_set_word(Y, 0);
    BN_set_word(r, radix);
    for (int i = len - 1; i >= 0; --i) {
        // Y = Y * radix + X[i]
        BN_set_word(x, X[i]);
        BN_mul(Y, Y, r, bn_ctx);
        BN_add(Y, Y, x);
    }

    BN_CTX_end(bn_ctx);
}

// convert number to numeral string in reverse order
void num2str_rev(const BIGNUM *X, unsigned int *Y, unsigned int radix, int len, BN_CTX *bn_ctx) {
    BN_CTX_start(bn_ctx);
    BIGNUM *dv = BN_CTX_get(bn_ctx),
            *rem = BN_CTX_get(bn_ctx),
            *r = BN_CTX_get(bn_ctx),
            *XX = BN_CTX_get(bn_ctx);

    BN_copy(XX, X);
    BN_set_word(r, radix);
    memset(Y, 0, len << 2);

    for (int i = 0; i < len; ++i) {
        // XX / r = dv ... rem
        BN_div(dv, rem, XX, r, bn_ctx);
        // Y[i] = XX % r
        Y[i] = BN_get_word(rem);
        // XX = XX / r
        BN_copy(XX, dv);
    }

    BN_CTX_end(bn_ctx);
}