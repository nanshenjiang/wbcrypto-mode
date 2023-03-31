#ifndef HEADER_FPE_LOCL_H
# define HEADER_FPE_LOCL_H

#include <openssl/bn.h>
#include <stdint.h>
#include <string.h>
#include <math.h>
#include <assert.h>
#include <openssl/bn.h>

# define FF1_ROUNDS 10
# define FF3_ROUNDS 8
# define FF3_TWEAK_SIZE 8

// ceil and floor for x / (2 ^ bit)
# define ceil2(x, bit) ( ((x) >> (bit)) + ( ((x) & ((1 << (bit)) - 1)) > 0 ) )
# define floor2(x, bit) ( (x) >> (bit) )

void pow_uv(BIGNUM *pow_u, BIGNUM *pow_v, unsigned int x, int u, int v, BN_CTX *ctx);

void map_chars(const unsigned char str[], unsigned int result[]);

void inverse_map_chars(unsigned result[], unsigned char str[], int len);

// convert numeral string to number
void str2num(BIGNUM *Y, const unsigned int *X, unsigned long long radix, unsigned int len, BN_CTX *ctx);

// convert number to numeral string
void num2str(const BIGNUM *X, unsigned int *Y, unsigned int radix, int len, BN_CTX *ctx);

void rev_bytes(unsigned char X[], int len);

// convert numeral string in reverse order to number
void str2num_rev(BIGNUM *Y, const unsigned int *X, unsigned int radix, unsigned int len, BN_CTX *bn_ctx);

// convert number to numeral string in reverse order
void num2str_rev(const BIGNUM *X, unsigned int *Y, unsigned int radix, int len, BN_CTX *bn_ctx);

//int log2(int x);

#endif
