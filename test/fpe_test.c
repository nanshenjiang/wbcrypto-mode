#include "test_local.h"
#include <wbcrypto/aes.h>
#include <wbcrypto/sm4.h>
#include <wbcrypto/wbaes.h>
#include <wbcrypto/wbsm4.h>
#include <wbcrypto/fpe.h>
#include <time.h>

int test_aes_fpe() {
    const uint8_t key[] = {
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
            0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
    };
    const char tweak[] = "12345";
    const char input[] = "13888888888";
    char cipher[20] = {0};
    char plain[20] = {0};

    WBCRYPTO_aes_context *aes_ctx = WBCRYPTO_aes_context_init();
    WBCRYPTO_aes_init_key(aes_ctx, key, sizeof(key));
    WBCRYPTO_fpe_context *fpe_ctx = WBCRYPTO_aes_fpe_init(aes_ctx, tweak, sizeof(tweak), 10);
    WBCRYPTO_ff1_encrypt(fpe_ctx, input, cipher);
    printf("[FF1] [aes] encrypt answer: %s\n", cipher);
    WBCRYPTO_ff1_decrypt(fpe_ctx, cipher, plain);
    printf("[FF1] [aes] decrypt answer: %s\n", plain);

    WBCRYPTO_ff3_encrypt(fpe_ctx, input, cipher);
    printf("[FF3] [aes] encrypt answer: %s\n", cipher);
    WBCRYPTO_ff3_decrypt(fpe_ctx, cipher, plain);
    printf("[FF3] [aes] decrypt answer: %s\n", plain);
}

int test_sm4_fpe() {
    const uint8_t key[] = {
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
            0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
    };
    const char tweak[] = "12345";
    const char input[] = "13888888888";
    char cipher[20] = {0};
    char plain[20] = {0};

    WBCRYPTO_sm4_context *sm4_ctx = WBCRYPTO_sm4_context_init();
    WBCRYPTO_sm4_init_key(sm4_ctx, key, sizeof(key));
    WBCRYPTO_fpe_context *fpe_ctx = WBCRYPTO_sm4_fpe_init(sm4_ctx, tweak, sizeof(tweak), 12);
    WBCRYPTO_ff1_encrypt(fpe_ctx, input, cipher);
    printf("[FF1] [sm4] encrypt answer: %s\n", cipher);
    WBCRYPTO_ff1_decrypt(fpe_ctx, cipher, plain);
    printf("[FF1] [sm4] decrypt answer: %s\n", plain);

    WBCRYPTO_ff3_encrypt(fpe_ctx, input, cipher);
    printf("[FF3] [sm4] encrypt answer: %s\n", cipher);
    WBCRYPTO_ff3_decrypt(fpe_ctx, cipher, plain);
    printf("[FF3] [sm4] decrypt answer: %s\n", plain);
}

int test_wbaes_fpe() {
    const uint8_t key[] = {
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
            0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
    };
    const char tweak[] = "12345";
    const char input[] = "13888888888";
    char cipher[20] = {0};
    char plain[20] = {0};

    WBCRYPTO_wbaes_context *wbaes_ctx = WBCRYPTO_wbaes_context_init(1, 1);
    WBCRYPTO_wbaes_gen_table(wbaes_ctx, key, sizeof(key));
    WBCRYPTO_fpe_context *fpe_ctx = WBCRYPTO_wbaes_fpe_init(wbaes_ctx, tweak, sizeof(tweak), 10);
    WBCRYPTO_ff1_encrypt(fpe_ctx, input, cipher);
    WBCRYPTO_ff1_decrypt(fpe_ctx, cipher, plain);
    WBCRYPTO_ff1_encrypt(fpe_ctx, input, cipher);
    printf("[FF1] [wbsm4] encrypt answer: %s\n", cipher);

    WBCRYPTO_ff1_decrypt(fpe_ctx, cipher, plain);
    printf("[FF1] [wbsm4] decrypt answer: %s\n", plain);

    WBCRYPTO_ff3_encrypt(fpe_ctx, input, cipher);
    printf("[FF3] [wbsm4] encrypt answer: %s\n", cipher);
    WBCRYPTO_ff3_decrypt(fpe_ctx, cipher, plain);
    printf("[FF3] [wbsm4] decrypt answer: %s\n", plain);
}

int test_wbsm4_fpe() {
    const uint8_t key[] = {
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
            0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
    };
    const char tweak[] = "12345";
    const char input[] = "13888888888";
    char cipher[20] = {0};
    char plain[20] = {0};

    WBCRYPTO_wbsm4_context *wbsm4_ctx = WBCRYPTO_wbsm4_context_init(1, 1);
    WBCRYPTO_wbsm4_gen_table(wbsm4_ctx, key, sizeof(key));
    WBCRYPTO_fpe_context *fpe_ctx = WBCRYPTO_wbsm4_fpe_init(wbsm4_ctx, tweak, sizeof(tweak), 10);
    WBCRYPTO_ff1_encrypt(fpe_ctx, input, cipher);
    WBCRYPTO_ff1_decrypt(fpe_ctx, cipher, plain);
    WBCRYPTO_ff1_encrypt(fpe_ctx, input, cipher);
    printf("[FF1] [wbsm4] encrypt answer: %s\n", cipher);

    WBCRYPTO_ff1_decrypt(fpe_ctx, cipher, plain);
    printf("[FF1] [wbsm4] decrypt answer: %s\n", plain);

    WBCRYPTO_ff3_encrypt(fpe_ctx, input, cipher);
    printf("[FF3] [wbsm4] encrypt answer: %s\n", cipher);
    WBCRYPTO_ff3_decrypt(fpe_ctx, cipher, plain);
    printf("[FF3] [wbsm4] decrypt answer: %s\n", plain);
}

int main() {
    test_aes_fpe();
    test_sm4_fpe();
    test_wbaes_fpe();
    test_wbsm4_fpe();
}
