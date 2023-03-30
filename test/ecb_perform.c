#include "test_local.h"
#include <wbcrypto/aes.h>
#include <wbcrypto/wbaes.h>
#include <wbcrypto/sm4.h>
#include <wbcrypto/wbsm4.h>

static const unsigned char key[16] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                                      0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};

static const unsigned char msg[16] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                                      0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};

void test_aes_standard_perf() {
    long long i;
    unsigned char cipher[16] = {0};
    clock_t program_start, program_end;
    double ts;

    WBCRYPTO_aes_context *aes_ctx = WBCRYPTO_aes_context_init();
    WBCRYPTO_aes_init_key(aes_ctx, key, sizeof(key));

    program_start = clock();
    for (i = 0; i < (long long)TEST_CYCLE_NUM * 64 * 1024; i++) {
        WBCRYPTO_aes_encrypt(msg, cipher, aes_ctx);
    }
    program_end = clock();
    ts = program_end - program_start;
    ts = ts / CLOCKS_PER_SEC;
    printf("The standard of AES encrypt 1MB spend:  %15.15f s, it means that the encryption speed is: %f MByte/s\n",
           ts / TEST_CYCLE_NUM, 1 / (ts / TEST_CYCLE_NUM));

    WBCRYPTO_aes_context_free(aes_ctx);
}

void test_wbaes_standard_perf() {
    long long i;
    unsigned char cipher[16] = {0};
    clock_t program_start, program_end;
    double ts;

    WBCRYPTO_wbaes_context *wbaes_ctx_enc;
    wbaes_ctx_enc = WBCRYPTO_wbaes_context_init(WBCRYPTO_ENCRYPT_MODE, 1);
    WBCRYPTO_wbaes_gen_table(wbaes_ctx_enc, key, sizeof(key));

    program_start = clock();
    for (i = 0; i < (long long)TEST_CYCLE_NUM * 64 * 1024; i++) {
        WBCRYPTO_wbaes_encrypt(msg, cipher, wbaes_ctx_enc);
    }
    program_end = clock();
    ts = program_end - program_start;
    ts = ts / CLOCKS_PER_SEC;
    printf("The standard of WBAES encrypt 1MB spend:  %15.15f s, it means that the encryption speed is: %f MByte/s\n",
           ts / TEST_CYCLE_NUM, 1 / (ts / TEST_CYCLE_NUM));

    WBCRYPTO_wbaes_context_free(wbaes_ctx_enc);
}

void test_sm4_standard_perf() {
    long long i;
    unsigned char cipher[16] = {0};
    clock_t program_start, program_end;
    double ts;

    WBCRYPTO_sm4_context *sm4_ctx = WBCRYPTO_sm4_context_init();
    WBCRYPTO_sm4_init_key(sm4_ctx, key, sizeof(key));

    program_start = clock();
    for (i = 0; i < (long long)TEST_CYCLE_NUM * 64 * 1024; i++) {
        WBCRYPTO_sm4_encrypt(msg, cipher, sm4_ctx);
    }
    program_end = clock();
    ts = program_end - program_start;
    ts = ts / CLOCKS_PER_SEC;
    printf("The standard of SM4 encrypt 1MB spend:  %15.15f s, it means that the encryption speed is: %f MByte/s\n",
           ts / TEST_CYCLE_NUM, 1 / (ts / TEST_CYCLE_NUM));

    WBCRYPTO_sm4_context_free(sm4_ctx);
}

void test_wbsm4_standard_perf() {
    long long i;
    unsigned char cipher[16] = {0};
    clock_t program_start, program_end;
    double ts;

    WBCRYPTO_wbsm4_context *wbsm4_ctx;
    wbsm4_ctx = WBCRYPTO_wbsm4_context_init(WBCRYPTO_ENCRYPT_MODE, 1);
    WBCRYPTO_wbsm4_gen_table(wbsm4_ctx, key, sizeof(key));

    program_start = clock();
    for (i = 0; i < (long long)TEST_CYCLE_NUM * 64 * 1024; i++) {
        WBCRYPTO_wbsm4_encrypt(msg, cipher, wbsm4_ctx);
    }
    program_end = clock();
    ts = program_end - program_start;
    ts = ts / CLOCKS_PER_SEC;
    printf("The standard of WBSM4 encrypt 1MB spend:  %15.15f s, it means that the encryption speed is: %f MByte/s\n",
           ts / TEST_CYCLE_NUM, 1 / (ts / TEST_CYCLE_NUM));

    WBCRYPTO_wbsm4_context_free(wbsm4_ctx);
}

int main() {
    test_aes_standard_perf();
    test_wbaes_standard_perf();
    test_sm4_standard_perf();
    test_wbsm4_standard_perf();
}
