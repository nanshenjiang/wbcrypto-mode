#include "test_local.h"
#include <wbcrypto/aes.h>
#include <wbcrypto/sm4.h>
#include <wbcrypto/wbaes.h>
#include <wbcrypto/wbsm4.h>
#include <wbcrypto/fpe.h>
#include <time.h>

const uint8_t key[] = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
};

int test_aes_fpe() {
    long long i;
    const char tweak[] = "";
    const char input[] = "1234567890123456";
    char cipher[50] = {0};
    clock_t program_start, program_end;
    double ts;

    WBCRYPTO_aes_context *aes_ctx = WBCRYPTO_aes_context_init();
    WBCRYPTO_aes_init_key(aes_ctx, key, sizeof(key));
    WBCRYPTO_fpe_context *fpe_ctx = WBCRYPTO_aes_fpe_init(aes_ctx, tweak, sizeof(tweak), 10);
    program_start = clock();
    for (i = 0; i < (long long)TEST_CYCLE_NUM * 64; i++) {
        WBCRYPTO_ff1_encrypt(fpe_ctx, input, cipher);
    }
    program_end = clock();
    ts = program_end - program_start;
    ts = ts / CLOCKS_PER_SEC;
    printf("[FF1] [aes] Time cost: %lf s, it means that the encryption speed is: %f MByte/s\n", ts / TEST_CYCLE_NUM,
           1 / (ts / TEST_CYCLE_NUM));

    program_start = clock();
    for (i = 0; i < (long long)TEST_CYCLE_NUM * 64; i++) {
        WBCRYPTO_ff1_decrypt(fpe_ctx, input, cipher);
    }
    program_end = clock();
    ts = program_end - program_start;
    ts = ts / CLOCKS_PER_SEC;
    printf("[FF1] [aes] Time cost: %lf s, it means that the decryption speed is: %f MByte/s\n", ts / TEST_CYCLE_NUM,
           1 / (ts / TEST_CYCLE_NUM));

    program_start = clock();
    for (i = 0; i < (long long)TEST_CYCLE_NUM * 64; i++) {
        WBCRYPTO_ff3_encrypt(fpe_ctx, input, cipher);
    }
    program_end = clock();
    ts = program_end - program_start;
    ts = ts / CLOCKS_PER_SEC;
    printf("[FF3] [aes] Time cost: %lf s, it means that the encryption speed is: %f MByte/s\n", ts / TEST_CYCLE_NUM,
           1 / (ts / TEST_CYCLE_NUM));
    program_start = clock();
    for (i = 0; i < (long long)TEST_CYCLE_NUM * 64; i++) {
        WBCRYPTO_ff3_decrypt(fpe_ctx, input, cipher);
    }
    program_end = clock();
    ts = program_end - program_start;
    ts = ts / CLOCKS_PER_SEC;
    printf("[FF3] [aes] Time cost: %lf s, it means that the decryption speed is: %f MByte/s\n", ts / TEST_CYCLE_NUM,
           1 / (ts / TEST_CYCLE_NUM));
    return 1;
}

int test_wbaes_fpe() {
    long long i;
    const char tweak[] = "1234567890123456";
    const char input[] = "1234567890123456";
    char cipher[50] = {0};
    clock_t program_start, program_end;
    double ts;

    WBCRYPTO_wbaes_context *wbaes_ctx = WBCRYPTO_wbaes_context_init(1, 1);
    WBCRYPTO_wbaes_gen_table(wbaes_ctx, key, sizeof(key));
    WBCRYPTO_fpe_context *fpe_ctx = WBCRYPTO_wbaes_fpe_init(wbaes_ctx, tweak, sizeof(tweak), 10);
    program_start = clock();
    for (i = 0; i < (long long)TEST_CYCLE_NUM * 64; i++) {
        WBCRYPTO_ff1_encrypt(fpe_ctx, input, cipher);
    }
    program_end = clock();
    ts = program_end - program_start;
    ts = ts / CLOCKS_PER_SEC;
    printf("[FF1] [wbaes] Time cost: %lf s, it means that the encryption speed is: %f MByte/s\n", ts / TEST_CYCLE_NUM,
           1 / (ts / TEST_CYCLE_NUM));

    program_start = clock();
    for (i = 0; i < (long long)TEST_CYCLE_NUM * 64; i++) {
        WBCRYPTO_ff1_decrypt(fpe_ctx, input, cipher);
    }
    program_end = clock();
    ts = program_end - program_start;
    ts = ts / CLOCKS_PER_SEC;
    printf("[FF1] [wbaes] Time cost: %lf s, it means that the decryption speed is: %f MByte/s\n", ts / TEST_CYCLE_NUM,
           1 / (ts / TEST_CYCLE_NUM));

    program_start = clock();
    for (i = 0; i < (long long)TEST_CYCLE_NUM * 64; i++) {
        WBCRYPTO_ff3_encrypt(fpe_ctx, input, cipher);
    }
    program_end = clock();
    ts = program_end - program_start;
    ts = ts / CLOCKS_PER_SEC;
    printf("[FF3] [wbaes] Time cost: %lf s, it means that the encryption speed is: %f MByte/s\n", ts / TEST_CYCLE_NUM,
           1 / (ts / TEST_CYCLE_NUM));
    program_start = clock();
    for (i = 0; i < (long long)TEST_CYCLE_NUM * 64; i++) {
        WBCRYPTO_ff3_decrypt(fpe_ctx, input, cipher);
    }
    program_end = clock();
    ts = program_end - program_start;
    ts = ts / CLOCKS_PER_SEC;
    printf("[FF3] [wbaes] Time cost: %lf s, it means that the decryption speed is: %f MByte/s\n", ts / TEST_CYCLE_NUM,
           1 / (ts / TEST_CYCLE_NUM));
    return 1;
}

int test_sm4_fpe() {
    long long i;
    const char tweak[] = "1234567890123456";
    const char input[] = "1234567890123456";
    char cipher[50] = {0};
    clock_t program_start, program_end;
    double ts;

    WBCRYPTO_sm4_context *sm4_ctx = WBCRYPTO_sm4_context_init();
    WBCRYPTO_sm4_init_key(sm4_ctx, key, sizeof(key));
    WBCRYPTO_fpe_context *fpe_ctx = WBCRYPTO_sm4_fpe_init(sm4_ctx, tweak, sizeof(tweak), 10);
    program_start = clock();
    for (i = 0; i < (long long)TEST_CYCLE_NUM * 64 * 1024; i++) {
        WBCRYPTO_ff1_encrypt(fpe_ctx, input, cipher);
    }
    program_end = clock();
    ts = program_end - program_start;
    ts = ts / CLOCKS_PER_SEC;
    printf("[FF1] [sm4] Time cost: %lf s, it means that the encryption speed is: %f MByte/s\n", ts / TEST_CYCLE_NUM,
           1 / (ts / TEST_CYCLE_NUM));

    program_start = clock();
    for (i = 0; i < (long long)TEST_CYCLE_NUM * 64 * 1024; i++) {
        WBCRYPTO_ff1_decrypt(fpe_ctx, input, cipher);
    }
    program_end = clock();
    ts = program_end - program_start;
    ts = ts / CLOCKS_PER_SEC;
    printf("[FF1] [sm4] Time cost: %lf s, it means that the decryption speed is: %f MByte/s\n", ts / TEST_CYCLE_NUM,
           1 / (ts / TEST_CYCLE_NUM));

    program_start = clock();
    for (i = 0; i < (long long)TEST_CYCLE_NUM * 64 * 1024; i++) {
        WBCRYPTO_ff3_encrypt(fpe_ctx, input, cipher);
    }
    program_end = clock();
    ts = program_end - program_start;
    ts = ts / CLOCKS_PER_SEC;
    printf("[FF3] [sm4] Time cost: %lf s, it means that the encryption speed is: %f MByte/s\n", ts / TEST_CYCLE_NUM,
           1 / (ts / TEST_CYCLE_NUM));
    program_start = clock();
    for (i = 0; i < (long long)TEST_CYCLE_NUM * 64 * 1024; i++) {
        WBCRYPTO_ff3_decrypt(fpe_ctx, input, cipher);
    }
    program_end = clock();
    ts = program_end - program_start;
    ts = ts / CLOCKS_PER_SEC;
    printf("[FF3] [sm4] Time cost: %lf s, it means that the decryption speed is: %f MByte/s\n", ts / TEST_CYCLE_NUM,
           1 / (ts / TEST_CYCLE_NUM));
    return 1;
}

int test_wbsm4_fpe() {
    long long i;
    const char tweak[] = "1234567890123456";
    const char input[] = "1234567890123456";
    char cipher[50] = {0};
    clock_t program_start, program_end;
    double ts;

    WBCRYPTO_wbsm4_context *wbsm4_ctx = WBCRYPTO_wbsm4_context_init(1, 1);
    WBCRYPTO_wbsm4_gen_table(wbsm4_ctx, key, sizeof(key));
    WBCRYPTO_fpe_context *fpe_ctx = WBCRYPTO_wbsm4_fpe_init(wbsm4_ctx, tweak, sizeof(tweak), 10);
    program_start = clock();
    for (i = 0; i < (long long)TEST_CYCLE_NUM * 64 * 1024; i++) {
        WBCRYPTO_ff1_encrypt(fpe_ctx, input, cipher);
    }
    program_end = clock();
    ts = program_end - program_start;
    ts = ts / CLOCKS_PER_SEC;
    printf("[FF1] [wbsm4] Time cost: %lf s, it means that the encryption speed is: %f MByte/s\n", ts / TEST_CYCLE_NUM,
           1 / (ts / TEST_CYCLE_NUM));

    program_start = clock();
    for (i = 0; i < (long long)TEST_CYCLE_NUM * 64 * 1024; i++) {
        WBCRYPTO_ff1_decrypt(fpe_ctx, input, cipher);
    }
    program_end = clock();
    ts = program_end - program_start;
    ts = ts / CLOCKS_PER_SEC;
    printf("[FF1] [wbsm4] Time cost: %lf s, it means that the decryption speed is: %f MByte/s\n", ts / TEST_CYCLE_NUM,
           1 / (ts / TEST_CYCLE_NUM));

    program_start = clock();
    for (i = 0; i < (long long)TEST_CYCLE_NUM * 64 * 1024; i++) {
        WBCRYPTO_ff3_encrypt(fpe_ctx, input, cipher);
    }
    program_end = clock();
    ts = program_end - program_start;
    ts = ts / CLOCKS_PER_SEC;
    printf("[FF3] [wbsm4] Time cost: %lf s, it means that the encryption speed is: %f MByte/s\n", ts / TEST_CYCLE_NUM,
           1 / (ts / TEST_CYCLE_NUM));
    program_start = clock();
    for (i = 0; i < (long long)TEST_CYCLE_NUM * 64 * 1024; i++) {
        WBCRYPTO_ff3_decrypt(fpe_ctx, input, cipher);
    }
    program_end = clock();
    ts = program_end - program_start;
    ts = ts / CLOCKS_PER_SEC;
    printf("[FF3] [wbsm4] Time cost: %lf s, it means that the decryption speed is: %f MByte/s\n", ts / TEST_CYCLE_NUM,
           1 / (ts / TEST_CYCLE_NUM));
    return 1;
}

int main() {
    test_aes_fpe();
    test_wbaes_fpe();
//    test_sm4_fpe();
//    test_wbsm4_fpe();
}
