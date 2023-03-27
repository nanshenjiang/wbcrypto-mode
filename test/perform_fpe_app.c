#include "test_local.h"
#include <wbcrypto/fpe_app.h>

static const unsigned char key[16] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                                      0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};

static const unsigned char msg[16] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                                      0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};

void test_aes_fpeapp_perf() {
    int i;
    const uint8_t key[] = {
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
            0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
    };
    const char input[] = "13888888888";
    const char sample[] = "123****1234";
    char cipher[200] = {0};
    clock_t program_start, program_end;
    double ts;

    WBCRYPTO_fpe_app_context app_ctx_ff1;
    WBCRYPTO_fpe_app_init(&app_ctx_ff1, key, sizeof(key), WBCYRPTO_FPE_CIPHER_AES, WBCYRPTO_FPE_FFX_FF1);
    program_start = clock();
    for (i = 0; i < TEST_CYCLE_NUM; i++) {
        WBCRYPTO_fpe_encrypt_phone_with_sample(&app_ctx_ff1, input, cipher, sample);
    }
    program_end = clock();
    ts = program_end - program_start;
    ts = ts / CLOCKS_PER_SEC;
    printf("[AES-FF1] Time cost: %lf s, it means that the encryption speed is: %f phone/s\n", ts / TEST_CYCLE_NUM,
           1 / (ts / TEST_CYCLE_NUM));

    WBCRYPTO_fpe_app_context app_ctx_ff3;
    WBCRYPTO_fpe_app_init(&app_ctx_ff3, key, sizeof(key), WBCYRPTO_FPE_CIPHER_AES, WBCYRPTO_FPE_FFX_FF3);
    program_start = clock();
    for (i = 0; i < TEST_CYCLE_NUM; i++) {
        WBCRYPTO_fpe_encrypt_phone_with_sample(&app_ctx_ff3, input, cipher, sample);
    }
    program_end = clock();
    ts = program_end - program_start;
    ts = ts / CLOCKS_PER_SEC;
    printf("[AES-FF3] Time cost: %lf s, it means that the encryption speed is: %f phone/s\n", ts / TEST_CYCLE_NUM,
           1 / (ts / TEST_CYCLE_NUM));
}

void test_wbaes_fpeapp_perf() {
    int i;
    const uint8_t key[] = {
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
            0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
    };
    const char input[] = "13888888888";
    const char sample[] = "123****1234";
    char cipher[200] = {0};
    clock_t program_start, program_end;
    double ts;

    WBCRYPTO_fpe_app_context app_ctx_ff1;
    WBCRYPTO_fpe_app_init(&app_ctx_ff1, key, sizeof(key), WBCYRPTO_FPE_CIPHER_WBAES, WBCYRPTO_FPE_FFX_FF1);
    program_start = clock();
    for (i = 0; i < TEST_CYCLE_NUM; i++) {
        WBCRYPTO_fpe_encrypt_phone_with_sample(&app_ctx_ff1, input, cipher, sample);
    }
    program_end = clock();
    ts = program_end - program_start;
    ts = ts / CLOCKS_PER_SEC;
    printf("[WBAES-FF1] Time cost: %lf s, it means that the encryption speed is: %f phone/s\n", ts / TEST_CYCLE_NUM,
           1 / (ts / TEST_CYCLE_NUM));

    WBCRYPTO_fpe_app_context app_ctx_ff3;
    WBCRYPTO_fpe_app_init(&app_ctx_ff3, key, sizeof(key), WBCYRPTO_FPE_CIPHER_WBAES, WBCYRPTO_FPE_FFX_FF3);
    program_start = clock();
    for (i = 0; i < TEST_CYCLE_NUM; i++) {
        WBCRYPTO_fpe_encrypt_phone_with_sample(&app_ctx_ff3, input, cipher, sample);
    }
    program_end = clock();
    ts = program_end - program_start;
    ts = ts / CLOCKS_PER_SEC;
    printf("[WBAES-FF3] Time cost: %lf s, it means that the encryption speed is: %f phone/s\n", ts / TEST_CYCLE_NUM,
           1 / (ts / TEST_CYCLE_NUM));
}

void test_sm4_fpeapp_perf() {
    int i;
    const uint8_t key[] = {
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
            0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
    };
    const char input[] = "13888888888";
    const char sample[] = "123****1234";
    char cipher[200] = {0};
    clock_t program_start, program_end;
    double ts;

    WBCRYPTO_fpe_app_context app_ctx_ff1;
    WBCRYPTO_fpe_app_init(&app_ctx_ff1, key, sizeof(key), WBCYRPTO_FPE_CIPHER_SM4, WBCYRPTO_FPE_FFX_FF1);
    program_start = clock();
    for (i = 0; i < TEST_CYCLE_NUM; i++) {
        WBCRYPTO_fpe_encrypt_phone_with_sample(&app_ctx_ff1, input, cipher, sample);
    }
    program_end = clock();
    ts = program_end - program_start;
    ts = ts / CLOCKS_PER_SEC;
    printf("[SM4-FF1] Time cost: %lf s, it means that the encryption speed is: %f phone/s\n", ts / TEST_CYCLE_NUM,
           1 / (ts / TEST_CYCLE_NUM));

    WBCRYPTO_fpe_app_context app_ctx_ff3;
    WBCRYPTO_fpe_app_init(&app_ctx_ff3, key, sizeof(key), WBCYRPTO_FPE_CIPHER_SM4, WBCYRPTO_FPE_FFX_FF3);
    program_start = clock();
    for (i = 0; i < TEST_CYCLE_NUM; i++) {
        WBCRYPTO_fpe_encrypt_phone_with_sample(&app_ctx_ff3, input, cipher, sample);
    }
    program_end = clock();
    ts = program_end - program_start;
    ts = ts / CLOCKS_PER_SEC;
    printf("[SM4-FF3] Time cost: %lf s, it means that the encryption speed is: %f phone/s\n", ts / TEST_CYCLE_NUM,
           1 / (ts / TEST_CYCLE_NUM));
}

void test_wbsm4_fpeapp_perf() {
    int i;
    const uint8_t key[] = {
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
            0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
    };
    const char input[] = "13888888888";
    const char sample[] = "123****1234";
    char cipher[200] = {0};
    clock_t program_start, program_end;
    double ts;

    WBCRYPTO_fpe_app_context app_ctx_ff1;
    WBCRYPTO_fpe_app_init(&app_ctx_ff1, key, sizeof(key), WBCYRPTO_FPE_CIPHER_WBSM4, WBCYRPTO_FPE_FFX_FF1);
    program_start = clock();
    for (i = 0; i < TEST_CYCLE_NUM; i++) {
        WBCRYPTO_fpe_encrypt_phone_with_sample(&app_ctx_ff1, input, cipher, sample);
    }
    program_end = clock();
    ts = program_end - program_start;
    ts = ts / CLOCKS_PER_SEC;
    printf("[WBSM4-FF1] Time cost: %lf s, it means that the encryption speed is: %f phone/s\n", ts / TEST_CYCLE_NUM,
           1 / (ts / TEST_CYCLE_NUM));

    WBCRYPTO_fpe_app_context app_ctx_ff3;
    WBCRYPTO_fpe_app_init(&app_ctx_ff3, key, sizeof(key), WBCYRPTO_FPE_CIPHER_WBSM4, WBCYRPTO_FPE_FFX_FF3);
    program_start = clock();
    for (i = 0; i < TEST_CYCLE_NUM; i++) {
        WBCRYPTO_fpe_encrypt_phone_with_sample(&app_ctx_ff3, input, cipher, sample);
    }
    program_end = clock();
    ts = program_end - program_start;
    ts = ts / CLOCKS_PER_SEC;
    printf("[WBSM4-FF3] Time cost: %lf s, it means that the encryption speed is: %f phone/s\n", ts / TEST_CYCLE_NUM,
           1 / (ts / TEST_CYCLE_NUM));
}

int main() {
    test_aes_fpeapp_perf();
    test_wbaes_fpeapp_perf();
    test_sm4_fpeapp_perf();
    test_wbsm4_fpeapp_perf();
}
