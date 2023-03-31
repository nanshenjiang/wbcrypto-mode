#include "test_local.h"
#include <wbcrypto/aes.h>
#include <wbcrypto/fpe.h>
#include <time.h>

int test_ff1_cmac() {
    int i;
    const uint8_t key[] = {
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
            0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
    };
    const char tweak[] = "";
    const char input[] = "1234567890123456";
    char cipher[50] = {0};
    char plain[50] = {0};
    clock_t program_start, program_end;
    double ts;

    WBCRYPTO_aes_context *aes_ctx = WBCRYPTO_aes_context_init();
    WBCRYPTO_aes_init_key(aes_ctx, key, sizeof(key));
    WBCRYPTO_fpe_mac_context *fpe_mac_enc_ctx = WBCRYPTO_aes_fpe_mac_init(aes_ctx, tweak, sizeof(tweak), 10);
    program_start = clock();
    for (i = 0; i < (long long)TEST_CYCLE_NUM * 64; i++) {
        WBCRYPTO_ff1_cmac_encrypt(fpe_mac_enc_ctx, input, cipher);
    }
    program_end = clock();
    ts = program_end - program_start;
    ts = ts / CLOCKS_PER_SEC;
    printf("[FF1-cmac] [aes] Time cost: %lf s, it means that the encryption speed is: %f KByte/s\n", ts / TEST_CYCLE_NUM,
           1 / (ts / TEST_CYCLE_NUM));

    WBCRYPTO_fpe_mac_context *fpe_mac_dec_ctx = WBCRYPTO_aes_fpe_mac_init(aes_ctx, tweak, sizeof(tweak), 10);
    program_start = clock();
    for (i = 0; i < (long long)TEST_CYCLE_NUM * 64; i++) {
        WBCRYPTO_ff1_cmac_decrypt(fpe_mac_dec_ctx, cipher, plain);
    }
    program_end = clock();
    ts = program_end - program_start;
    ts = ts / CLOCKS_PER_SEC;
    printf("[FF1-cmac] [aes] Time cost: %lf s, it means that the decryption speed is: %f KByte/s\n", ts / TEST_CYCLE_NUM,
           1 / (ts / TEST_CYCLE_NUM));
    return 1;
}

int test_ff3_gmac() {
    int i=0;
    const uint8_t key[] = {
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
            0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
    };
    const char tweak[] = "";
    const char input[] = "1234567890123456";
    char cipher[50] = {0};
    char plain[50] = {0};
    clock_t program_start, program_end;
    double ts;

    WBCRYPTO_aes_context *aes_ctx = WBCRYPTO_aes_context_init();
    WBCRYPTO_aes_init_key(aes_ctx, key, sizeof(key));
    WBCRYPTO_fpe_mac_context *fpe_mac_enc_ctx = WBCRYPTO_aes_fpe_mac_init(aes_ctx, tweak, sizeof(tweak), 10);
    program_start = clock();
    for (i = 0; i < (long long)TEST_CYCLE_NUM * 64; i++) {
        WBCRYPTO_ff3_gmac_encrypt(fpe_mac_enc_ctx, input, cipher);
    }
    program_end = clock();
    ts = program_end - program_start;
    ts = ts / CLOCKS_PER_SEC;
    printf("[FF3-gmac] [aes] Time cost: %lf s, it means that the encryption speed is: %f KByte/s\n", ts / TEST_CYCLE_NUM,
           1 / (ts / TEST_CYCLE_NUM));

    WBCRYPTO_fpe_mac_context *fpe_mac_dec_ctx = WBCRYPTO_aes_fpe_mac_init(aes_ctx, tweak, sizeof(tweak), 10);
    program_start = clock();
    for (i = 0; i < (long long)TEST_CYCLE_NUM * 64; i++) {
        WBCRYPTO_ff3_gmac_decrypt(fpe_mac_dec_ctx, cipher, plain);
    }
    program_end = clock();
    ts = program_end - program_start;
    ts = ts / CLOCKS_PER_SEC;
    printf("[FF3-gmac] [aes] Time cost: %lf s, it means that the decryption speed is: %f KByte/s\n", ts / TEST_CYCLE_NUM,
           1 / (ts / TEST_CYCLE_NUM));
    return 1;
}

int main() {
    test_ff1_cmac();
    test_ff3_gmac();
}
