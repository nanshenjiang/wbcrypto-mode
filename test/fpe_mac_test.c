#include "test_local.h"
#include <wbcrypto/aes.h>
#include <wbcrypto/fpe.h>
#include <time.h>

int test_ff1_cmac() {
    int ret=0;
    const uint8_t key[] = {
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
            0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
    };
    const char tweak[] = "12345";
    const char input[] = "13888888888";
    char cipher[20] = {0};
    char plain[20] = {0};
    char tag_enc[16],tag_dec[16];
    size_t use_len;

    WBCRYPTO_aes_context *aes_ctx = WBCRYPTO_aes_context_init();
    WBCRYPTO_aes_init_key(aes_ctx, key, sizeof(key));
    WBCRYPTO_fpe_mac_context *fpe_mac_enc_ctx = WBCRYPTO_aes_fpe_mac_init(aes_ctx, tweak, sizeof(tweak), 10);
    WBCRYPTO_ff1_cmac_encrypt(fpe_mac_enc_ctx, input, cipher);
    printf("[FF1-cmac] [aes] encrypt answer: %s\n", cipher);
    WBCRYPTO_ff1_cmac_finish(fpe_mac_enc_ctx, tag_enc, &use_len);
    printf("[FF1-cmac] [aes] encrypt tag: %s\n", tag_enc);

    WBCRYPTO_fpe_mac_context *fpe_mac_dec_ctx = WBCRYPTO_aes_fpe_mac_init(aes_ctx, tweak, sizeof(tweak), 10);
    WBCRYPTO_ff1_cmac_decrypt(fpe_mac_dec_ctx, cipher, plain);
    printf("[FF1-cmac] [aes] decrypt answer: %s\n", plain);
    WBCRYPTO_ff1_cmac_finish(fpe_mac_dec_ctx, tag_dec, &use_len);
    printf("[FF1-cmac] [aes] decrypt tag: %s\n", tag_dec);
    WBCRYPTO_MPI_CHK(TEST_cmp_values(tag_enc, tag_dec, 16));
    ret=1;
cleanup:
    return ret;
}

int test_ff3_gmac() {
    int ret=0;
    const uint8_t key[] = {
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
            0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
    };
    const char tweak[] = "12345";
    const char input[] = "13888888888";
    char cipher[20] = {0};
    char plain[20] = {0};
    char tag_enc[16]={0},tag_dec[16]={0};
    size_t use_len;

    WBCRYPTO_aes_context *aes_ctx = WBCRYPTO_aes_context_init();
    WBCRYPTO_aes_init_key(aes_ctx, key, sizeof(key));
    WBCRYPTO_fpe_mac_context *fpe_mac_enc_ctx = WBCRYPTO_aes_fpe_mac_init(aes_ctx, tweak, sizeof(tweak), 10);
    WBCRYPTO_ff3_gmac_encrypt(fpe_mac_enc_ctx, input, cipher);
    printf("[FF3-gmac] [aes] encrypt answer: %s\n", cipher);
    WBCRYPTO_ff3_gmac_finish(fpe_mac_enc_ctx, tag_enc, &use_len);
    printf("[FF3-gmac] [aes] encrypt tag: %s\n", tag_enc);

    WBCRYPTO_fpe_mac_context *fpe_mac_dec_ctx = WBCRYPTO_aes_fpe_mac_init(aes_ctx, tweak, sizeof(tweak), 10);
    WBCRYPTO_ff3_gmac_decrypt(fpe_mac_dec_ctx, cipher, plain);
    printf("[FF3-gmac] [aes] decrypt answer: %s\n", plain);
    WBCRYPTO_ff3_gmac_finish(fpe_mac_dec_ctx, tag_dec, &use_len);
    printf("[FF3-gmac] [aes] decrypt tag: %s\n", tag_dec);
    WBCRYPTO_MPI_CHK(TEST_cmp_values(tag_enc, tag_dec, 16));
    ret=1;
    cleanup:
    return ret;
}

int main() {
    printf(test_ff1_cmac() ? "ff1_cmac pass!\n" : "ff1_cmac failed!\n");
    printf(test_ff3_gmac() ? "ff3_gmac pass!\n" : "ff3_gmac failed!\n");
}
