#include "test_local.h"
#include <wbcrypto/se_wbsm4.h>

static const unsigned char key[16] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                                      0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};

static const unsigned char msg[16] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                                      0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};

static const unsigned char expect_cipher[16] = {0x68, 0x1e, 0xdf, 0x34, 0xd2, 0x06, 0x96, 0x5e,
                                                0x86, 0xb3, 0xe9, 0x4f, 0x53, 0x6e, 0x42, 0x46};

int test_wbsm4() {
    int ret = 0;
    unsigned char cipher[16] = {0};
    unsigned char plain[16] = {0};

    WBCRYPTO_se_wbsm4_context *wbsm4_ctx_enc, *wbsm4_ctx_dec;
    wbsm4_ctx_enc = WBCRYPTO_se_wbsm4_context_init(1);
    wbsm4_ctx_dec = WBCRYPTO_se_wbsm4_context_init(0);
    WBCRYPTO_se_wbsm4_gen_table(wbsm4_ctx_enc, key, sizeof(key));
    WBCRYPTO_se_wbsm4_gen_table(wbsm4_ctx_dec, key, sizeof(key));
    WBCRYPTO_se_wbsm4_encrypt(msg, cipher, wbsm4_ctx_enc);
    TEST_print_state(cipher, sizeof(cipher));
    WBCRYPTO_MPI_CHK(TEST_cmp_values(cipher, expect_cipher, 16));
    WBCRYPTO_se_wbsm4_decrypt(cipher, plain, wbsm4_ctx_enc);
    TEST_print_state(plain, sizeof(plain));
    WBCRYPTO_MPI_CHK(TEST_cmp_values(msg, plain, 16));
    ret = 1;
cleanup:
    WBCRYPTO_se_wbsm4_context_free(wbsm4_ctx_enc);
    return ret;
}

int main() {
    printf(test_wbsm4() ? "se-wbsm4-test pass!\n" : "se-wbsm4-test failed!\n");
}
