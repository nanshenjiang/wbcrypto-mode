#include "test_local.h"
#include <wbcrypto/wbsm4.h>

static const unsigned char key[16] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                                      0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};

static const unsigned char msg[16] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                                      0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};

static const unsigned char expect_cipher[16] = {0x68, 0x1e, 0xdf, 0x34, 0xd2, 0x06, 0x96, 0x5e,
                                                0x86, 0xb3, 0xe9, 0x4f, 0x53, 0x6e, 0x42, 0x46};

int test_wbsm4() {
    int ret = 0;
    int i;
    unsigned char iv[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
                            0x0f};
    unsigned char aad[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
                             0x0f};
    unsigned char msg1024[1024] = {0};
    unsigned char cipher[16] = {0};
    unsigned char plain[16] = {0};
    unsigned char cipher1024[1024] = {0};
    unsigned char plain1024[1024] = {0};
    size_t use_len;
    for (i = 0; i < 1024; i++) {
        msg1024[i] = i & 0xff;
    }

    WBCRYPTO_wbsm4_context *wbsm4_ctx_enc, *wbsm4_ctx_dec;
    wbsm4_ctx_enc = WBCRYPTO_wbsm4_context_init(WBCRYPTO_ENCRYPT_MODE, 1);
    wbsm4_ctx_dec = WBCRYPTO_wbsm4_context_init(WBCRYPTO_DECRYPT_MODE, 1);
    WBCRYPTO_wbsm4_gen_table(wbsm4_ctx_enc, key, sizeof(key));
    WBCRYPTO_wbsm4_gen_table(wbsm4_ctx_dec, key, sizeof(key));
    WBCRYPTO_wbsm4_encrypt(msg, cipher, wbsm4_ctx_enc);
    WBCRYPTO_MPI_CHK(TEST_cmp_values(cipher, expect_cipher, 16));
    TEST_print_state(cipher, sizeof(cipher));
    WBCRYPTO_wbsm4_decrypt(cipher, plain, wbsm4_ctx_dec);
    TEST_print_state(plain, sizeof(plain));
    WBCRYPTO_MPI_CHK(TEST_cmp_values(msg, plain, sizeof(msg)));
    ret = 1;
cleanup:
    WBCRYPTO_wbsm4_context_free(wbsm4_ctx_enc);
    WBCRYPTO_wbsm4_context_free(wbsm4_ctx_dec);
    return ret;
}

int main() {
    printf(test_wbsm4() ? "wbsm4-test pass!\n" : "wbsm4-test failed!\n");
}
