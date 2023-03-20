#include <wbcrypto/aes.h>
#include "test_local.h"

static const unsigned char key[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                      0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};

static const unsigned char msg[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                      0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};

static const unsigned char expect_cipher[16] = {0x0A, 0x94, 0x0B, 0xB5, 0x41, 0x6E, 0xF0, 0x45,
                                                0xF1, 0xC3, 0x94, 0x58, 0xC6, 0x53, 0xEA, 0x5A};
int test_aes() {
    int ret=0,i;
    unsigned char iv[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
                            0x0f};
    unsigned char aad[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
                             0x0f};
    unsigned char cipher[16] = {0};
    unsigned char plain[16] = {0};
    unsigned char msg1024[1024] = {0};
    unsigned char cipher1024[1024] = {0};
    unsigned char plain1024[1024] = {0};
    for (i = 0; i < 1024; i++) {
        msg1024[i] = i & 0xff;
    }

    WBCRYPTO_aes_context *aes_ctx = WBCRYPTO_aes_context_init();
    WBCRYPTO_aes_init_key(aes_ctx, key, sizeof(key));
    WBCRYPTO_aes_encrypt(msg, cipher, aes_ctx);
    TEST_print_state(cipher, sizeof(cipher));
    WBCRYPTO_MPI_CHK(TEST_cmp_values(cipher, expect_cipher, sizeof(cipher)));

    WBCRYPTO_aes_decrypt(cipher, plain, aes_ctx);
    TEST_print_state(plain, sizeof(plain));
    WBCRYPTO_MPI_CHK(TEST_cmp_values(msg, plain, sizeof(msg)));
    ret = 1;
cleanup:
    WBCRYPTO_aes_context_free(aes_ctx);
    return ret;
}

int main() {
    printf(test_aes()?"aes-test pass!\n":"aes-test failed!\n");
}