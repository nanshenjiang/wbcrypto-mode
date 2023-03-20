#include <wbcrypto/wbaes.h>
#include "test_local.h"

static const unsigned char key[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                      0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};

static const unsigned char msg[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                      0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};

static const unsigned char expect_cipher[16] = {0x0A, 0x94, 0x0B, 0xB5, 0x41, 0x6E, 0xF0, 0x45,
                                                0xF1, 0xC3, 0x94, 0x58, 0xC6, 0x53, 0xEA, 0x5A};

int test_wbaes() {
    int ret = 0, i;
    unsigned char iv[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
                            0x0f};
    unsigned char aad[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
                             0x0f};
    unsigned char cipher[16] = {0};
    unsigned char msg1024[1024] = {0};
    unsigned char cipher1024[1024] = {0};
    unsigned char plain1024[1024] = {0};
    for (i = 0; i < 1024; i++) {
        msg1024[i] = i & 0xff;
    }

    WBCRYPTO_wbaes_context *wbaes_ctx = WBCRYPTO_wbaes_context_init();
    WBCRYPTO_wbaes_gen_table(wbaes_ctx, key, sizeof(key));
    WBCRYPTO_wbaes_encrypt(msg, cipher, wbaes_ctx);
    TEST_print_state(cipher, sizeof(cipher));
    WBCRYPTO_MPI_CHK(TEST_cmp_values(cipher, expect_cipher, sizeof(cipher)));
    ret = 1;
cleanup:
    WBCRYPTO_wbaes_context_free(wbaes_ctx);
    return ret;
}

int main() {
    printf(test_wbaes() ? "wbaes-test pass!\n" : "wbaes-test failed!\n");
}