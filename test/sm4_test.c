#include "test_local.h"
#include <wbcrypto/sm4.h>

static const unsigned char key[16]={0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                                    0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};

static const unsigned char msg[16]={0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                                   0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};

static const unsigned char expect_cipher[16]={0x68, 0x1e, 0xdf, 0x34, 0xd2, 0x06, 0x96, 0x5e,
                                              0x86, 0xb3, 0xe9, 0x4f, 0x53, 0x6e, 0x42, 0x46};

int test_sm4(){
    int ret=0;
    unsigned char cipher[16] = {0};
    unsigned char plain[16] = {0};

    WBCRYPTO_sm4_context *sm4_ctx;
    sm4_ctx=WBCRYPTO_sm4_context_init();
    WBCRYPTO_sm4_init_key(sm4_ctx, key, sizeof(key));
    WBCRYPTO_sm4_encrypt(msg, cipher, sm4_ctx);
    WBCRYPTO_MPI_CHK(TEST_cmp_values(cipher, expect_cipher, 16));
    TEST_print_state(cipher, sizeof(cipher));
    WBCRYPTO_sm4_decrypt(cipher, plain, sm4_ctx);
    TEST_print_state(plain, sizeof(plain));
    WBCRYPTO_MPI_CHK(TEST_cmp_values(msg, plain, sizeof(msg)));

    WBCRYPTO_sm4_context_free(sm4_ctx);
    ret = 1;
cleanup:
    return ret;
}

int main(){
    printf(test_sm4()?"sm4-test pass!\n":"sm4-test failed!\n");
}
