#include "test_local.h"
#include <wbcrypto/wbsm4.h>
#include <omp.h>

static const unsigned char key[16] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                                      0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};

static const unsigned char msg[16] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                                      0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};

void test_wbsm4_standard_perf() {
    long long i;
    unsigned char cipher[16] = {0};
    double start, end, total;

    WBCRYPTO_wbsm4_context *wbsm4_ctx_enc;
    wbsm4_ctx_enc = WBCRYPTO_wbsm4_context_init(WBCRYPTO_ENCRYPT_MODE, 1);
    WBCRYPTO_wbsm4_gen_table(wbsm4_ctx_enc, key, sizeof(key));

    start = omp_get_wtime();
    for (i = 0; i < (long long)TEST_CYCLE_NUM * 64 * 1024; i++) {
        WBCRYPTO_wbsm4_encrypt(msg, cipher, wbsm4_ctx_enc);
    }
    end = omp_get_wtime();
    total = end - start;
    printf("The standard of WBSM4 encrypt 1MB spend:  %15.15f s, it means that the encryption speed is: %f MByte/s\n",
           total / TEST_CYCLE_NUM, 1 / (total / TEST_CYCLE_NUM));

    WBCRYPTO_wbsm4_context_free(wbsm4_ctx_enc);
}

void test_wbsm4_cbc_perf() {
    long long i;
    unsigned char iv[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
                            0x0f};
    unsigned char msg1024[1024] = {0};
    unsigned char cipher1024[1024] = {0};
    size_t use_len;
    for (i = 0; i < 1024; i++) {
        msg1024[i] = i & 0xff;
    }
    double start, end, total;

    WBCRYPTO_wbsm4_context *wbsm4_ctx_enc;
    wbsm4_ctx_enc = WBCRYPTO_wbsm4_context_init(WBCRYPTO_ENCRYPT_MODE, 1);
    WBCRYPTO_wbsm4_gen_table(wbsm4_ctx_enc, key, sizeof(key));

    start = omp_get_wtime();
    for (i = 0; i < (long long)TEST_CYCLE_NUM * 1024; i++) {
        WBCRYPTO_wbsm4_cbc_encrypt(msg1024, sizeof(msg1024), cipher1024, sizeof(cipher1024), &use_len, wbsm4_ctx_enc,
                                   iv);
    }
    end = omp_get_wtime();
    total = end - start;
    printf("The cbc mode of WBSM4 encrypt 1MB spend:  %15.15f s, it means that the encryption speed is: %f MByte/s\n",
           total / TEST_CYCLE_NUM, 1 / (total / TEST_CYCLE_NUM));
    WBCRYPTO_wbsm4_context_free(wbsm4_ctx_enc);
}

void test_wbsm4_gcm_perf() {
    long long i;
    unsigned char iv[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
                            0x0f};
    unsigned char aad[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
                             0x0f};
    unsigned char msg1024[1024] = {0};
    unsigned char cipher1024[1024] = {0};
    for (i = 0; i < 1024; i++) {
        msg1024[i] = i & 0xff;
    }
    double start, end, total;

    WBCRYPTO_wbsm4_context *wbsm4_ctx_enc;
    wbsm4_ctx_enc = WBCRYPTO_wbsm4_context_init(WBCRYPTO_ENCRYPT_MODE, 1);
    WBCRYPTO_wbsm4_gen_table(wbsm4_ctx_enc, key, sizeof(key));

    WBCRYPTO_gcm_context *gcm_enc;
    gcm_enc = WBCRYPTO_wbsm4_gcm_init(wbsm4_ctx_enc);
    WBCRYPTO_gcm_setiv(gcm_enc, iv, sizeof(iv));
    WBCRYPTO_gcm_aad(gcm_enc, aad, sizeof(aad));
    start = omp_get_wtime();
    for (i = 0; i < (long long)TEST_CYCLE_NUM * 1024; i++) {
        WBCRYPTO_gcm_encrypt(gcm_enc, msg1024, sizeof(msg1024), cipher1024, sizeof(cipher1024));
    }
    end = omp_get_wtime();
    total = end - start;
    printf("The gcm mode of WBSM4 encrypt 1MB spend:  %15.15f s, it means that the encryption speed is: %f MByte/s\n",
           total / TEST_CYCLE_NUM, 1 / (total / TEST_CYCLE_NUM));
    WBCRYPTO_wbsm4_context_free(wbsm4_ctx_enc);
    WBCRYPTO_gcm_free(gcm_enc);
}

int test_wbsm4_gcm_parallel_perf() {
    long long i;
    unsigned char iv[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
                            0x0f};
    unsigned char aad[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
                             0x0f};
    unsigned char msg1024[1024] = {0};
    unsigned char cipher1024[1024] = {0};
    for (i = 0; i < 1024; i++) {
        msg1024[i] = i & 0xff;
    }
    double start, end, total;

    WBCRYPTO_wbsm4_context *wbsm4_ctx_enc;
    wbsm4_ctx_enc = WBCRYPTO_wbsm4_context_init(WBCRYPTO_ENCRYPT_MODE, 1);
    WBCRYPTO_wbsm4_gen_table(wbsm4_ctx_enc, key, sizeof(key));

    WBCRYPTO_gcm_context *gcm_enc;
    gcm_enc = WBCRYPTO_wbsm4_gcm_init(wbsm4_ctx_enc);
    WBCRYPTO_gcm_setiv(gcm_enc, iv, sizeof(iv));
    WBCRYPTO_gcm_aad(gcm_enc, aad, sizeof(aad));
    start = omp_get_wtime();
    for (i = 0; i < (long long)TEST_CYCLE_NUM * 1024; i++) {
        WBCRYPTO_gcm_parallel_encrypt(gcm_enc, msg1024, sizeof(msg1024), cipher1024, sizeof(cipher1024));
    }
    end = omp_get_wtime();
    total = end - start;
    printf("The gcm mode of WBSM4 parallel encrypt 1MB spend:  %15.15f s, it means that the encryption speed is: %f MByte/s\n",
           total / TEST_CYCLE_NUM, 1 / (total / TEST_CYCLE_NUM));
    WBCRYPTO_wbsm4_context_free(wbsm4_ctx_enc);
    WBCRYPTO_gcm_free(gcm_enc);
}

int main() {
    test_wbsm4_standard_perf();
    test_wbsm4_cbc_perf();
    test_wbsm4_gcm_perf();
    test_wbsm4_gcm_parallel_perf();
}
