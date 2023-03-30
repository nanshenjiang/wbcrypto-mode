#include <wbcrypto/sm4.h>
#include <wbcrypto/aes.h>
#include <wbcrypto/wbaes.h>
#include <wbcrypto/wbsm4.h>
#include <wbcrypto/wbaes_wbgcm_ee.h>
#include <wbcrypto/wbaes_wbgcm_mask.h>
#include "test_local.h"

static const unsigned char key[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                      0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};

const char *testFilePath[] = {"../../testData/test_1KB.txt", "../../testData/test_10KB.txt",
                              "../../testData/test_100KB.txt", "../../testData/test_1MB.txt",
                              "../../testData/test_10MB.txt", "../../testData/test_100MB.txt"};

int power(int base, int exponent) {
    int result = 1;
    int i;
    for (i = 0; i < exponent; i++) {
        result *= base;
    }
    return result;
}

int test_aes_gcmfile() {
    int i, j;
    unsigned char iv[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
                            0x0f};
    unsigned char aad[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
                             0x0f};
    clock_t program_start, program_end;
    double ts;

    WBCRYPTO_aes_context *aes_ctx = WBCRYPTO_aes_context_init();
    WBCRYPTO_aes_init_key(aes_ctx, key, sizeof(key));

    WBCRYPTO_gcmfile_context *enc_gcmfile, *dec_gcmfile;
    enc_gcmfile = WBCRYPTO_aes_gcmfile_init(aes_ctx);
    WBCRYPTO_gcmfile_setiv(enc_gcmfile, iv, sizeof(iv));
    WBCRYPTO_gcmfile_aad(enc_gcmfile, aad, sizeof(aad));
    dec_gcmfile = WBCRYPTO_aes_gcmfile_init(aes_ctx);
    WBCRYPTO_gcmfile_setiv(dec_gcmfile, iv, sizeof(iv));
    WBCRYPTO_gcmfile_aad(dec_gcmfile, aad, sizeof(aad));

    for (i = 0; i < sizeof(testFilePath) / 8; i++) {
        char *tmp_enc = "../../testData/test.enc.txt";
        char *tmp_dec = "../../testData/test.dec.txt";
        program_start = clock();
        for (j = 0; j < TEST_CYCLE_NUM; j++) {
            WBCRYPTO_gcmfile_encrypt(enc_gcmfile, testFilePath[i], tmp_enc);
        }
        program_end = clock();
        ts = program_end - program_start;
        ts = ts / CLOCKS_PER_SEC;
        printf("AES encrypt %d KB txt spend: %lf s\n", power(10, i), ts / TEST_CYCLE_NUM);

        program_start = clock();
        for (j = 0; j < TEST_CYCLE_NUM; j++) {
            WBCRYPTO_gcmfile_decrypt(dec_gcmfile, tmp_enc, tmp_dec);
        }
        program_end = clock();
        ts = program_end - program_start;
        ts = ts / CLOCKS_PER_SEC;
        printf("AES decrypt %d KB txt spend: %lf s\n", power(10, i), ts / TEST_CYCLE_NUM);
        remove(tmp_enc);
        remove(tmp_dec);
    }

    WBCRYPTO_aes_context_free(aes_ctx);
    WBCRYPTO_gcmfile_free(enc_gcmfile);
    WBCRYPTO_gcmfile_free(dec_gcmfile);
    return 1;
}

int test_sm4_gcmfile() {
    int i,j;
    unsigned char iv[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
                            0x0f};
    unsigned char aad[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
                             0x0f};
    clock_t program_start, program_end;
    double ts;

    WBCRYPTO_sm4_context *sm4_ctx = WBCRYPTO_sm4_context_init();
    WBCRYPTO_sm4_init_key(sm4_ctx, key, sizeof(key));

    WBCRYPTO_gcmfile_context *enc_gcmfile, *dec_gcmfile;
    enc_gcmfile = WBCRYPTO_sm4_gcmfile_init(sm4_ctx);
    WBCRYPTO_gcmfile_setiv(enc_gcmfile, iv, sizeof(iv));
    WBCRYPTO_gcmfile_aad(enc_gcmfile, aad, sizeof(aad));
    dec_gcmfile = WBCRYPTO_sm4_gcmfile_init(sm4_ctx);
    WBCRYPTO_gcmfile_setiv(dec_gcmfile, iv, sizeof(iv));
    WBCRYPTO_gcmfile_aad(dec_gcmfile, aad, sizeof(aad));

    for (i = 0; i < sizeof(testFilePath) / 8; i++) {
        char *tmp_enc = "../../testData/test.enc.txt";
        char *tmp_dec = "../../testData/test.dec.txt";
        program_start = clock();
        for (j = 0; j < TEST_CYCLE_NUM; j++) {
            WBCRYPTO_gcmfile_encrypt(enc_gcmfile, testFilePath[i], tmp_enc);
        }
        program_end = clock();
        ts = program_end - program_start;
        ts = ts / CLOCKS_PER_SEC;
        printf("SM4 encrypt %d KB txt spend: %lf s\n", power(10, i), ts / TEST_CYCLE_NUM);

        program_start = clock();
        for (j = 0; j < TEST_CYCLE_NUM; j++) {
            WBCRYPTO_gcmfile_decrypt(dec_gcmfile, tmp_enc, tmp_dec);
        }
        program_end = clock();
        ts = program_end - program_start;
        ts = ts / CLOCKS_PER_SEC;
        printf("SM4 decrypt %d KB txt spend: %lf s\n", power(10, i), ts / TEST_CYCLE_NUM);
        remove(tmp_enc);
        remove(tmp_dec);
    }

    WBCRYPTO_sm4_context_free(sm4_ctx);
    WBCRYPTO_gcmfile_free(enc_gcmfile);
    WBCRYPTO_gcmfile_free(dec_gcmfile);
    return 1;
}

int test_wbaes_gcmfile() {
    int i,j;
    unsigned char iv[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
                            0x0f};
    unsigned char aad[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
                             0x0f};
    clock_t program_start, program_end;
    double ts;

    WBCRYPTO_wbaes_context *wbaes_ctx;
    wbaes_ctx = WBCRYPTO_wbaes_context_init(WBCRYPTO_ENCRYPT_MODE, 1);
    WBCRYPTO_wbaes_gen_table(wbaes_ctx, key, sizeof(key));

    WBCRYPTO_gcmfile_context *enc_gcmfile, *dec_gcmfile;
    enc_gcmfile = WBCRYPTO_wbaes_gcmfile_init(wbaes_ctx);
    WBCRYPTO_gcmfile_setiv(enc_gcmfile, iv, sizeof(iv));
    WBCRYPTO_gcmfile_aad(enc_gcmfile, aad, sizeof(aad));
    dec_gcmfile = WBCRYPTO_wbaes_gcmfile_init(wbaes_ctx);
    WBCRYPTO_gcmfile_setiv(dec_gcmfile, iv, sizeof(iv));
    WBCRYPTO_gcmfile_aad(dec_gcmfile, aad, sizeof(aad));

    for (i = 0; i < sizeof(testFilePath) / 8; i++) {
        char *tmp_enc = "../../testData/test.enc.txt";
        char *tmp_dec = "../../testData/test.dec.txt";
        program_start = clock();
        for (j = 0; j < TEST_CYCLE_NUM; j++) {
            WBCRYPTO_gcmfile_encrypt(enc_gcmfile, testFilePath[i], tmp_enc);
        }
        program_end = clock();
        ts = program_end - program_start;
        ts = ts / CLOCKS_PER_SEC;
        printf("WBAES encrypt %d KB txt spend: %lf s\n", power(10, i), ts / TEST_CYCLE_NUM);

        program_start = clock();
        for (j = 0; j < TEST_CYCLE_NUM; j++) {
            WBCRYPTO_gcmfile_decrypt(dec_gcmfile, tmp_enc, tmp_dec);
        }
        program_end = clock();
        ts = program_end - program_start;
        ts = ts / CLOCKS_PER_SEC;
        printf("WBAES decrypt %d KB txt spend: %lf s\n", power(10, i), ts / TEST_CYCLE_NUM);
        remove(tmp_enc);
        remove(tmp_dec);
    }

    WBCRYPTO_wbaes_context_free(wbaes_ctx);
    WBCRYPTO_gcmfile_free(enc_gcmfile);
    WBCRYPTO_gcmfile_free(dec_gcmfile);
    return 1;
}

int test_wbsm4_gcmfile() {
    int i,j;
    unsigned char iv[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
                            0x0f};
    unsigned char aad[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
                             0x0f};
    clock_t program_start, program_end;
    double ts;

    WBCRYPTO_wbsm4_context *wbsm4_ctx;
    wbsm4_ctx = WBCRYPTO_wbsm4_context_init(WBCRYPTO_ENCRYPT_MODE, 1);
    WBCRYPTO_wbsm4_gen_table(wbsm4_ctx, key, sizeof(key));

    WBCRYPTO_gcmfile_context *enc_gcmfile, *dec_gcmfile;
    enc_gcmfile = WBCRYPTO_wbsm4_gcmfile_init(wbsm4_ctx);
    WBCRYPTO_gcmfile_setiv(enc_gcmfile, iv, sizeof(iv));
    WBCRYPTO_gcmfile_aad(enc_gcmfile, aad, sizeof(aad));
    dec_gcmfile = WBCRYPTO_wbsm4_gcmfile_init(wbsm4_ctx);
    WBCRYPTO_gcmfile_setiv(dec_gcmfile, iv, sizeof(iv));
    WBCRYPTO_gcmfile_aad(dec_gcmfile, aad, sizeof(aad));

    for (i = 0; i < sizeof(testFilePath) / 8; i++) {
        char *tmp_enc = "../../testData/test.enc.txt";
        char *tmp_dec = "../../testData/test.dec.txt";
        program_start = clock();
        for (j = 0; j < TEST_CYCLE_NUM; j++) {
            WBCRYPTO_gcmfile_encrypt(enc_gcmfile, testFilePath[i], tmp_enc);
        }
        program_end = clock();
        ts = program_end - program_start;
        ts = ts / CLOCKS_PER_SEC;
        printf("WBSM4 encrypt %d KB txt spend: %lf s\n", power(10, i), ts / TEST_CYCLE_NUM);

        program_start = clock();
        for (j = 0; j < TEST_CYCLE_NUM; j++) {
            WBCRYPTO_gcmfile_decrypt(dec_gcmfile, tmp_enc, tmp_dec);
        }
        program_end = clock();
        ts = program_end - program_start;
        ts = ts / CLOCKS_PER_SEC;
        printf("WBSM4 decrypt %d KB txt spend: %lf s\n", power(10, i), ts / TEST_CYCLE_NUM);
        remove(tmp_enc);
        remove(tmp_dec);
    }

    WBCRYPTO_wbsm4_context_free(wbsm4_ctx);
    WBCRYPTO_gcmfile_free(enc_gcmfile);
    WBCRYPTO_gcmfile_free(dec_gcmfile);
    return 1;
}

int test_wbaes_wbgcmfile_ee() {
    int i,j;
    unsigned char iv[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
                            0x0f};
    unsigned char aad[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
                             0x0f};
    clock_t program_start, program_end;
    double ts;

    WBCRYPTO_wbaes_wbgcm_ee_context wbaes_ctx;
    WBCRYPTO_wbaes_wbgcm_ee_gen_table(&wbaes_ctx, key, sizeof(key));

    WBCRYPTO_wbgcm_ee_context *wbgcm_enc = WBCRYPTO_wbaes_wbgcm_ee_init(&wbaes_ctx);
    WBCRYPTO_wbaes_wbgcm_ee_setiv(wbgcm_enc, iv, sizeof(iv));
    WBCRYPTO_wbaes_wbgcm_ee_aad(wbgcm_enc, aad, sizeof(aad));
    WBCRYPTO_wbgcm_ee_context *wbgcm_dec = WBCRYPTO_wbaes_wbgcm_ee_init(&wbaes_ctx);
    WBCRYPTO_wbaes_wbgcm_ee_setiv(wbgcm_dec, iv, sizeof(iv));
    WBCRYPTO_wbaes_wbgcm_ee_aad(wbgcm_dec, aad, sizeof(aad));

    for (i = 0; i < sizeof(testFilePath) / 8; i++) {
        char *tmp_enc = "../../testData/test.enc.txt";
        char *tmp_dec = "../../testData/test.dec.txt";
        program_start = clock();
        for (j = 0; j < TEST_CYCLE_NUM; j++) {
            WBCRYPTO_wbaes_wbgcmfile_ee_encrypt(wbgcm_enc, testFilePath[i], tmp_enc);

        }
        program_end = clock();
        ts = program_end - program_start;
        ts = ts / CLOCKS_PER_SEC;
        printf("WBAES-EE encrypt %d KB txt spend: %lf s\n", power(10, i), ts / TEST_CYCLE_NUM);

        program_start = clock();
        for (j = 0; j < TEST_CYCLE_NUM; j++) {
            WBCRYPTO_wbaes_wbgcmfile_ee_decrypt(wbgcm_dec, tmp_enc, tmp_dec);
        }
        program_end = clock();
        ts = program_end - program_start;
        ts = ts / CLOCKS_PER_SEC;
        printf("WBAES-EE decrypt %d KB txt spend: %lf s\n", power(10, i), ts / TEST_CYCLE_NUM);
        remove(tmp_enc);
        remove(tmp_dec);
    }

    WBCRYPTO_wbaes_wbgcm_ee_free(wbgcm_enc);
    WBCRYPTO_wbaes_wbgcm_ee_free(wbgcm_dec);
    return 1;
}

int test_wbaes_wbgcmfile_mask() {
    int i,j;
    unsigned char iv[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
                            0x0f};
    unsigned char aad[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
                             0x0f};
    clock_t program_start, program_end;
    double ts;

    WBCRYPTO_wbaes_wbgcm_mask_context *wbaes_enc_ctx = WBCRYPTO_wbaes_wbgcm_mask_init_table();
    WBCRYPTO_wbaes_wbgcm_mask_context *wbaes_dec_ctx = WBCRYPTO_wbaes_wbgcm_mask_init_table();
    WBCRYPTO_wbaes_wbgcm_mask_gen_table(wbaes_enc_ctx, wbaes_dec_ctx, key, sizeof(key));

    WBCRYPTO_wbgcm_mask_context *wbgcm_enc;
    wbgcm_enc = WBCRYPTO_wbaes_wbgcm_mask_init(wbaes_enc_ctx);
    WBCRYPTO_wbaes_wbgcm_mask_setiv(wbgcm_enc, iv, sizeof(iv));
    WBCRYPTO_wbaes_wbgcm_mask_aad(wbgcm_enc, aad, sizeof(aad));
    WBCRYPTO_wbgcm_mask_context *wbgcm_dec;
    wbgcm_dec = WBCRYPTO_wbaes_wbgcm_mask_init(wbaes_dec_ctx);
    WBCRYPTO_wbaes_wbgcm_mask_setiv(wbgcm_dec, iv, sizeof(iv));
    WBCRYPTO_wbaes_wbgcm_mask_aad(wbgcm_dec, aad, sizeof(aad));

    for (i = 0; i < sizeof(testFilePath) / 8; i++) {
        char *tmp_enc = "../../testData/test.enc.txt";
        char *tmp_dec = "../../testData/test.dec.txt";
        program_start = clock();
        for (j = 0; j < TEST_CYCLE_NUM; j++) {
            WBCRYPTO_wbaes_wbgcmfile_mask_encrypt(wbgcm_enc, testFilePath[i], tmp_enc);

        }
        program_end = clock();
        ts = program_end - program_start;
        ts = ts / CLOCKS_PER_SEC;
        printf("WBAES-Masking encrypt %d KB txt spend: %lf s\n", power(10, i), ts / TEST_CYCLE_NUM);

        program_start = clock();
        for (j = 0; j < TEST_CYCLE_NUM; j++) {
            WBCRYPTO_wbaes_wbgcmfile_mask_decrypt(wbgcm_dec, tmp_enc, tmp_dec);
        }
        program_end = clock();
        ts = program_end - program_start;
        ts = ts / CLOCKS_PER_SEC;
        printf("WBAES-Masking decrypt %d KB txt spend: %lf s\n", power(10, i), ts / TEST_CYCLE_NUM);
        remove(tmp_enc);
        remove(tmp_dec);
    }

    WBCRYPTO_wbaes_wbgcm_mask_free(wbgcm_enc);
    WBCRYPTO_wbaes_wbgcm_mask_free(wbgcm_dec);
    return 1;
}

int main() {
    test_aes_gcmfile();
    test_sm4_gcmfile();
    test_wbaes_gcmfile();
    test_wbsm4_gcmfile();
    test_wbaes_wbgcmfile_ee();
    test_wbaes_wbgcmfile_mask();
}