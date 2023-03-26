#include <wbcrypto/sm4.h>
#include <wbcrypto/aes.h>
#include <wbcrypto/wbaes.h>
#include <wbcrypto/wbsm4.h>
#include <wbcrypto/wbaes_wbgcm_ee.h>
#include <wbcrypto/wbaes_wbgcm_mask.h>
#include "test_local.h"

static const unsigned char key[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                      0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};

int test_aes_gcmfile() {
    int ret = 0;
    int i;
    unsigned char iv[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
                            0x0f};
    unsigned char aad[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
                             0x0f};

    WBCRYPTO_aes_context *aes_ctx = WBCRYPTO_aes_context_init();
    WBCRYPTO_aes_init_key(aes_ctx, key, sizeof(key));

    WBCRYPTO_gcmfile_context *enc_gcmfile, *dec_gcmfile;
    enc_gcmfile = WBCRYPTO_aes_gcmfile_init(aes_ctx);
    WBCRYPTO_gcmfile_setiv(enc_gcmfile, iv, sizeof(iv));
    WBCRYPTO_gcmfile_aad(enc_gcmfile, aad, sizeof(aad));
    WBCRYPTO_gcmfile_encrypt(enc_gcmfile, WBCRYPTO_TEST_FIN_PATH, WBCRYPTO_TEST_FENC_PATH);

    dec_gcmfile = WBCRYPTO_aes_gcmfile_init(aes_ctx);
    WBCRYPTO_gcmfile_setiv(dec_gcmfile, iv, sizeof(iv));
    WBCRYPTO_gcmfile_aad(dec_gcmfile, aad, sizeof(aad));
    WBCRYPTO_gcmfile_decrypt(dec_gcmfile, WBCRYPTO_TEST_FENC_PATH, WBCRYPTO_TEST_FDEC_PATH);
    WBCRYPTO_MPI_CHK(TEST_cmp_handle_files());

    ret = 1;
    cleanup:
    WBCRYPTO_aes_context_free(aes_ctx);
    WBCRYPTO_gcmfile_free(enc_gcmfile);
    WBCRYPTO_gcmfile_free(dec_gcmfile);
    return ret;
}

int test_sm4_gcmfile() {
    int ret = 0;
    int i;
    unsigned char iv[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
                            0x0f};
    unsigned char aad[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
                             0x0f};

    WBCRYPTO_sm4_context *sm4_ctx = WBCRYPTO_sm4_context_init();
    WBCRYPTO_sm4_init_key(sm4_ctx, key, sizeof(key));

    WBCRYPTO_gcmfile_context *enc_gcmfile, *dec_gcmfile;
    enc_gcmfile = WBCRYPTO_sm4_gcmfile_init(sm4_ctx);
    WBCRYPTO_gcmfile_setiv(enc_gcmfile, iv, sizeof(iv));
    WBCRYPTO_gcmfile_aad(enc_gcmfile, aad, sizeof(aad));
    WBCRYPTO_gcmfile_encrypt(enc_gcmfile, WBCRYPTO_TEST_FIN_PATH, WBCRYPTO_TEST_FENC_PATH);

    dec_gcmfile = WBCRYPTO_sm4_gcmfile_init(sm4_ctx);
    WBCRYPTO_gcmfile_setiv(dec_gcmfile, iv, sizeof(iv));
    WBCRYPTO_gcmfile_aad(dec_gcmfile, aad, sizeof(aad));
    WBCRYPTO_gcmfile_decrypt(dec_gcmfile, WBCRYPTO_TEST_FENC_PATH, WBCRYPTO_TEST_FDEC_PATH);
    WBCRYPTO_MPI_CHK(TEST_cmp_handle_files());

    ret = 1;
    cleanup:
    WBCRYPTO_sm4_context_free(sm4_ctx);
    WBCRYPTO_gcmfile_free(enc_gcmfile);
    WBCRYPTO_gcmfile_free(dec_gcmfile);
    return ret;
}

int test_wbaes_gcmfile() {
    int ret = 0;
    int i;
    unsigned char iv[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
                            0x0f};
    unsigned char aad[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
                             0x0f};

    WBCRYPTO_wbaes_context *wbaes_ctx;
    wbaes_ctx = WBCRYPTO_wbaes_context_init(WBCRYPTO_ENCRYPT_MODE, 1);
    WBCRYPTO_wbaes_gen_table(wbaes_ctx, key, sizeof(key));

    WBCRYPTO_gcmfile_context *enc_gcmfile, *dec_gcmfile;
    enc_gcmfile = WBCRYPTO_wbaes_gcmfile_init(wbaes_ctx);
    WBCRYPTO_gcmfile_setiv(enc_gcmfile, iv, sizeof(iv));
    WBCRYPTO_gcmfile_aad(enc_gcmfile, aad, sizeof(aad));
    WBCRYPTO_gcmfile_encrypt(enc_gcmfile, WBCRYPTO_TEST_FIN_PATH, WBCRYPTO_TEST_FENC_PATH);

    dec_gcmfile = WBCRYPTO_wbaes_gcmfile_init(wbaes_ctx);
    WBCRYPTO_gcmfile_setiv(dec_gcmfile, iv, sizeof(iv));
    WBCRYPTO_gcmfile_aad(dec_gcmfile, aad, sizeof(aad));
    WBCRYPTO_gcmfile_decrypt(dec_gcmfile, WBCRYPTO_TEST_FENC_PATH, WBCRYPTO_TEST_FDEC_PATH);
    WBCRYPTO_MPI_CHK(TEST_cmp_handle_files());

    ret = 1;
    cleanup:
    WBCRYPTO_wbaes_context_free(wbaes_ctx);
    WBCRYPTO_gcmfile_free(enc_gcmfile);
    WBCRYPTO_gcmfile_free(dec_gcmfile);
    return ret;
}

int test_wbsm4_gcmfile() {
    int ret = 0;
    int i;
    unsigned char iv[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
                            0x0f};
    unsigned char aad[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
                             0x0f};

    WBCRYPTO_wbsm4_context *wbsm4_ctx;
    wbsm4_ctx = WBCRYPTO_wbsm4_context_init(WBCRYPTO_ENCRYPT_MODE, 1);
    WBCRYPTO_wbsm4_gen_table(wbsm4_ctx, key, sizeof(key));

    WBCRYPTO_gcmfile_context *enc_gcmfile, *dec_gcmfile;
    enc_gcmfile = WBCRYPTO_wbsm4_gcmfile_init(wbsm4_ctx);
    WBCRYPTO_gcmfile_setiv(enc_gcmfile, iv, sizeof(iv));
    WBCRYPTO_gcmfile_aad(enc_gcmfile, aad, sizeof(aad));
    WBCRYPTO_gcmfile_encrypt(enc_gcmfile, WBCRYPTO_TEST_FIN_PATH, WBCRYPTO_TEST_FENC_PATH);

    dec_gcmfile = WBCRYPTO_wbsm4_gcmfile_init(wbsm4_ctx);
    WBCRYPTO_gcmfile_setiv(dec_gcmfile, iv, sizeof(iv));
    WBCRYPTO_gcmfile_aad(dec_gcmfile, aad, sizeof(aad));
    WBCRYPTO_gcmfile_decrypt(dec_gcmfile, WBCRYPTO_TEST_FENC_PATH, WBCRYPTO_TEST_FDEC_PATH);
    WBCRYPTO_MPI_CHK(TEST_cmp_handle_files());

    ret = 1;
    cleanup:
    WBCRYPTO_wbsm4_context_free(wbsm4_ctx);
    WBCRYPTO_gcmfile_free(enc_gcmfile);
    WBCRYPTO_gcmfile_free(dec_gcmfile);
    return ret;
}

int test_wbaes_wbgcmfile_ee() {
    int ret = 0;
    int i;
    unsigned char iv[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
                            0x0f};
    unsigned char aad[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
                             0x0f};

    WBCRYPTO_wbaes_wbgcm_ee_context wbaes_ctx;
    WBCRYPTO_wbaes_wbgcm_ee_gen_table(&wbaes_ctx, key, sizeof(key));

    WBCRYPTO_wbgcm_ee_context *wbgcm_enc = WBCRYPTO_wbaes_wbgcm_ee_init(&wbaes_ctx);
    WBCRYPTO_wbaes_wbgcm_ee_setiv(wbgcm_enc, iv, sizeof(iv));
    WBCRYPTO_wbaes_wbgcm_ee_aad(wbgcm_enc, aad, sizeof(aad));
    WBCRYPTO_wbaes_wbgcmfile_ee_encrypt(wbgcm_enc, WBCRYPTO_TEST_FIN_PATH, WBCRYPTO_TEST_FENC_PATH);

    WBCRYPTO_wbgcm_ee_context *wbgcm_dec=WBCRYPTO_wbaes_wbgcm_ee_init(&wbaes_ctx);
    WBCRYPTO_wbaes_wbgcm_ee_setiv(wbgcm_dec,iv,sizeof(iv));
    WBCRYPTO_wbaes_wbgcm_ee_aad(wbgcm_dec,aad,sizeof(aad));
    WBCRYPTO_wbaes_wbgcmfile_ee_decrypt(wbgcm_dec, WBCRYPTO_TEST_FENC_PATH, WBCRYPTO_TEST_FDEC_PATH);
    WBCRYPTO_MPI_CHK(TEST_cmp_handle_files());

    ret = 1;
cleanup:
    WBCRYPTO_wbaes_wbgcm_ee_free(wbgcm_enc);
    WBCRYPTO_wbaes_wbgcm_ee_free(wbgcm_dec);
    return ret;
}

int test_wbaes_wbgcmfile_mask() {
    int ret = 0;
    int i;
    unsigned char iv[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
                            0x0f};
    unsigned char aad[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
                             0x0f};

    WBCRYPTO_wbaes_wbgcm_mask_context *wbaes_enc_ctx = WBCRYPTO_wbaes_wbgcm_mask_init_table();
    WBCRYPTO_wbaes_wbgcm_mask_context *wbaes_dec_ctx = WBCRYPTO_wbaes_wbgcm_mask_init_table();
    WBCRYPTO_wbaes_wbgcm_mask_gen_table(wbaes_enc_ctx, wbaes_dec_ctx, key, sizeof(key));

    WBCRYPTO_wbgcm_mask_context *wbgcm_enc;
    wbgcm_enc=WBCRYPTO_wbaes_wbgcm_mask_init(wbaes_enc_ctx);
    WBCRYPTO_wbaes_wbgcm_mask_setiv(wbgcm_enc,iv,sizeof(iv));
    WBCRYPTO_wbaes_wbgcm_mask_aad(wbgcm_enc,aad,sizeof(aad));
    WBCRYPTO_wbaes_wbgcmfile_mask_encrypt(wbgcm_enc, WBCRYPTO_TEST_FIN_PATH, WBCRYPTO_TEST_FENC_PATH);

    WBCRYPTO_wbgcm_mask_context *wbgcm_dec;
    wbgcm_dec=WBCRYPTO_wbaes_wbgcm_mask_init(wbaes_dec_ctx);
    WBCRYPTO_wbaes_wbgcm_mask_setiv(wbgcm_dec,iv,sizeof(iv));
    WBCRYPTO_wbaes_wbgcm_mask_aad(wbgcm_dec,aad,sizeof(aad));
    WBCRYPTO_wbaes_wbgcmfile_mask_decrypt(wbgcm_dec, WBCRYPTO_TEST_FENC_PATH, WBCRYPTO_TEST_FDEC_PATH);
    WBCRYPTO_MPI_CHK(TEST_cmp_handle_files());

    ret = 1;
cleanup:
    WBCRYPTO_wbaes_wbgcm_mask_free(wbgcm_enc);
    WBCRYPTO_wbaes_wbgcm_mask_free(wbgcm_dec);
    return ret;
}

int main() {
    printf(test_aes_gcmfile() ? "aes-test file pass!\n" : "aes-test file failed!\n");
    printf(test_sm4_gcmfile() ? "sm4-test file pass!\n" : "sm4-test file failed!\n");
    printf(test_wbaes_gcmfile() ? "wbaes-test file pass!\n" : "wbaes-test file failed!\n");
    printf(test_wbsm4_gcmfile() ? "wbsm4-test file pass!\n" : "wbsm4-test file failed!\n");
    printf(test_wbaes_wbgcmfile_ee() ? "wbsm4-wbgcm-ee-test file pass!\n" : "wbsm4-wbgcm-ee-test file failed!\n");
    printf(test_wbaes_wbgcmfile_mask() ? "wbsm4-wbgcm-mask-test file pass!\n" : "wbsm4-wbgcm-mask-test file failed!\n");
}