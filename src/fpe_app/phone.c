#include <wbcrypto/fpe_app.h>
#include <wbcrypto/sm4.h>
#include <wbcrypto/wbsm4.h>
#include <string.h>
#include <ctype.h>

int aux_fpe_phone(WBCRYPTO_fpe_app_context *ctx, char *phone, char *sample, char *after_phone, fpe_block128_f block) {
    int ret = 0;
    int len = strlen(phone);
    int i, j, k, tweak_len = 0;

    for (i = 0; i < len; i++) {
        if (isdigit(sample[i])) {
            ++tweak_len;
        }
    }
    char input[len - tweak_len + 1];
    input[len - tweak_len] = '\0';
    char tweak[tweak_len + 1];
    tweak[tweak_len] = '\0';
    char ans[len - tweak_len];
    for (i = 0, j = 0, k = 0; i < len; i++) {
        if (isdigit(sample[i])) {
            tweak[k++] = phone[i];
        } else {
            input[j++] = phone[i];
        }
    }

    WBCRYPTO_fpe_context *fpe_ctx;
    if (strcmp(ctx->cipher, WBCYRPTO_FPE_CIPHER_SM4) == 0) {
        fpe_ctx = WBCRYPTO_sm4_fpe_init(ctx->cipher_ctx, tweak, sizeof(tweak), 10);
    } else if (strcmp(ctx->cipher, WBCYRPTO_FPE_CIPHER_WBSM4) == 0) {
        WBCRYPTO_fpe_context *fpe_ctx = WBCRYPTO_wbsm4_fpe_init(ctx->cipher_ctx, tweak, sizeof(tweak), 10);
    } else if (strcmp(ctx->cipher, WBCYRPTO_FPE_CIPHER_AES) == 0) {
        // todo 加入aes
    } else {
        // default: aes
    }
    (*block)(fpe_ctx, input, ans);

    for (i = 0, j = 0; i < len; i++) {
        if (isdigit(sample[i])) {
            after_phone[i] = phone[i];
        } else {
            after_phone[i] = ans[j++];
        }
    }

    ret = 1;
cleanup:
    WBCRYPTO_fpe_free(fpe_ctx);
    return ret;
}

int WBCRYPTO_fpe_encrypt_phone(WBCRYPTO_fpe_app_context *ctx, char *phone, char *sample, char *after_phone) {
    fpe_block128_f block;
    if (strcmp(ctx->ffx, WBCYRPTO_FPE_FFX_FF1) == 0) {
        block = (fpe_block128_f) WBCRYPTO_ff1_encrypt;
    } else if (strcmp(ctx->ffx, WBCYRPTO_FPE_FFX_FF3) == 0) {
        block = (fpe_block128_f) WBCRYPTO_ff3_encrypt;
    } else { // default: ff3-1
        block = (fpe_block128_f) WBCRYPTO_ff3_encrypt;
    }
    return aux_fpe_phone(ctx, phone, sample, after_phone, block);
}

int WBCRYPTO_fpe_decrypt_phone(WBCRYPTO_fpe_app_context *ctx, char *phone, char *sample, char *after_phone) {
    fpe_block128_f block;
    if (strcmp(ctx->ffx, WBCYRPTO_FPE_FFX_FF1) == 0) {
        block = (fpe_block128_f) WBCRYPTO_ff1_decrypt;
    } else if (strcmp(ctx->ffx, WBCYRPTO_FPE_FFX_FF3) == 0) {
        block = (fpe_block128_f) WBCRYPTO_ff3_decrypt;
    } else { // default: ff3-1
        block = (fpe_block128_f) WBCRYPTO_ff3_decrypt;
    }
    return aux_fpe_phone(ctx, phone, sample, after_phone, block);
}