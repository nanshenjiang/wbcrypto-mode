#include <wbcrypto/fpe_app.h>
#include <wbcrypto/aes.h>
#include <wbcrypto/sm4.h>
#include <wbcrypto/wbsm4.h>
#include <string.h>
#include <ctype.h>
#include "cn_char.h"

int aux_fpe_address(WBCRYPTO_fpe_app_context *ctx, char *address, char *sample, char *after_address, fpe_block128_f block) {
    int ret = 0;
    int len = strlen(address) / 3;
    int i, tweak_len = 0;

    for (i = 0; i < strlen(sample); i++) {
        if (sample[i] == 'x') {
            ++tweak_len;
        }
    }
    tweak_len = len - tweak_len;
    char input[(len - tweak_len) * 4 + 1];
    char tweak[tweak_len * 4 + 1];
    char ans[(len - tweak_len) * 4];
    char *input_p = input;
    char *tweak_p = tweak;
    char *ch = address;
    for (i = 0; i < strlen(sample); ch += 3) {
        uint32_t uc = utf8CharToUint32(ch);
        int uc_int = utf8Uint32ToInt(uc);
        if (sample[i] == 'x') {
            utf8IntToCharDuodecimal(uc_int, input_p);
            input_p += 4;
            ++i;
        } else {
            utf8IntToCharDuodecimal(uc_int, tweak_p);
            tweak_p += 4;
            i += 3;
        }
    }
    input[(len - tweak_len) * 4] = '\0';
    tweak[tweak_len * 4] = '\0';

    WBCRYPTO_fpe_context *fpe_ctx = NULL;
    if (strcmp(ctx->cipher, WBCYRPTO_FPE_CIPHER_SM4) == 0) {
        fpe_ctx = WBCRYPTO_sm4_fpe_init(ctx->cipher_ctx, tweak, sizeof(tweak), 12);
    } else if (strcmp(ctx->cipher, WBCYRPTO_FPE_CIPHER_WBSM4) == 0) {
        fpe_ctx = WBCRYPTO_wbsm4_fpe_init(ctx->cipher_ctx, tweak, sizeof(tweak), 12);
    } else if (strcmp(ctx->cipher, WBCYRPTO_FPE_CIPHER_AES) == 0) {
        fpe_ctx = WBCRYPTO_aes_fpe_init(ctx->cipher_ctx, tweak, sizeof(tweak), 12);
    } else { // default: aes
        fpe_ctx = WBCRYPTO_aes_fpe_init(ctx->cipher_ctx, tweak, sizeof(tweak), 12);
    }
    (*block)(fpe_ctx, input, ans);

    char *ori_add = address;
    char *ans_p = ans;
    char *af_p = after_address;
    for (i = 0; i < strlen(sample); af_p += 3, ori_add += 3) {
        if (sample[i] == 'x') {
            int uc_int = utf8CharDuodecimalToInt(ans_p);
            uint32_t uc = utf8IntToUint32(uc_int);
            utf8Uint32ToChar(uc, af_p);
            ans_p += 4;
            ++i;
        } else {
            memcpy(af_p, ori_add, 3);
            i += 3;
        }
    }

    ret = 1;
cleanup:
    WBCRYPTO_fpe_free(fpe_ctx);
    return ret;
}

int WBCRYPTO_fpe_encrypt_address(WBCRYPTO_fpe_app_context *ctx, char *address, char *sample, char *after_address) {
    fpe_block128_f block;
    if (strcmp(ctx->ffx, WBCYRPTO_FPE_FFX_FF1) == 0) {
        block = (fpe_block128_f) WBCRYPTO_ff1_encrypt;
    } else if (strcmp(ctx->ffx, WBCYRPTO_FPE_FFX_FF3) == 0) {
        block = (fpe_block128_f) WBCRYPTO_ff3_encrypt;
    } else { // default: ff3-1
        block = (fpe_block128_f) WBCRYPTO_ff3_encrypt;
    }
    return aux_fpe_address(ctx, address, sample, after_address, block);
}

int WBCRYPTO_fpe_decrypt_address(WBCRYPTO_fpe_app_context *ctx, char *address, char *sample, char *after_address) {
    fpe_block128_f block;
    if (strcmp(ctx->ffx, WBCYRPTO_FPE_FFX_FF1) == 0) {
        block = (fpe_block128_f) WBCRYPTO_ff1_decrypt;
    } else if (strcmp(ctx->ffx, WBCYRPTO_FPE_FFX_FF3) == 0) {
        block = (fpe_block128_f) WBCRYPTO_ff3_decrypt;
    } else { // default: ff3-1
        block = (fpe_block128_f) WBCRYPTO_ff3_decrypt;
    }
    return aux_fpe_address(ctx, address, sample, after_address, block);
}