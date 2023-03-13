#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <mysql.h>
#include <wbcrypto/sm4.h>
#include <wbcrypto/fpe.h>

const uint8_t key[] = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
};

extern "C" {
    bool fpe_init(UDF_INIT *initid, UDF_ARGS *args, char *message);
    void fpe_deinit(UDF_INIT *initid);
    char *fpe(UDF_INIT *initid, UDF_ARGS *args, char *result, unsigned long *length, char *is_null, char *error);
}

void fpe_enc_phone(char *num, char *sample, int len, char *ret);

void fpe_enc_idcard(char *num, char *sample, int len, char *ret);

/*
 * fpe(plain, mode, sample)
 * fpe(plain, phone/idcard/address, "134xxxx5678")
 */
bool fpe_init(UDF_INIT *initid, UDF_ARGS *args, char *message) {
    if (args->arg_count != 3) {
        strcpy(message, "requires three argument");
        return 1;
    }

    if (args->arg_type[0] != STRING_RESULT || args->arg_type[1] != STRING_RESULT ||
        args->arg_type[2] != STRING_RESULT) {
        strcpy(message, "requires string as argument");
        return 1;
    }

    initid->max_length = args->lengths[0];
    initid->maybe_null = args->maybe_null;
    initid->ptr = (char *) malloc(initid->max_length + 1);
    if (initid->ptr == NULL) {
        strcpy(message, "could't allocate memory");
        return 1;
    }

    return 0;
}

void fpe_deinit(UDF_INIT *initid) {
    free(initid->ptr);
}

char *fpe(UDF_INIT *initid, UDF_ARGS *args, char *result, unsigned long *length, char *is_null, char *error) {
    char *plain = args->args[0];
    char *mode = args->args[1];
    char *sample = args->args[2];
    int plain_len = args->lengths[0];

    if (plain_len != args->lengths[2]) {
        char msg[200];
        sprintf(msg, "sample should be as long as plain, plain: %s, sample: %s", plain, sample);
        strcpy(error, msg);
        return NULL;
    }

    memcpy(initid->ptr, plain, plain_len);
    initid->ptr[plain_len] = '\0';

    if (strcmp(mode, "phone") == 0) {
        if (plain_len != 11) {
            strcpy(error, "the length of phone should be 11");
            return NULL;
        }
        fpe_e
                nc_phone(plain, sample, plain_len, initid->ptr);
    } else if (strcmp(mode, "idcard") == 0) {
        if (plain_len != 18) {
            strcpy(error, "the length of id-card should be 18");
            return NULL;
        }
        fpe_enc_idcard(plain, sample, plain_len, initid->ptr);
    } else if (strcmp(mode, "address") == 0) {
    } else {
        strcpy(error, "requires optional mode: phone or idcard or address");
        return NULL;
    }

    *length = plain_len;
    memcpy(result, initid->ptr, plain_len);

    // char ret[1024];
    // sprintf(ret, "%s", result);

    return result;
}

void fpe_enc_phone(char *phone, char *sample, int len, char *ret) {
    int i, j, k, tweak_len = 0;
    for (i = 0; i < len; i++) {
        if (isdigit(sample[i])) {
            ++tweak_len;
        }
    }
    char plain[len - tweak_len];
    char tweak[tweak_len];
    char ans[len - tweak_len];
    for (i = 0, j = 0, k = 0; i < len; i++) {
        if (isdigit(sample[i])) {
            tweak[k++] = phone[i];
        } else {
            plain[j++] = phone[i];
        }
    }

    WBCRYPTO_sm4_context *sm4_ctx = WBCRYPTO_sm4_context_init();
    WBCRYPTO_sm4_init_key(sm4_ctx, key, sizeof(key));
    WBCRYPTO_fpe_context *fpe_ctx = WBCRYPTO_sm4_fpe_init(sm4_ctx, tweak, sizeof(tweak), 10);
    WBCRYPTO_ff1_encrypt(fpe_ctx, plain, ans);

    for (i = 0, j = 0; i < len; i++) {
        if (isdigit(sample[i])) {
            ret[i] = phone[i];
        } else {
            ret[i] = ans[j++];
        }
    }
}

void fpe_enc_idcard(char *idcard, char *sample, int len, char *ret) {
    int i, j, k, tweak_len = 0;
    if (idcard[len] == 'X') {
        len--;
    }
    for (i = 0; i < len; i++) {
        if (isdigit(sample[i])) {
            ++tweak_len;
        }
    }
    char plain[len - tweak_len];
    char tweak[tweak_len];
    char ans[len - tweak_len];
    for (i = 0, j = 0, k = 0; i < len; i++) {
        if (isdigit(sample[i])) {
            tweak[k++] = idcard[i];
        } else {
            plain[j++] = idcard[i];
        }
    }

    WBCRYPTO_sm4_context *sm4_ctx = WBCRYPTO_sm4_context_init();
    WBCRYPTO_sm4_init_key(sm4_ctx, key, sizeof(key));
    WBCRYPTO_fpe_context *fpe_ctx = WBCRYPTO_sm4_fpe_init(sm4_ctx, tweak, sizeof(tweak), 10);
    WBCRYPTO_ff1_encrypt(fpe_ctx, plain, ans);

    for (i = 0, j = 0; i < len; i++) {
        if (isdigit(sample[i])) {
            ret[i] = idcard[i];
        } else {
            ret[i] = ans[j++];
        }
    }
    if (idcard[len] == 'X') {
        ret[len] = 'X';
    }
}