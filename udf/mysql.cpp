#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <mysql.h>
#include <wbcrypto/sm4.h>
#include <wbcrypto/fpe.h>

const uint8_t key[] = {
    0x2b,
    0x7e,
    0x15,
    0x16,
    0x28,
    0xae,
    0xd2,
    0xa6,
    0xab,
    0xf7,
    0x15,
    0x88,
    0x09,
    0xcf,
    0x4f,
    0x3c,
};

extern "C"
{
    bool fpe_init(UDF_INIT *initid, UDF_ARGS *args, char *message);
    void fpe_deinit(UDF_INIT *initid);
    char *fpe(UDF_INIT *initid, UDF_ARGS *args, char *result, unsigned long *length, char *is_null, char *error);
}

void fpe_enc_num(char *num, char *sample, int len, char *ret);

/*
 * fpe(plain, mode, sample)
 * fpe(plain, phone/idcard/address, "134xxxx5678")
 */
bool fpe_init(UDF_INIT *initid, UDF_ARGS *args, char *message)
{
    if (args->arg_count != 3)
    {
        strcpy(message, "requires three argument");
        return 1;
    }

    if (args->arg_type[0] != STRING_RESULT || args->arg_type[1] != STRING_RESULT || args->arg_type[2] != STRING_RESULT)
    {
        strcpy(message, "requires string as argument");
        return 1;
    }

    if (args->lengths[0] != args->lengths[2])
    {
        strcpy(message, "sample should be as long as plain");
        return 1;
    }

    if (strcmp(args->args[1], "phone") == 0)
    {
        if (args->lengths[0] != 11)
        {
            strcpy(message, "the length of phone should be 11");
            return 1;
        }
    }
    else if (strcmp(args->args[1], "idcard") == 0)
    {
        if (args->lengths[0] != 18)
        {
            strcpy(message, "the length of id-card should be 18");
            return 1;
        }
    }
    else if (strcmp(args->args[1], "address") == 0)
    {
        if (args->lengths[0] > 4096)
        {
            strcpy(message, "the length of address is too long");
            return 1;
        }
    }
    else
    {
        strcpy(message, "requires optional mode: phone or idcard or address");
        return 1;
    }

    initid->max_length = args->lengths[0];
    initid->maybe_null = args->maybe_null;
    initid->ptr = (char *)malloc(initid->max_length);
    if (initid->ptr == NULL)
    {
        strcpy(message, "could't allocate memory");
        return 1;
    }

    return 0;
}

void fpe_deinit(UDF_INIT *initid)
{
    free(initid->ptr);
}

char *fpe(UDF_INIT *initid, UDF_ARGS *args, char *result, unsigned long *length, char *is_null, char *error)
{
    int plain_len = initid->max_length;

    fpe_enc_num(args->args[0], args->args[2], plain_len, initid->ptr);

    *length = plain_len;
    memcpy(result, initid->ptr, plain_len);

    // char ret[1024];
    // sprintf(ret, "%s", result);

    return result;
}

void fpe_enc_num(char *num, char *sample, int len, char *ret)
{
    int i, j, k, tweak_len = 0;
    for (i = 0; i < len; i++)
    {
        if (!isdigit(sample[i]))
        {
            ++tweak_len;
        }
    }
    char plain[len - tweak_len];
    char tweak[tweak_len];
    char ans[len - tweak_len];
    for (i = 0, j = 0, k = 0; i < len; i++)
    {
        if (isdigit(sample[i]))
        {
            plain[j++] = num[i];
        }
        else
        {
            tweak[k++] = uint8_t(num[i]);
        }
    }

    WBCRYPTO_sm4_context *sm4_ctx = WBCRYPTO_sm4_context_init();
    WBCRYPTO_sm4_init_key(sm4_ctx, key, sizeof(key));
    WBCRYPTO_ff1_context *ff1_ctx1 = WBCRYPTO_sm4_ff1_init(sm4_ctx, tweak, sizeof(tweak), 10);
    WBCRYPTO_ff1_encrypt(ff1_ctx1, plain, ans);

    for (i = 0, j = 0; i < len; i++)
    {
        if (isdigit(sample[i]))
        {
            ret[i] = num[i];
        }
        else
        {
            ret[i] = ans[j++];
        }
    }
}