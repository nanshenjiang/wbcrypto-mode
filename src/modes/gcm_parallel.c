#include <wbcrypto/modes.h>
#include <omp.h>

int WBCRYPTO_gcm_parallel_encrypt(WBCRYPTO_gcm_context *ctx,
                         const unsigned char *in, size_t inlen,
                         unsigned char *out, size_t outlen){
    int ret=0, len;            // our error return if the AES encrypt fails
    if(outlen<inlen){
        WBCRYPTO_THROW_REASON("WBCRYPTO_gcm_encrypt",WBCRYPTO_INLEN_THAN_OUTLEN);
    }else{
        len=inlen;
    }
    size_t i, j; // local loop iterator
    block128_f block = ctx->block;
    void *key = ctx->key;

    ctx->len += len; // bump the GCM context's running length count

    size_t len_s = (len - 1) / 16 + 1;
    //pretreatment
    unsigned char **y_arr = (unsigned char **)malloc(sizeof(unsigned char *) * len_s);
    for (i = 0; i < len_s; i++)
    {
        y_arr[i] = (unsigned char *)malloc(sizeof(unsigned char) * 16);
        for (j = 16; j > 12; j--)
            if (++ctx->y[j - 1] != 0)
                break;
        for (j = 0; j < 16; j++)
            y_arr[i][j] = ctx->y[j];
    }
    //able to parallel
//    int threads_num = omp_get_max_threads();
    omp_set_num_threads(4);
#pragma omp parallel
    {
#pragma omp for
        for (i = 0; i < len_s; i++)
        {
            unsigned char ectr[16];
            size_t use_len = 16;
            if (i == (len_s - 1))
            {
                use_len = (len % 16 == 0) ? 16 : len % 16;
            }
            (*block)(y_arr[i], ectr, key);
            for (j = 0; j < use_len; j++)
            {
                out[16 * i + j] = (unsigned char)(ectr[j] ^ in[16 * i + j]);
            }
        }
    }
    //unable to parallel
    for (i = 0; i < len_s; i++)
    {
        size_t use_len = 16;
        if (i == (len_s - 1))
        {
            use_len = (len % 16 == 0) ? 16 : len % 16;
        }
        for (j = 0; j < use_len; j++)
        {
            ctx->buf[j] ^= out[16 * i + j];
        }
        gcm_mult(ctx, ctx->buf, ctx->buf);
    }
    ret=1;
cleanup:
    return ret;
}

int WBCRYPTO_gcm_parallel_decrypt(WBCRYPTO_gcm_context *ctx,
                         const unsigned char *in, size_t inlen,
                         unsigned char *out, size_t outlen){
    int ret=0, len;            // our error return if the AES encrypt fails
    if(outlen<inlen){
        WBCRYPTO_THROW_REASON("WBCRYPTO_gcm_decrypt",WBCRYPTO_INLEN_THAN_OUTLEN);
    }else{
        len=inlen;
    }
    size_t i, j; // local loop iterator
    block128_f block = ctx->block;
    void *key = ctx->key;

    ctx->len += len; // bump the GCM context's running length count

    size_t len_s = (len - 1) / 16 + 1;
    //pretreatment
    unsigned char **y_arr = (unsigned char **)malloc(sizeof(unsigned char *) * len_s);
    for (i = 0; i < len_s; i++)
    {
        y_arr[i] = (unsigned char *)malloc(sizeof(unsigned char) * 16);
        for (j = 16; j > 12; j--)
            if (++ctx->y[j - 1] != 0)
                break;
        for (j = 0; j < 16; j++)
            y_arr[i][j] = ctx->y[j];
    }
    //able to parallel
//    int threads_num = omp_get_max_threads();
    omp_set_num_threads(4);
#pragma omp parallel
    {
#pragma omp for
        for (i = 0; i < len_s; i++)
        {
            unsigned char ectr[16];
            size_t use_len = 16;
            if (i == (len_s - 1))
            {
                use_len = (len % 16 == 0) ? 16 : len % 16;
            }
            (*block)(y_arr[i], ectr, key);
            for (j = 0; j < use_len; j++)
            {
                out[16 * i + j] = (unsigned char)(ectr[j] ^ in[16 * i + j]);
            }
        }
    }
    //unable to parallel
    for (i = 0; i < len_s; i++)
    {
        size_t use_len = 16;
        if (i == (len_s - 1))
        {
            use_len = (len % 16 == 0) ? 16 : len % 16;
        }
        for (j = 0; j < use_len; j++)
        {
            ctx->buf[j] ^= out[16 * i + j];
        }
        gcm_mult(ctx, ctx->buf, ctx->buf);
    }
    ret=1;
cleanup:
    return ret;
}