#include "ffx.h"
#include "aux_cbc.h"
#include <math.h>

/*
 * This function is intended to be used to create a context for
 * a specific algorithm. That is, the algorithm embeds the ffx_ctx
 * structure within a structure of its own. It then supplies the
 * total length of its structure as the @len parameter and the offset
 * to the ffx_ctx structure within as the @off parameter.
 *
 * The other parameters describe the limits/parameters of the algorithm.
 */
WBCRYPTO_ffx_context *ffx_ctx_create(const uint8_t *const twkbuf, const size_t twklen,
                                    const size_t maxtxtlen, const size_t mintwklen, const size_t maxtwklen,
                                    const unsigned int radix,
                                    const void *cipher_ctx, block128_f block)
{
    struct ffx_ctx *ctx;
    size_t mintxtlen;

    /*
     * FF1 and FF3-1 support a radix up to 65536, but the
     * implementation becomes increasingly difficult and
     * less useful in practice after the limits below.
     */
    if (radix < 2 || radix > 36)
    {
        goto cleanup;
    }

    /*
     * for both ff1 and ff3-1: radix**minlen >= 1000000
     *
     * therefore:
     *   minlen = ceil(log_radix(1000000))
     *          = ceil(log_10(1000000) / log_10(radix))
     *          = ceil(6 / log_10(radix))
     */
    mintxtlen = ceil((double)6 / log10(radix));
    if (mintxtlen < 2 || mintxtlen > maxtxtlen)
    {
        goto cleanup;
    }

    /*
     * make sure the default tweak falls within the
     * specified parameters for the algorithm
     *
     * a maxtwklen of 0 indicates that there is
     * no upper limit
     */
    if (mintwklen > maxtwklen ||
        twklen < mintwklen ||
        (maxtwklen > 0 && twklen > maxtwklen))
    {
        goto cleanup;
    }

    /*
     * allocate space and copy in the parameters
     *
     * the only way to fail at this point is if this
     * allocation or the allocation of the evp context
     * fails
     */
    ctx = malloc(sizeof(struct ffx_ctx));
    if (ctx)
    {
        ctx->cipher_ctx = (void *)cipher_ctx;
        ctx->block = block;
        if (ctx->cipher_ctx)
        {
            ctx->radix = radix;
            ctx->txtminlen = mintxtlen;
            ctx->txtmaxlen = maxtxtlen;

            ctx->twkminlen = mintwklen;
            ctx->twkmaxlen = maxtwklen;

            ctx->twk_buf = (uint8_t *)malloc(twklen*sizeof(uint8_t));
            ctx->twk_len = twklen;
            memcpy(ctx->twk_buf, twkbuf, twklen);
        }
        else
        {
            free(ctx);
            goto cleanup;
        }
    }
    return ctx;
cleanup:
    return NULL;
}

void ffx_ctx_free(WBCRYPTO_ffx_context *ctx)
{
    if(ctx){
        free(ctx);
    }
}

/*
 * reverse a sequence of bytes. @dst and @src may be
 * equal but may not overlap, otherwise
 */
uint8_t *ffx_revb(uint8_t *const dst,
                  const uint8_t *const src, const size_t len)
{
    size_t i;

    for (i = 0; i < len / 2; i++)
    {
        const uint8_t t = src[i];
        dst[i] = src[(len - 1) - i];
        dst[(len - 1) - i] = t;
    }

    /*
     * if length is odd, there will be a byte in the
     * middle untouched by the loop above
     */
    if (len % 2)
    {
        dst[i] = src[i];
    }

    return dst;
}

/*
 * convert a (big) integer, @n, to a string in the radix, @r,
 * with a length, @m. The caller must supply the space pointed
 * to by @str, and the number of bytes pointed to by @str is
 * indicated by @len, which must be at least @m + 2. (The
 * underlying number library sometimes overestimates the space
 * required to represent the string. The +2 includes 1 byte
 * for this overestimation and 1 byte for the nul terminator.)
 *
 * If, after conversion, the number of bytes necessary to
 * represent the @n is larger than @m, the function fails. if
 * the number of bytes is less than @m, the string is zero-padded
 * to the left.
 *
 * the function returns 0 on success
 */
int ffx_str(char *const str, const size_t len,
            const unsigned int m, const unsigned int r,
            const bigint_t *const n)
{
    int res;

    res = -EINVAL;
    if (bigint_cmp_si(n, 0) >= 0)
    {
        res = bigint_get_str(str, len, r, n);
        if (res == 0)
        {
            const size_t len = strlen(str);

            if (len < m)
            {
                memmove(str + (m - len), str, len + 1);
                memset(str, '0', m - len);
            }
            else if (len > m)
            {
                res = -EOVERFLOW;
            }
        }
    }

    return res;
}

/*
 * perform a byte-wise exclusive-or operation over the sequence
 * of bytes pointed to by @s1 and @s2, storing the result into @d.
 * @len indicates the minimum number of bytes in @s1, @s2, and @d.
 *
 * @d may be equal to @s1 and/or @s2, but they may not overlap,
 * otherwise
 *
 * @d is returned
 */
void *ffx_memxor(void *d,
                 const void *s1, const void *s2,
                 size_t len)
{
    while (len)
    {
        *(uint8_t *)d = *(uint8_t *)s1 ^ *(uint8_t *)s2;

        d = (uint8_t *)d + 1;

        s1 = (uint8_t *)s1 + 1;
        s2 = (uint8_t *)s2 + 1;

        len--;
    }

    return d;
}

/*
 * perform an aes-cbc encryption (with an IV of 0) of @src using
 * the supplied @ctx, storing the last block of output into @dst.
 * The number of bytes pointed to by @src is indicated by @len and
 * must be a multiple of 16. @dst and @src may point to the same
 * location but may not overlap, otherwise. @dst must point to a
 * location at least 16 bytes long
 */
int ffx_prf(WBCRYPTO_ffx_context *ctx,
            uint8_t *dst, const uint8_t *src, const size_t len)
{
    int i;
    uint8_t IV[16] = {0};

    if (len % 16)
    {
        return -EINVAL;
    }

    uint8_t *dst_t = malloc(len * sizeof(uint8_t));
    size_t uselen;

    aux_cbc128_encrypt(src, dst_t, len, ctx->cipher_ctx, IV, (block128_f)ctx->block);

    for (i = len - 16; i < len; i++)
    {
        dst[i - len + 16] = dst_t[i];
    }

    free(dst_t);

    return 0;
}

/*
 * perform an aes-ecb encryption of @src using the supplied @ctx.
 * @src and @dst must each be 16 bytes long. @src and @dst may
 * point to the same location or otherwise overlap
 */
int ffx_ciph(WBCRYPTO_ffx_context *ctx,
             uint8_t *const dst, const uint8_t *const src)
{
    return ffx_prf(ctx, dst, src, 16);
}
