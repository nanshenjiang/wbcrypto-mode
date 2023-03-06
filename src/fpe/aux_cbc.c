#include "aux_cbc.h"

int aux_cbc128_encrypt(const unsigned char *in, unsigned char *out,
                       size_t len, const void *key,
                       unsigned char ivec[16], block128_f block)
{
    size_t n;
    const unsigned char *iv = ivec;

    while (len >= 16)
    {
        for (n = 0; n < 16; n += sizeof(size_t))
            *(size_t *)(out + n) =
                *(size_t *)(in + n) ^ *(size_t *)(iv + n);
        (*block)(out, out, key);
        iv = out;
        len -= 16;
        in += 16;
        out += 16;
    }
    while (len)
    {
        for (n = 0; n < 16 && n < len; ++n)
            out[n] = in[n] ^ iv[n];
        for (; n < 16; ++n)
            out[n] = iv[n];
        (*block)(out, out, key);
        iv = out;
        if (len <= 16)
            break;
        len -= 16;
        in += 16;
        out += 16;
    }
    memcpy(ivec, iv, 16);
}