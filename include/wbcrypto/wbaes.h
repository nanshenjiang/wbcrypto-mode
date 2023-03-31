#ifndef WBCRYPTO_WBAES_H
#define WBCRYPTO_WBAES_H

#include <wbcrypto/aes.h>
#include <wbcrypto/modes.h>
#include <WBMatrix/WBMatrix.h>

#ifdef __cplusplus
extern "C" {
#endif

    //Chow Whitebox-AES
    struct wbaes_context {
        uint32_t TypeII[10][16][256];
        uint32_t TypeIII[9][16][256];
        uint8_t TypeIV_II[9][4][3][8][16][16];
        uint8_t TypeIV_III[9][4][3][8][16][16];
        uint8_t TypeIa[16][256];
        uint8_t TypeIb[16][256];
    };

    typedef struct wbaes_context WBCRYPTO_wbaes_context;

    /******************************************basic function**********************************************/
    /**
    * the function initializes the wbaes context
    * @param ctx Context to initialize, MUST be NULL
    * @return NULL is fault, otherwise successful
    */
    WBCRYPTO_wbaes_context *WBCRYPTO_wbaes_context_init();

    /**
    * free context
    * @param ctx
    */
    void WBCRYPTO_wbaes_context_free(WBCRYPTO_wbaes_context *ctx);

    /**
    * the function generate key-tables by the key in the context
    * @param key key used to generate the key-tables, which need to hide
    * @param keylen key length
    * @return 1 if success, 0 if error
    */
    int WBCRYPTO_wbaes_gen_table(WBCRYPTO_wbaes_context *ctx, const uint8_t *key, size_t keylen);

    /**
    * the function is used to encrypt(**generally not used directly**)
    * @param ctx wbaes-ctx must be init
    * @param input plaintext
    * @param output ciphertext
    * @return 1 if success, 0 if error
    */
    int WBCRYPTO_wbaes_encrypt(const uint8_t *input, uint8_t *output, WBCRYPTO_wbaes_context *ctx);

    /********************************************CBC mode************************************************/
    /**
    * wbaes encryption of cbc mode
    * @param in plaintext
    * @param inlen the length of input
    * @param out ciphertext
    * @param max_olen the longest storage space of ciphertext
    * @param use_olen the specific using space length of ciphertext
    * @param ctx wbsm4-ctx must be init
    * @param ivec initialization-vectors, the length must be 16
    * @return 1 if success, 0 if error
    */
    int WBCRYPTO_wbaes_cbc_encrypt(const unsigned char *in, size_t inlen,
                                   unsigned char *out, size_t max_olen, size_t *use_olen,
                                   const WBCRYPTO_wbaes_context *ctx,
                                   unsigned char ivec[16]);

    /********************************************GCM mode************************************************/
    /**
    * init the gcm128 context
    * @param key the context of wbaes-algorithm, must be init
    * @return NULL is fault, otherwise successful
    */
    WBCRYPTO_gcm_context *WBCRYPTO_wbaes_gcm_init(WBCRYPTO_wbaes_context *key);

    /******************************************gcmfile mode*********************************************/
    /**
    * init the gcm-file context
    * @param key the context of wbaes-algorithm, must be init
    * @return NULL is fault, otherwise successful
    */
    WBCRYPTO_gcmfile_context *WBCRYPTO_wbaes_gcmfile_init(WBCRYPTO_wbaes_context *key);

    /******************************************fpe mode*********************************************/
    /**
    * Create a context instance for use with the FPE algorithm
    * @param key the context of wbaes-algorithm, must be init
    * @param twkbuf: Pointer to tweak data (may be NULL)
    * @param twklen: Number of bytes of tweak data (may be 0)
    * @param radix: The radix of the plain/cipher text data
    * @param return NULL is fault, otherwise successful
    */
    WBCRYPTO_fpe_context *WBCRYPTO_wbaes_fpe_init(WBCRYPTO_wbaes_context *key, const char *twkbuf, size_t twklen, unsigned int radix);

    /**
    * Create a context instance for use with the fpe_mac algorithm
    * @param key the context of aes-algorithm, must be init
    * @param twkbuf: Pointer to tweak data (may be NULL)
    * @param twklen: Number of bytes of tweak data (may be 0)
    * @param radix: The radix of the plain/cipher text data
    * @param return NULL is fault, otherwise successful
    */
    WBCRYPTO_fpe_mac_context *WBCRYPTO_wbaes_fpe_mac_init(WBCRYPTO_wbaes_context *key, const char *twkbuf, size_t twklen, unsigned int radix);

#ifdef __cplusplus
}
#endif

#endif //WBCRYPTO_WBAES_H
