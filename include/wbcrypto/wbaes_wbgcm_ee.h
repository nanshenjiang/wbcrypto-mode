#ifndef WBCRYPTO_MODE_WBAES_WBGCM_EE_H
#define WBCRYPTO_MODE_WBAES_WBGCM_EE_H

#include <wbcrypto/wbaes.h>
#include <wbcrypto/modes.h>
#include <WBMatrix/WBMatrix.h>

#ifdef __cplusplus
extern "C" {
#endif

    /******************************************************************
    * CHOW Whitebox-AES with whibox-gcm mode by ee type
    *****************************************************************/
    struct wbaes_wbgcm_ee_context {
        uint32_t TypeII[10][16][256];
        uint32_t TypeIII[9][16][256];
        uint8_t TypeIV_II[9][4][3][8][16][16];
        uint8_t TypeIV_III[9][4][3][8][16][16];
        uint8_t TypeIa[16][256];   //wbaes externl encoding(input)
        uint8_t GBOX_TypeI[16][256];
        uint8_t GBOX_TypeIII[16][256][256];
    };

    typedef struct wbaes_wbgcm_ee_context WBCRYPTO_wbaes_wbgcm_ee_context;

    void WBCRYPTO_wbaes_wbgcm_ee_gen_table(WBCRYPTO_wbaes_wbgcm_ee_context *ctx, const uint8_t *key, size_t keylen);

    void aux_WBCRYPTO_wbaes_wbgcm_ee_encrypt(const uint8_t *input, uint8_t *output, WBCRYPTO_wbaes_wbgcm_ee_context *ctx);

    /**********************Whibox-GCM-EE Modes******************************/

    struct wbgcm_ee_context{
        uint64_t len;                   // cipher data length processed so far
        uint64_t add_len;               // total add data length
        uint64_t HL[16];                // precalculated lo-half HTable
        uint64_t HH[16];                // precalculated hi-half HTable
        unsigned char base_ectr[16];    // first counter-mode cipher output for tag
        unsigned char y[16];            // the current cipher-input IV|Counter value
        unsigned char buf[16];          // buf working value
        WBCRYPTO_wbaes_wbgcm_ee_context *key;       // cipher context used
        block128_f block;               //encryption algorithm
    };

    typedef struct wbgcm_ee_context WBCRYPTO_wbgcm_ee_context;

    WBCRYPTO_wbgcm_ee_context *WBCRYPTO_wbaes_wbgcm_ee_init(WBCRYPTO_wbaes_wbgcm_ee_context *key);

    int WBCRYPTO_wbaes_wbgcm_ee_setiv(WBCRYPTO_wbgcm_ee_context *ctx,
                                       const unsigned char *iv, size_t len);

    int WBCRYPTO_wbaes_wbgcm_ee_aad(WBCRYPTO_wbgcm_ee_context *ctx,
                                     const unsigned char *aad, size_t len);

    int WBCRYPTO_wbaes_wbgcm_ee_encrypt(WBCRYPTO_wbgcm_ee_context *ctx,
                                         const unsigned char *in, size_t inlen,
                                         unsigned char *out, size_t outlen);

    int WBCRYPTO_wbaes_wbgcm_ee_decrypt(WBCRYPTO_wbgcm_ee_context *ctx,
                                         const unsigned char *in, size_t inlen,
                                         unsigned char *out, size_t outlen);

    int WBCRYPTO_wbaes_wbgcm_ee_finish(WBCRYPTO_wbgcm_ee_context *ctx, unsigned char *tag,
                                        size_t len);

    void WBCRYPTO_wbaes_wbgcm_ee_free(WBCRYPTO_wbgcm_ee_context *ctx);

#ifdef __cplusplus
}
#endif

#endif //WBCRYPTO_MODE_WBAES_WBGCM_EE_H
