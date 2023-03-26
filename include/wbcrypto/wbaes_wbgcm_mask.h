#ifndef WBCRYPTO_MODE_WBAES_WBGCM_MASK_H
#define WBCRYPTO_MODE_WBAES_WBGCM_MASK_H

#include <wbcrypto/wbaes.h>
#include <wbcrypto/modes.h>
#include <WBMatrix/WBMatrix.h>

#ifdef __cplusplus
extern "C" {
#endif

    /******************************************************************
    * CHOW Whitebox-AES with whibox-gcm mode by masking
    *****************************************************************/
    struct wbaes_wbgcm_mask_context {
        int encMode; //enc: 1, dec: 0
        uint32_t TypeII[10][16][256];
        uint32_t TypeIII[9][16][256];
        uint8_t TypeIV_II[9][4][3][8][16][16];
        uint8_t TypeIV_III[9][4][3][8][16][16];
        uint8_t TypeIa[16][256];   //wbaes externl encoding(input)
        uint8_t TypeIb[16][256];   //wbaes externl encoding(output)
        uint8_t GBOX_TypeI[16][256];
        uint8_t GBOX_TypeII[16][256];
        uint8_t ***GBOX_TypeIII;   //GBOX_TypeIII[16][256][256]
        M8 L1[16];
    };

    typedef struct wbaes_wbgcm_mask_context WBCRYPTO_wbaes_wbgcm_mask_context;

    WBCRYPTO_wbaes_wbgcm_mask_context *WBCRYPTO_wbaes_wbgcm_mask_init_table();

    void WBCRYPTO_wbaes_wbgcm_mask_gen_table(WBCRYPTO_wbaes_wbgcm_mask_context *enc_ctx,
                                             WBCRYPTO_wbaes_wbgcm_mask_context *dec_ctx,
                                             const uint8_t *key, size_t keylen);

    void aux_WBCRYPTO_wbaes_wbgcm_mask_encrypt(const uint8_t *input, uint8_t *output, WBCRYPTO_wbaes_wbgcm_mask_context *ctx);

    /**********************Whibox-GCM-Masking Modes******************************/
    struct wbgcm_mask_context {
        uint64_t len;                   // cipher data length processed so far
        uint64_t add_len;               // total add data length
        uint64_t HL[16];                // precalculated lo-half HTable
        uint64_t HH[16];                // precalculated hi-half HTable
        unsigned char base_ectr[16];    // first counter-mode cipher output for tag
        unsigned char y[16];            // the current cipher-input IV|Counter value
        unsigned char buf[16];          // buf working value
        WBCRYPTO_wbaes_wbgcm_mask_context *key;       // cipher context used
        block128_f block;               //encryption algorithm
    };

    typedef struct wbgcm_mask_context WBCRYPTO_wbgcm_mask_context;

    WBCRYPTO_wbgcm_mask_context *WBCRYPTO_wbaes_wbgcm_mask_init(WBCRYPTO_wbaes_wbgcm_mask_context *key);

    int WBCRYPTO_wbaes_wbgcm_mask_setiv(WBCRYPTO_wbgcm_mask_context *ctx, const unsigned char *iv, size_t len);

    int WBCRYPTO_wbaes_wbgcm_mask_aad(WBCRYPTO_wbgcm_mask_context *ctx, const unsigned char *aad, size_t len);

    int WBCRYPTO_wbaes_wbgcm_mask_encrypt(WBCRYPTO_wbgcm_mask_context *ctx,
                                          const unsigned char *in, size_t inlen,
                                          unsigned char *out, size_t outlen);

    int WBCRYPTO_wbaes_wbgcm_mask_decrypt(WBCRYPTO_wbgcm_mask_context *ctx,
                                          const unsigned char *in, size_t inlen,
                                          unsigned char *out, size_t outlen);

    int WBCRYPTO_wbaes_wbgcm_mask_finish(WBCRYPTO_wbgcm_mask_context *ctx, unsigned char *tag, size_t len);

    void WBCRYPTO_wbaes_wbgcm_mask_free(WBCRYPTO_wbgcm_mask_context *ctx);

    /**********************Whibox-GCM-Masking File Modes******************************/

    int WBCRYPTO_wbaes_wbgcmfile_mask_encrypt(WBCRYPTO_wbgcm_mask_context *ctx, char *infpath, char *outfpath);

    int WBCRYPTO_wbaes_wbgcmfile_mask_decrypt(WBCRYPTO_wbgcm_mask_context *ctx, char *infpath, char *outfpath);


#ifdef __cplusplus
}
#endif

#endif //WBCRYPTO_MODE_WBAES_WBGCM_MASK_H
