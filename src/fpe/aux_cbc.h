#ifndef WBCRYPTO_AUX_CBC_H
#define WBCRYPTO_AUX_CBC_H

#include <wbcrypto/modes.h>


#ifdef  __cplusplus
extern "C" {
#endif

    /******************************************************************
    * Auxiliary function to implement the unfilled version of CBC mode
    *****************************************************************/
    int aux_cbc128_encrypt(const unsigned char *in, unsigned char *out,
                                size_t len, const void *key,
                                unsigned char ivec[16], block128_f block);

#ifdef  __cplusplus
}
#endif

#endif //WBCRYPTO_AUX_CBC_H