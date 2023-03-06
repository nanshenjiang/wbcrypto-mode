#include "test_local.h"
#include <wbcrypto/sm4.h>
#include <wbcrypto/wbsm4.h>
#include <wbcrypto/fpe.h>
#include <time.h>

#define TESTTIME 1

int test_fpe(){
    int i;

    const uint8_t key[] = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
    };
    const uint8_t tweak[] = {
    };
    const char input[] = "13888888888";
    const char expect[] = "35858231455";
    char cipher[20]={0};
    char plain[20]={0};
    clock_t program_start, program_end;
    double ts;

    WBCRYPTO_sm4_context *sm4_ctx=WBCRYPTO_sm4_context_init();
    WBCRYPTO_sm4_init_key(sm4_ctx, key, sizeof(key));
    WBCRYPTO_ff1_context *ff1_ctx1 = WBCRYPTO_sm4_ff1_init(sm4_ctx, tweak, sizeof(tweak), 10);
    program_start = clock();
    for (i = 0; i < TESTTIME*64*1024; i++) {
        WBCRYPTO_ff1_encrypt(ff1_ctx1, input, cipher);
    }
    program_end = clock();
    ts = program_end - program_start;
    ts = ts/CLOCKS_PER_SEC;
    printf("Time cost: %lf s, it means that the encryption speed is: %f MByte/s\n", ts / TESTTIME, 1/(ts/TESTTIME));
    printf("encrypt answer: %s\n", cipher);

    WBCRYPTO_ff1_decrypt(ff1_ctx1, cipher, plain);
    printf("decrypt answer: %s\n", plain);

    // WBCRYPTO_wbsm4_context *wbsm4_ctx=WBCRYPTO_wbsm4_context_init(1, 1);
    // WBCRYPTO_wbsm4_gen_table(wbsm4_ctx, key, sizeof(key));
    // WBCRYPTO_ff1_context *ff1_ctx2 = WBCRYPTO_wbsm4_ff1_init(wbsm4_ctx, tweak, sizeof(tweak), 10);
    // WBCRYPTO_ff1_encrypt(ff1_ctx2, input, cipher);
    // printf("%s\n", cipher);
    // WBCRYPTO_ff1_decrypt(ff1_ctx2, cipher, plain);
    // printf("%s\n", plain);
}

int main(){
    test_fpe();
}
