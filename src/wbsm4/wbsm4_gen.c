#include "wbsm4_local.h"

const uint8_t SBOX[256] = {
        0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7,
        0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
        0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3,
        0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
        0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a,
        0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
        0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95,
        0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
        0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba,
        0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
        0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b,
        0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
        0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2,
        0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
        0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52,
        0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
        0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5,
        0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
        0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55,
        0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
        0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60,
        0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
        0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f,
        0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
        0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f,
        0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
        0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd,
        0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
        0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e,
        0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
        0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20,
        0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48,
};

M32 L_matrix = {
        .M[0] = 0xA0202080,
        .M[1] = 0x50101040,
        .M[2] = 0x28080820,
        .M[3] = 0x14040410,
        .M[4] = 0xA020208,
        .M[5] = 0x5010104,
        .M[6] = 0x2808082,
        .M[7] = 0x1404041,
        .M[8] = 0x80A02020,
        .M[9] = 0x40501010,
        .M[10] = 0x20280808,
        .M[11] = 0x10140404,
        .M[12] = 0x80A0202,
        .M[13] = 0x4050101,
        .M[14] = 0x82028080,
        .M[15] = 0x41014040,
        .M[16] = 0x2080A020,
        .M[17] = 0x10405010,
        .M[18] = 0x8202808,
        .M[19] = 0x4101404,
        .M[20] = 0x2080A02,
        .M[21] = 0x1040501,
        .M[22] = 0x80820280,
        .M[23] = 0x40410140,
        .M[24] = 0x202080A0,
        .M[25] = 0x10104050,
        .M[26] = 0x8082028,
        .M[27] = 0x4041014,
        .M[28] = 0x202080A,
        .M[29] = 0x1010405,
        .M[30] = 0x80808202,
        .M[31] = 0x40404101
};

void identityAff32(Aff32 *aff){
    int i;
    for(i = 0; i < 32; i++)
    {
        identityM32(&aff->Mat);
    }
    aff->Vec.V = 0;
}

uint8_t *wbsm4_gen_dummyround_array(int rounds, int dummyrounds) {
    int len_origin = rounds + dummyrounds;
    uint8_t *da = (uint8_t*) malloc(sizeof(uint8_t)*(len_origin));
    memset(da, 0, rounds);
    memset(da+rounds, 1, dummyrounds);
    wRandomShuffleU8(da, len_origin);
    int len_result = rounds + 4*dummyrounds;
    uint8_t *result = (uint8_t*) malloc(sizeof(uint8_t)*(len_result));
    uint8_t *iter = result;
    int i;
    for (i=0; i<len_origin; i++) {
        *iter = *(da+i);
        if (*iter) {
            memset(iter, 1, 4*sizeof(uint8_t));
            iter += 4;
        } else {
            iter ++;
        }
    }
    free(da);
    return result;
}

int WBCRYPTO_wbsm4_gen_table(WBCRYPTO_wbsm4_context *wbsm4_ctx,
                             const uint8_t *key, size_t keylen){
    int ret = 0;
    int i, j, x;
    uint8_t temp_u8;
    uint32_t temp_u32;
    Aff32 P[36];
    Aff32 P_inv[36];
    Aff8 Eij[32][4];
    Aff8 Eij_inv[32][4];
    Aff32 Ei_inv[32];
    Aff32 Q[32];
    Aff32 Q_inv[32];

    Aff32 M[32][3];
    Aff32 C[32];
    Aff32 D[32];
    uint32_t Q_constant[3] = {0};

    WBCRYPTO_sm4_context *sm4_key=WBCRYPTO_sm4_context_init();
    if(wbsm4_ctx->encmode) {
        aux_sm4_init_key(sm4_key, key, keylen, WBCRYPTO_ENCRYPT_MODE);
    }else{
        aux_sm4_init_key(sm4_key, key, keylen, WBCRYPTO_DECRYPT_MODE);
    }
    InitRandom(((unsigned int)time(NULL)));

    uint8_t *dummy_array = wbsm4_gen_dummyround_array(32, (wbsm4_ctx->rounds-32)/4);

    for (i = 0; i < 36; i++)
    {
        //affine P
        genaffinepairM32(&P[i], &P_inv[i]);
    }

    for (i = 0; i < 32; i++)
    {
        //affine E
        for (j = 0; j < 4; j++)
        {
            genaffinepairM8(&Eij[i][j], &Eij_inv[i][j]);
        }

        // combine 4 E8 to 1 E32
        affinecomM8to32(Eij_inv[i][0], Eij_inv[i][1], Eij_inv[i][2], Eij_inv[i][3], &Ei_inv[i]);

        //affine M
        affinemixM32(Ei_inv[i], P_inv[i + 1], &M[i][0]);
        affinemixM32(Ei_inv[i], P_inv[i + 2], &M[i][1]);
        affinemixM32(Ei_inv[i], P_inv[i + 3], &M[i][2]);

        //affine Q
        genaffinepairM32(&Q[i], &Q_inv[i]);

        //affine C D, C for Xi0, D for T(Xi1+Xi2+Xi3+rk)
        affinemixM32(P[i + 4], P_inv[i], &C[i]);
        affinemixM32(P[i + 4], Q_inv[i], &D[i]);
        uint32_t temp_u32 = cus_random();
        C[i].Vec.V ^= temp_u32;
        D[i].Vec.V ^= P[i + 4].Vec.V ^ temp_u32;
    }

    int flag = 0;
    int point;
    for (i = 0, point=0; i < wbsm4_ctx->rounds; i++, point++)
    {
        if(dummy_array[i]==0) {
            point = flag ? point - 4 : point;
            flag = 0;

            //1
            for (j = 0; j < 3; j++) {
                Q_constant[j] = cus_random();
            }
            for (x = 0; x < 256; x++) {
                for (j = 0; j < 4; j++) {
                    temp_u32 = x << (24 - j * 8);
                    wbsm4_ctx->MM[i][0][j][x] = affineU32(M[point][0], temp_u32);
                    wbsm4_ctx->MM[i][1][j][x] = affineU32(M[point][1], temp_u32);
                    wbsm4_ctx->MM[i][2][j][x] = affineU32(M[point][2], temp_u32);
                }
                for (j = 0; j < 3; j++) {
                    wbsm4_ctx->MM[i][0][j][x] ^= Q_constant[j];
                    wbsm4_ctx->MM[i][1][j][x] ^= Q_constant[j];
                    wbsm4_ctx->MM[i][2][j][x] ^= Q_constant[j];
                }
                wbsm4_ctx->MM[i][0][3][x] ^= M[point][0].Vec.V ^ Q_constant[0] ^ Q_constant[1] ^ Q_constant[2];
                wbsm4_ctx->MM[i][1][3][x] ^= M[point][1].Vec.V ^ Q_constant[0] ^ Q_constant[1] ^ Q_constant[2];
                wbsm4_ctx->MM[i][2][3][x] ^= M[point][2].Vec.V ^ Q_constant[0] ^ Q_constant[1] ^ Q_constant[2];
            }
            //2
            for (j = 0; j < 3; j++) {
                Q_constant[j] = cus_random();
            }
            for (x = 0; x < 256; x++) {
                for (j = 0; j < 4; j++) {
                    temp_u32 = x << (24 - j * 8);
                    wbsm4_ctx->CC[i][j][x] = affineU32(C[point], temp_u32);
                    wbsm4_ctx->DD[i][j][x] = affineU32(D[point], temp_u32);
                }
                for (j = 0; j < 3; j++) {
                    wbsm4_ctx->CC[i][j][x] ^= Q_constant[j];
                    wbsm4_ctx->DD[i][j][x] ^= Q_constant[j];
                }
                wbsm4_ctx->CC[i][3][x] ^= C[point].Vec.V ^ Q_constant[0] ^ Q_constant[1] ^ Q_constant[2];
                wbsm4_ctx->DD[i][3][x] ^= D[point].Vec.V ^ Q_constant[0] ^ Q_constant[1] ^ Q_constant[2];
            }
            //3
            //combine QL
            M32 QL;
            MatMulMatM32(Q[point].Mat, L_matrix, &QL);

            for (j = 0; j < 3; j++) {
                Q_constant[j] = cus_random();
            }

            for (x = 0; x < 256; x++) {
                for (j = 0; j < 4; j++) {
                    temp_u8 = affineU8(Eij[point][j], x);
                    temp_u8 = SBOX[temp_u8 ^ ((sm4_key->rk[point] >> (24 - j * 8)) & 0xff)];
                    temp_u32 = temp_u8 << (24 - j * 8);
                    wbsm4_ctx->Table[i][j][x] = MatMulNumM32(QL, temp_u32);
                }
                for (j = 0; j < 3; j++) {
                    wbsm4_ctx->Table[i][j][x] ^= Q_constant[j];
                }
                wbsm4_ctx->Table[i][3][x] ^= Q[point].Vec.V ^ Q_constant[0] ^ Q_constant[1] ^ Q_constant[2];
            }
        }else{
            flag=1;
            for(j=0;j<4;j++){
                for(x=0;x<256;x++){
                    wbsm4_ctx->Table[i][j][x]=0;
//                    wbsm4_ctx->DD[i][j][x]=0;
                }
            }
//            identityAff32(&wbsm4_ctx->CC[i]);
            for(j=0;j<4;j++){
                for(x=0;x<256;x++){
                    wbsm4_ctx->CC[i][j][x] = x << (24 - j * 8);
                }
            }
        }
    }

    //external encoding
    for(j = 0; j < 3; j++)
    {
        Q_constant[j] = cus_random();
    }
    for (i = 0; i < 4; i++)
    {
        for(x = 0; x < 256; x++)
        {
            for(j = 0; j < 4; j++)
            {
                temp_u32 = x << (24 - j * 8);
                wbsm4_ctx->SE[i][j][x] = affineU32(P[i], temp_u32);
                wbsm4_ctx->FE[i][j][x] = affineU32(P_inv[35 - i], temp_u32);
            }
            for(j = 0; j < 3; j++)
            {
                wbsm4_ctx->SE[i][j][x] ^= Q_constant[j];
                wbsm4_ctx->FE[i][j][x] ^= Q_constant[j];
            }
            wbsm4_ctx->SE[i][3][x] ^=  P[i].Vec.V ^ Q_constant[0] ^ Q_constant[1] ^ Q_constant[2];
            wbsm4_ctx->FE[i][3][x] ^=  P_inv[35 - i].Vec.V ^ Q_constant[0] ^ Q_constant[1] ^ Q_constant[2];
        }
    }

    ret=1;
cleanup:
    free(dummy_array);
    return ret;
}


