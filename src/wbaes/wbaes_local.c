#include "wbaes_local.h"

void shiftRows(uint8_t state[16]) {
    int i;
    uint8_t out[16];
    int shiftTab[16] = {0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11};
    for (i = 0; i < 16; i++) {
        out[i] = state[shiftTab[i]];
    }
    memcpy(state, out, sizeof(out));
}

uint8_t gMul(uint8_t a, uint8_t b) {
    int i;
    uint8_t p = 0;
    uint8_t hi_bit_set;

    for (i = 0; i < 8; i++) {
        if ((b & 1) == 1)
            p ^= a;
        hi_bit_set = (a & 0x80);
        a <<= 1;
        if (hi_bit_set == 0x80)
            a ^= 0x1b;
        b >>= 1;
    }
    return p;
}

void expandKey(const uint8_t key[16], uint8_t expandedKey[176]) {
    uint8_t tmp[4];
    int i = 0;
    int k;

    for (i = 0; i < 4; i++) {
        expandedKey[4 * i] = key[4 * i];
        expandedKey[4 * i + 1] = key[4 * i + 1];
        expandedKey[4 * i + 2] = key[4 * i + 2];
        expandedKey[4 * i + 3] = key[4 * i + 3];
    }

    for (i = 4; i < 44; i++) {
        tmp[0] = expandedKey[4 * (i - 1)];
        tmp[1] = expandedKey[4 * (i - 1) + 1];
        tmp[2] = expandedKey[4 * (i - 1) + 2];
        tmp[3] = expandedKey[4 * (i - 1) + 3];

        if (i % 4 == 0) {
            k = tmp[0];
            tmp[0] = SBox[tmp[1]] ^ rCon[i / 4];
            tmp[1] = SBox[tmp[2]];
            tmp[2] = SBox[tmp[3]];
            tmp[3] = SBox[k];

        }
        expandedKey[4 * i] = expandedKey[4 * (i - 4)] ^ tmp[0];
        expandedKey[4 * i + 1] = expandedKey[4 * (i - 4) + 1] ^ tmp[1];
        expandedKey[4 * i + 2] = expandedKey[4 * (i - 4) + 2] ^ tmp[2];
        expandedKey[4 * i + 3] = expandedKey[4 * (i - 4) + 3] ^ tmp[3];
    }
}