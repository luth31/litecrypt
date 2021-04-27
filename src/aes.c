#include "aes.h"
#include "_aes.h"
#include <stdio.h>

void Cipher() {

}

void ExpandKey(AES_Key* key, AES_RoundKey* rkey) {
    int i;
    for (i = 0; i < key->size; ++i) {
        rkey->data[i] = key->data[i];
        printf("%08X ", rkey->data[i]);
    }
    printf("\ni\ttemp\t\tRot\t\tSub\t\tRcon\t\txor rcon\tw\t\tw final\n");
    uint32_t tmp;
    while (i < 4 * (rkey->rounds + 1)) {
        printf("%d\t", i);
        tmp = rkey->data[i-1];
        printf("%08X\t", tmp);
        if (i % key->size == 0) {
            //tmp = SubWord(RotWord(tmp)) ^ Rcon[i/key->size];
            tmp = RotWord(tmp);
            printf("%08X\t", tmp);
            tmp = SubWord(tmp);
            printf("%08X\t", tmp);
            tmp ^= Rcon[i/key->size];
            printf("%08X\t", Rcon[i/key->size]);
            printf("%08X\t", tmp);
        }
        else if (key->size > 6 && i % key->size == 4) {
            tmp = SubWord(tmp);
            printf("%08X\t", tmp);
        }
        else {
            printf("\t\t\t\t");
        }
        rkey->data[i] = rkey->data[i - key->size] ^ tmp;
        printf("%08X\t%08X\n", rkey->data[i - key->size], rkey->data[i]);
        ++i;
    }
}

uint32_t SubWord(uint32_t word) {
    word = (sbox[(word & 0xFF000000) >> 24] << 24) |
            (sbox[(word & 0x00FF0000) >> 16] << 16) |
            (sbox[(word & 0x0000FF00) >> 8] << 8) |
            (sbox[(word & 0x000000FF)]);
    return word;
}

uint32_t RotWord(uint32_t word) {
    word = ((word & 0xFF000000) >> 24) |
            ((word & 0x00FF0000) << 8) |
            ((word & 0x0000FF00) << 8) |
            ((word & 0x000000FF) << 8);
    return word;
}

void AddRoundKey() {

}

void MixColumns() {

}

void ShiftRows() {

}

void SubBytes() {

}

void InvMixColumns() {

}

void InvShiftRows() {

}

void InvSubBytes() {

}