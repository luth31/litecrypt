#include "aes.h"
#include "_aes.h"
#include "stdio.h"
#include "stdlib.h"
#include "string.h"

AES_Ctx* AES_Init(enum AES_KEY_SIZE key_size, uint32_t* key) {
    AES_Ctx* ctx = (AES_Ctx*)malloc(sizeof(AES_Ctx));
    ctx->key = (AES_Key*)malloc(sizeof(AES_Key));
    ctx->key->size = key_size;
    ctx->key->data = (uint32_t*)malloc(key_size * sizeof(uint32_t));
    memcpy(ctx->key->data, key, key_size * sizeof(uint32_t));

    ctx->roundKey = (AES_RoundKey*)malloc(sizeof(AES_RoundKey));
    switch (key_size) {
        case AES_KEY_128:
            ctx->roundKey->rounds = 10;
            break;
        case AES_KEY_192:
            ctx->roundKey->rounds = 12;
            break;
        case AES_KEY_256:
            ctx->roundKey->rounds = 14;
            break;
        default:
            perror("Invalid key size!");
            exit(1);
            break;
    }
    ctx->roundKey->size = 4 * (ctx->roundKey->rounds + 1);
    ctx->roundKey->data = (uint32_t*)malloc(ctx->roundKey->size * sizeof(uint32_t));
    ExpandKey(ctx->key, ctx->roundKey);
    return ctx;
}

void ExpandKey(AES_Key* key, AES_RoundKey* rkey) {
    int i;
    for (i = 0; i < key->size; ++i) {
        rkey->data[i] = key->data[i];
    }
    uint32_t tmp;
    while (i < 4 * (rkey->rounds + 1)) {
        tmp = rkey->data[i-1];
        if (i % key->size == 0)
            tmp = SubWord(RotWord(tmp)) ^ Rcon[i/key->size];
        else if (key->size > 6 && i % key->size == 4)
            tmp = SubWord(tmp);
        rkey->data[i] = rkey->data[i - key->size] ^ tmp;
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