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

void AES_Encrypt(AES_Ctx* ctx, uint32_t input[4], uint32_t output[4]) {
    AES_State* state = (AES_State*)malloc(sizeof(AES_State));
    state->word[0] = input[0];
    state->word[1] = input[1];
    state->word[2] = input[2];
    state->word[3] = input[3];
    Cipher(state, ctx->roundKey);
    memcpy(output, state->word, 4 * sizeof(uint32_t));
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

void Cipher(AES_State* state, AES_RoundKey* key) {
    AES_State* temp_state = (AES_State*)malloc(sizeof(AES_State));
    temp_state->word[0] = state->word[0];
    temp_state->word[1] = state->word[1];
    temp_state->word[2] = state->word[2];
    temp_state->word[3] = state->word[3];
    AddRoundKey(temp_state, key, 0);
    for (int i = 1; i < key->rounds; ++i) {
        SubBytes(temp_state);;
        ShiftRows(temp_state);
        MixColumns(temp_state);
        AddRoundKey(temp_state, key, i);
    }
    SubBytes(temp_state);
    ShiftRows(temp_state);
    AddRoundKey(temp_state, key, key->rounds);
    state->word[0] = temp_state->word[0];
    state->word[1] = temp_state->word[1];
    state->word[2] = temp_state->word[2];
    state->word[3] = temp_state->word[3];
}

void AddRoundKey(AES_State* state, AES_RoundKey* key, uint8_t round) {
    state->word[0] ^= key->data[round * 4 + 0];
    state->word[1] ^= key->data[round * 4 + 1];
    state->word[2] ^= key->data[round * 4 + 2];
    state->word[3] ^= key->data[round * 4 + 3];
}

void MixColumns(AES_State* state) {
    for (int i = 0; i < 4; ++i) {
        uint8_t col[4];
        uint8_t col_copy[4];
        col_copy[0] = state->word[i] >> 24;
        col_copy[1] = state->word[i] >> 16;
        col_copy[2] = state->word[i] >> 8;
        col_copy[3] = state->word[i];
        col[0] = mixcol_mul_2[col_copy[0]] ^ mixcol_mul_3[col_copy[1]] ^ col_copy[2] ^ col_copy[3];
        col[1] = col_copy[0] ^ mixcol_mul_2[col_copy[1]] ^ mixcol_mul_3[col_copy[2]] ^ col_copy[3];
        col[2] = col_copy[0] ^ col_copy[1] ^ mixcol_mul_2[col_copy[2]] ^ mixcol_mul_3[col_copy[3]];
        col[3] = mixcol_mul_3[col_copy[0]] ^ col_copy[1] ^ col_copy[2] ^ mixcol_mul_2[col_copy[3]];
        state->word[i] = (col[0] << 24) | (col[1] << 16) | (col[2] << 8) | (col[3]);
    }
}

void ShiftRows(AES_State* state) {
    uint32_t tmp;
    // Second row
    tmp = state->word[3] & 0x00FF0000;
    state->word[3] = (state->word[3] & 0xFF00FFFF) | (state->word[0] & 0x00FF0000);
    state->word[0] = (state->word[0] & 0xFF00FFFF) | (state->word[1] & 0x00FF0000);
    state->word[1] = (state->word[1] & 0xFF00FFFF) | (state->word[2] & 0x00FF0000);
    state->word[2] = (state->word[2] & 0xFF00FFFF) | (tmp);
    // Third row
    tmp = state->word[3] & 0x0000FF00;
    state->word[3] = (state->word[3] & 0xFFFF00FF) | (state->word[1] & 0x0000FF00);
    state->word[1] = (state->word[1] & 0xFFFF00FF) | tmp;
    tmp = state->word[2] & 0x0000FF00;
    state->word[2] = (state->word[2] & 0xFFFF00FF) | (state->word[0] & 0x0000FF00);
    state->word[0] = (state->word[0] & 0xFFFF00FF) | tmp;
    // Third row
    tmp = state->word[3] & 0x000000FF;
    state->word[3] = (state->word[3] & 0xFFFFFF00) | (state->word[2] & 0x000000FF);
    state->word[2] = (state->word[2] & 0xFFFFFF00) | (state->word[1] & 0x000000FF);
    state->word[1] = (state->word[1] & 0xFFFFFF00) | (state->word[0] & 0x000000FF);
    state->word[0] = (state->word[0] & 0xFFFFFF00) | tmp;
}

void SubBytes(AES_State* state) {
    state->word[0] = SubWord(state->word[0]);
    state->word[1] = SubWord(state->word[1]);
    state->word[2] = SubWord(state->word[2]);
    state->word[3] = SubWord(state->word[3]);
}

void InvMixColumns() {

}

void InvShiftRows() {

}

void InvSubBytes() {

}
