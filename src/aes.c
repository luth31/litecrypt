#include "aes.h"
#include "_aes.h"
#include "stdio.h"
#include "stdlib.h"
#include "string.h"
#include "_rot.h"

AES_Ctx* AES_Init(enum AES_KEY_SIZE key_size, uint32_t* key) {
    AES_Ctx* ctx = (AES_Ctx*)malloc(sizeof(AES_Ctx));
    ctx->key = (AES_Key*)malloc(sizeof(AES_Key));
    ctx->key->size = key_size;
    switch (key_size) {
        case AES_KEY_128:
            ctx->rounds = 10;
            break;
        case AES_KEY_192:
            ctx->rounds = 12;
            break;
        case AES_KEY_256:
            ctx->rounds = 14;
            break;
        default:
            perror("Invalid key size!");
            exit(1);
            break;
    }
    ctx->key->state = (AES_State*)malloc(sizeof(AES_State) * (ctx->rounds + 1));
    ExpandKey(ctx->key, ctx->rounds, key);
    return ctx;
}

void AES_Encrypt(AES_Ctx* ctx, uint8_t input[16], uint8_t output[16]) {
    AES_State state;
    for (int i = 0; i < 4; ++i)
        for (int j = 0; j < 4; ++j)
            state.data[i][j] = input[i + j * 4];
    Cipher(&state, ctx->key, ctx->rounds);
    for (int i = 0; i < 4; ++i)
        for (int j = 0; j < 4; ++j)
            output[i + j * 4] = state.data[i][j];
}

void AES_Finish(AES_Ctx* ctx) {
    free(ctx->key->state);
    free(ctx->key);
    free(ctx);
}

void Cipher(AES_State* state, AES_Key* key, uint8_t rounds) {
    AddRoundKey(state, key, 0);
    SubBytes(state);
    ShiftRows(state);
    MixColumns(state);
    AddRoundKey(state, key, 1);
    SubBytes(state);
    ShiftRows(state);
    MixColumns(state);
    AddRoundKey(state, key, 2);
    SubBytes(state);
    ShiftRows(state);
    MixColumns(state);
    AddRoundKey(state, key, 3);
    SubBytes(state);
    ShiftRows(state);
    MixColumns(state);
    AddRoundKey(state, key, 4);
    SubBytes(state);
    ShiftRows(state);
    MixColumns(state);
    AddRoundKey(state, key, 5);
    SubBytes(state);
    ShiftRows(state);
    MixColumns(state);
    AddRoundKey(state, key, 6);
    SubBytes(state);
    ShiftRows(state);
    MixColumns(state);
    AddRoundKey(state, key, 7);
    SubBytes(state);
    ShiftRows(state);
    MixColumns(state);
    AddRoundKey(state, key, 8);
    SubBytes(state);
    ShiftRows(state);
    MixColumns(state);
    AddRoundKey(state, key, 9);
    if (key->size > AES_KEY_128) {
        SubBytes(state);
        ShiftRows(state);
        MixColumns(state);
        AddRoundKey(state, key, 10);
        SubBytes(state);
        ShiftRows(state);
        MixColumns(state);
        AddRoundKey(state, key, 11);
        if (key->size > AES_KEY_192) {
            SubBytes(state);
            ShiftRows(state);
            MixColumns(state);
            AddRoundKey(state, key, 12);
            SubBytes(state);
            ShiftRows(state);
            MixColumns(state);
            AddRoundKey(state, key, 13);
        }
    }
    SubBytes(state);
    ShiftRows(state);
    AddRoundKey(state, key, rounds);
}

void InvCipher(AES_State* state, AES_Key* key, uint8_t rounds) {
    AddRoundKey(state, key, rounds);
    InvShiftRows(state);
    InvSubBytes(state);
    AddRoundKey(state, key, rounds - 1);
    InvMixColumns(state);
    InvShiftRows(state);
    InvSubBytes(state);
    AddRoundKey(state, key, rounds - 2);
    InvMixColumns(state);
    InvShiftRows(state);
    InvSubBytes(state);
    AddRoundKey(state, key, rounds - 3);
    InvMixColumns(state);
    InvShiftRows(state);
    InvSubBytes(state);
    AddRoundKey(state, key, rounds - 4);
    InvMixColumns(state);
    InvShiftRows(state);
    InvSubBytes(state);
    AddRoundKey(state, key, rounds - 5);
    InvMixColumns(state);
    InvShiftRows(state);
    InvSubBytes(state);
    AddRoundKey(state, key, rounds - 6);
    InvMixColumns(state);
    InvShiftRows(state);
    InvSubBytes(state);
    AddRoundKey(state, key, rounds - 7);
    InvMixColumns(state);
    InvShiftRows(state);
    InvSubBytes(state);
    AddRoundKey(state, key, rounds - 8);
    InvMixColumns(state);
    InvShiftRows(state);
    InvSubBytes(state);
    AddRoundKey(state, key, rounds - 9);
    InvMixColumns(state);
    if (key->size > AES_KEY_128) {
        InvShiftRows(state);
        InvSubBytes(state);
        AddRoundKey(state, key, rounds - 10);
        InvMixColumns(state);
        InvShiftRows(state);
        InvSubBytes(state);
        AddRoundKey(state, key, rounds - 11);
        InvMixColumns(state);
        if (key->size > AES_KEY_192) {
            InvShiftRows(state);
            InvSubBytes(state);
            AddRoundKey(state, key, rounds - 12);
            InvMixColumns(state);
            InvShiftRows(state);
            InvSubBytes(state);
            AddRoundKey(state, key, rounds - 13);
            InvMixColumns(state);
        }
    }
    InvShiftRows(state);
    InvSubBytes(state);
    AddRoundKey(state, key, 0);
}

void ExpandKey(AES_Key* expanded_key, uint8_t rounds, uint32_t* key) {
    int i;
    uint32_t* rkey = (uint32_t*)malloc(4 * (rounds + 1) * sizeof(uint32_t));
    for (i = 0; i < expanded_key->size; ++i) {
        rkey[i] = key[i];
    }
    uint32_t tmp;
    while (i < 4 * (rounds + 1)) {
        tmp = rkey[i-1];
        if (i % expanded_key->size == 0)
            tmp = SubWord(rotl_u32(tmp, 8)) ^ Rcon[i/expanded_key->size];
        else if (expanded_key->size > 6 && i % expanded_key->size == 4)
            tmp = SubWord(tmp);
        rkey[i] = rkey[i - expanded_key->size] ^ tmp;
        ++i;

    }
    for (int round = 0; round < rounds + 1; ++round)
        for (int col = 0; col < 4; ++col) {
            expanded_key->state[round].data[0][col] = rkey[round * 4 + col] >> 24;
            expanded_key->state[round].data[1][col] = rkey[round * 4 + col] >> 16;
            expanded_key->state[round].data[2][col] = rkey[round * 4 + col] >> 8;
            expanded_key->state[round].data[3][col] = rkey[round * 4 + col];
    }
    free(rkey);
}

void AddRoundKey(AES_State* state, AES_Key* key, uint8_t round) {
    state->data[0][0] ^= key->state[round].data[0][0];
    state->data[0][1] ^= key->state[round].data[0][1];
    state->data[0][2] ^= key->state[round].data[0][2];
    state->data[0][3] ^= key->state[round].data[0][3];

    state->data[1][0] ^= key->state[round].data[1][0];
    state->data[1][1] ^= key->state[round].data[1][1];
    state->data[1][2] ^= key->state[round].data[1][2];
    state->data[1][3] ^= key->state[round].data[1][3];

    state->data[2][0] ^= key->state[round].data[2][0];
    state->data[2][1] ^= key->state[round].data[2][1];
    state->data[2][2] ^= key->state[round].data[2][2];
    state->data[2][3] ^= key->state[round].data[2][3];

    state->data[3][0] ^= key->state[round].data[3][0];
    state->data[3][1] ^= key->state[round].data[3][1];
    state->data[3][2] ^= key->state[round].data[3][2];
    state->data[3][3] ^= key->state[round].data[3][3];
}

void ShiftRows(AES_State* state) {
    uint32_t tmp;
    // Second row
    tmp = state->data[1][3];
    state->data[1][3] = state->data[1][0];
    state->data[1][0] = state->data[1][1];
    state->data[1][1] = state->data[1][2];
    state->data[1][2] = tmp;
    // Third row
    tmp = state->data[2][3];
    state->data[2][3] = state->data[2][1];
    state->data[2][1] = tmp;
    tmp = state->data[2][2];
    state->data[2][2] = state->data[2][0];
    state->data[2][0] = tmp;
    // Fourth row
    tmp = state->data[3][3];
    state->data[3][3] = state->data[3][2];
    state->data[3][2] = state->data[3][1];
    state->data[3][1] = state->data[3][0];
    state->data[3][0] = tmp;
}

void SubBytes(AES_State* state) {
    state->data[0][0] = sbox[state->data[0][0]];
    state->data[0][1] = sbox[state->data[0][1]];
    state->data[0][2] = sbox[state->data[0][2]];
    state->data[0][3] = sbox[state->data[0][3]];

    state->data[1][0] = sbox[state->data[1][0]];
    state->data[1][1] = sbox[state->data[1][1]];
    state->data[1][2] = sbox[state->data[1][2]];
    state->data[1][3] = sbox[state->data[1][3]];

    state->data[2][0] = sbox[state->data[2][0]];
    state->data[2][1] = sbox[state->data[2][1]];
    state->data[2][2] = sbox[state->data[2][2]];
    state->data[2][3] = sbox[state->data[2][3]];

    state->data[3][0] = sbox[state->data[3][0]];
    state->data[3][1] = sbox[state->data[3][1]];
    state->data[3][2] = sbox[state->data[3][2]];
    state->data[3][3] = sbox[state->data[3][3]];
}

void MixColumns(AES_State* state) {
    uint8_t tmp[4][4];
    // First column
    tmp[0][0] = mixcol_mul_2[state->data[0][0]] ^ mixcol_mul_3[state->data[1][0]] ^ state->data[2][0] ^ state->data[3][0];
    tmp[1][0] = state->data[0][0] ^ mixcol_mul_2[state->data[1][0]] ^ mixcol_mul_3[state->data[2][0]] ^ state->data[3][0];
    tmp[2][0] = state->data[0][0] ^ state->data[1][0] ^ mixcol_mul_2[state->data[2][0]] ^ mixcol_mul_3[state->data[3][0]];
    tmp[3][0] = mixcol_mul_3[state->data[0][0]] ^ state->data[1][0] ^ state->data[2][0] ^ mixcol_mul_2[state->data[3][0]];
    // Second column
    tmp[0][1] = mixcol_mul_2[state->data[0][1]] ^ mixcol_mul_3[state->data[1][1]] ^ state->data[2][1] ^ state->data[3][1];
    tmp[1][1] = state->data[0][1] ^ mixcol_mul_2[state->data[1][1]] ^ mixcol_mul_3[state->data[2][1]] ^ state->data[3][1];
    tmp[2][1] = state->data[0][1] ^ state->data[1][1] ^ mixcol_mul_2[state->data[2][1]] ^ mixcol_mul_3[state->data[3][1]];
    tmp[3][1] = mixcol_mul_3[state->data[0][1]] ^ state->data[1][1] ^ state->data[2][1] ^ mixcol_mul_2[state->data[3][1]];
    // Third column
    tmp[0][2] = mixcol_mul_2[state->data[0][2]] ^ mixcol_mul_3[state->data[1][2]] ^ state->data[2][2] ^ state->data[3][2];
    tmp[1][2] = state->data[0][2] ^ mixcol_mul_2[state->data[1][2]] ^ mixcol_mul_3[state->data[2][2]] ^ state->data[3][2];
    tmp[2][2] = state->data[0][2] ^ state->data[1][2] ^ mixcol_mul_2[state->data[2][2]] ^ mixcol_mul_3[state->data[3][2]];
    tmp[3][2] = mixcol_mul_3[state->data[0][2]] ^ state->data[1][2] ^ state->data[2][2] ^ mixcol_mul_2[state->data[3][2]];
    // Fourth column
    tmp[0][3] = mixcol_mul_2[state->data[0][3]] ^ mixcol_mul_3[state->data[1][3]] ^ state->data[2][3] ^ state->data[3][3];
    tmp[1][3] = state->data[0][3] ^ mixcol_mul_2[state->data[1][3]] ^ mixcol_mul_3[state->data[2][3]] ^ state->data[3][3];
    tmp[2][3] = state->data[0][3] ^ state->data[1][3] ^ mixcol_mul_2[state->data[2][3]] ^ mixcol_mul_3[state->data[3][3]];
    tmp[3][3] = mixcol_mul_3[state->data[0][3]] ^ state->data[1][3] ^ state->data[2][3] ^ mixcol_mul_2[state->data[3][3]];
    memcpy(state->data, tmp, 16);
}

uint32_t SubWord(uint32_t word) {
    word = (sbox[(word & 0xFF000000) >> 24] << 24) |
            (sbox[(word & 0x00FF0000) >> 16] << 16) |
            (sbox[(word & 0x0000FF00) >> 8] << 8) |
            (sbox[(word & 0x000000FF)]);
    return word;
}
