#ifndef __AES_H__
#define __AES_H__
#include "stdint.h"
#include "_aes.h"

typedef struct {
    AES_Key* key;
    AES_RoundKey* roundKey;
} AES_Ctx;

enum AES_KEY_SIZE {
    AES_KEY_128 = 4,
    AES_KEY_192 = 6,
    AES_KEY_256 = 8
};

AES_Ctx* AES_Init(enum AES_KEY_SIZE key_size, uint32_t* key);
void AES_Encrypt(AES_Ctx* ctx, uint32_t input[4], uint32_t output[4]);
#endif
