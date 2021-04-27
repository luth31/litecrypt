#ifndef __AES_H__
#define __AES_H__
#include "stdint.h"
#include "_aes.h"

typedef struct {
    AES_Key* key;
    AES_RoundKey* roundKey;
    uint8_t rounds;
} AES_Ctx;


void AES_Init(AES_Ctx* ctx, AES_Key* key);
uint32_t* AES_Encrypt(AES_Ctx* ctx, uint32_t data);
uint32_t* AES_Decrypt(AES_Ctx* ctx, uint32_t data);
#endif