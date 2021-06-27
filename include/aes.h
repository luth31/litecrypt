#ifndef __AES_H__
#define __AES_H__
#include "stdint.h"
#include "_aes.h"

#ifdef _MSC_VER
    #define LITECRYPT_API __declspec(dllexport)
#elif defined(__clang__) || defined(__GNUC__)
    #define LITECRYPT_API __attribute__((visibility("default")))
#endif

typedef struct {
    AES_Key* key;
    uint8_t rounds;
} AES_Ctx;

typedef struct {
    AES_Ctx aes;
    uint64_t nonce;
    uint64_t counter;
} AES_CTR_Ctx;

enum AES_KEY_SIZE {
    AES_KEY_128 = 4,
    AES_KEY_192 = 6,
    AES_KEY_256 = 8
};

LITECRYPT_API AES_Ctx* AES_Init(enum AES_KEY_SIZE key_size, uint32_t* key);
LITECRYPT_API AES_CTR_Ctx* AES_CTR_Init(enum AES_KEY_SIZE key_size, uint32_t* key, uint64_t nonce);
LITECRYPT_API void AES_GenCtrBlock(AES_CTR_Ctx* ctx, uint8_t output[16]);
LITECRYPT_API void AES_Encrypt(AES_Ctx* ctx, uint8_t input[16], uint8_t output[16]);
LITECRYPT_API void AES_Decrypt(AES_Ctx* ctx, uint8_t input[16], uint8_t output[16]);
LITECRYPT_API void AES_Finish(AES_Ctx* ctx);


#endif
