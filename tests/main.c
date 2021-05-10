#include <assert.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include "_aes.h"
#include "aes.h"

// TODO: Add GoogleTest framework
bool test_encrypt_128() {
    uint8_t input[16] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };
    uint32_t key[4] = { 0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f };
    uint8_t expected[16] = { 0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a };
    uint8_t output[16];
    AES_Ctx* ctx = AES_Init(AES_KEY_128, key);
    AES_Encrypt(ctx, input, output);
    for (int i = 0; i < 4; ++i) {
        if (output[i] != expected[i]) {
            printf("AES-128 encrypt test failed\n");
            AES_Finish(ctx);
            return false;
        }
    }
    printf("AES-128 encrypt test passed\n");
    AES_Finish(ctx);
    return true;
}

bool test_encrypt_192() {
    uint8_t input[16] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };
    uint32_t key[6] = { 0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f, 0x10111213, 0x14151617 };
    uint8_t expected[16] = { 0xdd, 0xa9, 0x7c, 0xa4, 0x86, 0x4c, 0xdf, 0xe0, 0x6e, 0xaf, 0x70, 0xa0, 0xec, 0x0d, 0x71, 0x91 };
    uint8_t output[16];
    AES_Ctx* ctx = AES_Init(AES_KEY_192, key);
    AES_Encrypt(ctx, input, output);
    for (int i = 0; i < 4; ++i) {
        if (output[i] != expected[i]) {
            printf("AES-192 encrypt test failed\n");
            AES_Finish(ctx);
            return false;
        }
    }
    printf("AES-192 encrypt test passed\n");
    AES_Finish(ctx);
    return true;
}

bool test_encrypt_256() {
    uint8_t input[16] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };
    uint32_t key[8] = { 0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f, 0x10111213, 0x14151617, 0x18191a1b, 0x1c1d1e1f };
    uint8_t expected[16] = { 0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf, 0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60, 0x89 };
    uint8_t output[16];
    AES_Ctx* ctx = AES_Init(AES_KEY_256, key);
    AES_Encrypt(ctx, input, output);
    for (int i = 0; i < 4; ++i) {
        if (output[i] != expected[i]) {
            printf("AES-256 encrypt test failed\n");
            AES_Finish(ctx);
            return false;
        }
    }
    printf("AES-256 encrypt test passed\n");
    AES_Finish(ctx);
    return true;
}

int main(int argc, char** argv) {
    bool passed = true;
    // Test encryption
    passed = test_encrypt_128();
    passed = test_encrypt_192();
    passed = test_encrypt_256();
    if (!passed)
        return 1;
    return 0;
}
