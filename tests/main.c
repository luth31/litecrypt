#include <assert.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include "_aes.h"
#include "aes.h"

// TODO: Add GoogleTest framework
void test_key_schedule_128() {
    AES_Ctx* ctx_128;
    uint32_t key_128[4] = { 0x2b7e1516, 0x28aed2a6, 0xabf71588, 0x09cf4f3c };
    uint32_t expected[44] = { 0x2b7e1516, 0x28aed2a6, 0xabf71588, 0x09cf4f3c, 0xa0fafe17, 0x88542cb1, 0x23a33939, 0x2a6c7605, 0xf2c295f2, 0x7a96b943, 0x5935807a, 0x7359f67f,0x3d80477d, 0x4716fe3e, 0x1e237e44, 0x6d7a883b, 0xef44a541, 0xa8525b7f, 0xb671253b, 0xdb0bad00, 0xd4d1c6f8, 0x7c839d87, 0xcaf2b8bc, 0x11f915bc, 0x6d88a37a, 0x110b3efd, 0xdbf98641, 0xca0093fd, 0x4e54f70e, 0x5f5fc9f3, 0x84a64fb2, 0x4ea6dc4f, 0xead27321, 0xb58dbad2, 0x312bf560, 0x7f8d292f, 0xac7766f3, 0x19fadc21, 0x28d12941, 0x575c006e, 0xd014f9a8, 0xc9ee2589, 0xe13f0cc8, 0xb6630ca6 };
    ctx_128 = AES_Init(AES_KEY_128, key_128);
    for (int i = 0; i < ctx_128->roundKey->size; ++i) {
        assert(ctx_128->roundKey->data[i] == expected[i]);
    }
    printf("AES-128 key schedule test passed\n");
}

void test_key_schedule_192() {
    AES_Ctx* ctx_192;
    uint32_t key_192[6] = { 0x8e73b0f7, 0xda0e6452, 0xc810f32b, 0x809079e5, 0x62f8ead2, 0x522c6b7b };
    uint32_t expected[52] = { 0x8e73b0f7, 0xda0e6452, 0xc810f32b, 0x809079e5, 0x62f8ead2, 0x522c6b7b, 0xfe0c91f7, 0x2402f5a5, 0xec12068e, 0x6c827f6b, 0x0e7a95b9, 0x5c56fec2, 0x4db7b4bd, 0x69b54118, 0x85a74796, 0xe92538fd, 0xe75fad44, 0xbb095386, 0x485af057, 0x21efb14f, 0xa448f6d9, 0x4d6dce24, 0xaa326360, 0x113b30e6, 0xa25e7ed5, 0x83b1cf9a, 0x27f93943, 0x6a94f767, 0xc0a69407, 0xd19da4e1, 0xec1786eb, 0x6fa64971, 0x485f7032, 0x22cb8755, 0xe26d1352, 0x33f0b7b3, 0x40beeb28, 0x2f18a259, 0x6747d26b, 0x458c553e, 0xa7e1466c, 0x9411f1df, 0x821f750a, 0xad07d753, 0xca400538, 0x8fcc5006, 0x282d166a, 0xbc3ce7b5, 0xe98ba06f, 0x448c773c, 0x8ecc7204, 0x01002202 };
    ctx_192 = AES_Init(AES_KEY_192, key_192);
    for (int i = 0; i < ctx_192->roundKey->size; ++i) {
        assert(ctx_192->roundKey->data[i] == expected[i]);
    }
    printf("AES-192 key schedule test passed\n");
}

void test_key_schedule_256() {
    AES_Ctx* ctx_256;
    uint32_t key_256[8] = { 0x603deb10, 0x15ca71be, 0x2b73aef0, 0x857d7781, 0x1f352c07, 0x3b6108d7, 0x2d9810a3, 0x0914dff4 };
    uint32_t expected[60] = { 0x603deb10, 0x15ca71be, 0x2b73aef0, 0x857d7781, 0x1f352c07, 0x3b6108d7, 0x2d9810a3, 0x0914dff4, 0x9ba35411, 0x8e6925af, 0xa51a8b5f, 0x2067fcde, 0xa8b09c1a, 0x93d194cd, 0xbe49846e, 0xb75d5b9a, 0xd59aecb8, 0x5bf3c917, 0xfee94248, 0xde8ebe96, 0xb5a9328a, 0x2678a647, 0x98312229, 0x2f6c79b3, 0x812c81ad, 0xdadf48ba, 0x24360af2, 0xfab8b464, 0x98c5bfc9, 0xbebd198e, 0x268c3ba7, 0x09e04214, 0x68007bac, 0xb2df3316, 0x96e939e4, 0x6c518d80, 0xc814e204, 0x76a9fb8a, 0x5025c02d, 0x59c58239, 0xde136967, 0x6ccc5a71, 0xfa256395, 0x9674ee15, 0x5886ca5d, 0x2e2f31d7, 0x7e0af1fa, 0x27cf73c3, 0x749c47ab, 0x18501dda, 0xe2757e4f, 0x7401905a, 0xcafaaae3, 0xe4d59b34, 0x9adf6ace, 0xbd10190d, 0xfe4890d1, 0xe6188d0b, 0x046df344, 0x706c631e };
    ctx_256 = AES_Init(AES_KEY_256, key_256);
    for (int i = 0; i < ctx_256->roundKey->size; ++i) {
        assert(ctx_256->roundKey->data[i] == expected[i]);
    }
    printf("AES-256 key schedule test passed\n");
}

void test_encrypt_128() {
    uint32_t input[4] = { 0x00112233, 0x44556677, 0x8899aabb, 0xccddeeff };
    uint32_t key[4] = { 0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f };
    uint32_t expected[4] = { 0x69c4e0d8, 0x6a7b0430, 0xd8cdb780, 0x70b4c55a };
    uint32_t output[4];
    AES_Ctx* ctx = AES_Init(AES_KEY_128, key);
    AES_Encrypt(ctx, input, output);
    for (int i = 0; i < 4; ++i) {
        assert(output[i] == expected[i]);
    }
    printf("AES-128 encrypt test passed\n");
}

void test_encrypt_192() {
    uint32_t input[4] = { 0x00112233, 0x44556677, 0x8899aabb, 0xccddeeff };
    uint32_t key[6] = { 0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f, 0x10111213, 0x14151617 };
    uint32_t expected[4] = { 0xdda97ca4, 0x864cdfe0, 0x6eaf70a0, 0xec0d7191 };
    uint32_t output[4];
    AES_Ctx* ctx = AES_Init(AES_KEY_192, key);
    AES_Encrypt(ctx, input, output);
    for (int i = 0; i < 4; ++i) {
        assert(output[i] == expected[i]);
    }
    printf("AES-192 encrypt test passed\n");
}

void test_encrypt_256() {
    uint32_t input[4] = { 0x00112233, 0x44556677, 0x8899aabb, 0xccddeeff };
    uint32_t key[8] = { 0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f, 0x10111213, 0x14151617, 0x18191a1b, 0x1c1d1e1f };
    uint32_t expected[4] = { 0x8ea2b7ca, 0x516745bf, 0xeafc4990, 0x4b496089 };
    uint32_t output[4];
    AES_Ctx* ctx = AES_Init(AES_KEY_256, key);
    AES_Encrypt(ctx, input, output);
    for (int i = 0; i < 4; ++i) {
        assert(output[i] == expected[i]);
    }
    printf("AES-256 encrypt test passed\n");
}

int main(int argc, char** argv) {
    // Test key schedule
    test_key_schedule_128();
    test_key_schedule_192();
    test_key_schedule_256();
    
    // Test encryption
    test_encrypt_128();
    test_encrypt_192();
    test_encrypt_256();
    
    return 0;
}
