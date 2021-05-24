#include <assert.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include "_aes.h"
#include "aes.h"
#include <pthread.h>
#include <string.h>

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

bool test_decrypt_128() {
    uint8_t input[16] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };
    uint32_t key[4] = { 0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f };
    uint8_t output[16];
    AES_Ctx* ctx = AES_Init(AES_KEY_128, key);
    AES_Encrypt(ctx, input, output);
    AES_Decrypt(ctx, output, output);
    for (int i = 0; i < 4; ++i) {
        if (output[i] != input[i]) {
            printf("AES-128 decrypt test failed\n");
            AES_Finish(ctx);
            return false;
        }
    }
    printf("AES-128 decrypt test passed\n");
    AES_Finish(ctx);
    return true;
}

bool test_decrypt_192() {
    uint8_t input[16] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };
    uint32_t key[6] = { 0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f, 0x10111213, 0x14151617 };
    uint8_t output[16];
    AES_Ctx* ctx = AES_Init(AES_KEY_192, key);
    AES_Encrypt(ctx, input, output);
    AES_Decrypt(ctx, output, output);
    for (int i = 0; i < 4; ++i) {
        if (output[i] != input[i]) {
            printf("AES-192 decrypt test failed\n");
            AES_Finish(ctx);
            return false;
        }
    }
    printf("AES-192 decrypt test passed\n");
    AES_Finish(ctx);
    return true;
}

bool test_decrypt_256() {
    uint8_t input[16] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };
    uint32_t key[8] = { 0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f, 0x10111213, 0x14151617, 0x18191a1b, 0x1c1d1e1f };
    uint8_t output[16];
    AES_Ctx* ctx = AES_Init(AES_KEY_256, key);
    AES_Encrypt(ctx, input, output);
    AES_Decrypt(ctx, output, output);
    for (int i = 0; i < 4; ++i) {
        if (output[i] != input[i]) {
            printf("AES-256 decrypt test failed\n");
            AES_Finish(ctx);
            return false;
        }
    }
    printf("AES-256 decrypt test passed\n");
    AES_Finish(ctx);
    return true;
}

typedef struct {
    AES_Ctx* ctx;
    uint8_t* data;
} AES_MT_ENC_DATA;

void* parallel_encrypt_file(void* data) {
    uint64_t size;
    AES_MT_ENC_DATA* mt_data = (AES_MT_ENC_DATA*)data;
    uint8_t* enc_data = AES_Encrypt_MT(mt_data->ctx, mt_data->data, 128, &size);
    return (void*)enc_data;
}

void encrypt_file(int argc, char** argv) {
    FILE* test_file = fopen(argv[2], "r");
    char enc_filename[128];
    strcpy(enc_filename, argv[2]);
    strcat(enc_filename, ".aes");

    if (test_file == NULL) {
        printf("Couldn't open file!\n");
        return;
    }
    FILE* encrypted_file = fopen(enc_filename, "w+");
    if (encrypted_file == NULL) {
        printf("Couldn't create encrypted file!\n");
        return;
    }
    fseek(test_file, 0, SEEK_END);
    size_t size = ftell(test_file);
    fseek(test_file, 0, SEEK_SET);
    
    uint32_t key[4] = { 0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f };
    AES_Ctx* ctx = AES_Init(AES_KEY_128, key);

    pthread_t threads[4];
    AES_MT_ENC_DATA* mt_data = (AES_MT_ENC_DATA*)malloc(4 * sizeof(AES_MT_ENC_DATA));

    uint8_t* buffer = (uint8_t*)malloc(512 * sizeof(uint8_t));

    for (int i = 0; i < 4; ++i) {
        mt_data[i].ctx = ctx;
        mt_data[i].data = buffer + (128 * i);
    }

    uint64_t read_size;
    while ((read_size = fread(buffer, sizeof(uint8_t), 512, test_file)) > 0) {
        if (read_size < 512) {
            uint64_t enc_size;
            uint8_t* enc_buffer = AES_Encrypt_MT(ctx, buffer, read_size, &enc_size);
            fwrite(enc_buffer, enc_size, 1, encrypted_file);
            free(enc_buffer);
        }
        else {
            uint8_t* enc_buffer[4];

            pthread_create(&threads[0], NULL, parallel_encrypt_file, &mt_data[0]);
            pthread_create(&threads[1], NULL, parallel_encrypt_file, &mt_data[1]);
            pthread_create(&threads[2], NULL, parallel_encrypt_file, &mt_data[2]);
            pthread_create(&threads[3], NULL, parallel_encrypt_file, &mt_data[3]);

            pthread_join(threads[0], &enc_buffer[0]);
            pthread_join(threads[1], &enc_buffer[1]);
            pthread_join(threads[2], &enc_buffer[2]);
            pthread_join(threads[3], &enc_buffer[3]);
            for (int i = 0; i < 4; ++i) {
                fwrite(enc_buffer[i], 128, 1, encrypted_file);
                free(enc_buffer[i]);
            }
        }
    }
    free(mt_data);
    free(buffer);
    fclose(test_file);
    fclose(encrypted_file);
    AES_Finish(ctx);
}

int main(int argc, char** argv) {
    bool passed = true;
    // Test encryption
    /*passed = test_encrypt_128();
    passed = test_encrypt_192();
    passed = test_encrypt_256();
    
    passed = test_decrypt_128();
    passed = test_decrypt_192();
    passed = test_decrypt_256();*/
    if (argc < 2) {
        printf("Not enough arguments!\n");
        return 1;
    }
    if (strcmp(argv[1], "-e") == 0)
        encrypt_file(argc, argv);
    else if (strcmp(argv[1], "-d") == 0)
        //decrypt_file(argc, argv);
        printf("Decryption not yet implemented!\n");
    else {
        printf("Invalid operation!\n");
        return 1;
    }
    if (!passed)
        return 1;
    return 0;
}
