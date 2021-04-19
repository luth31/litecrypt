#include "aes.h"
#include "_aes.h"
#include "stdio.h"

void test_private() {
    printf("Private function()\n");
}

void test_public() {
    test_private();
    printf("Public function()\n");
}
