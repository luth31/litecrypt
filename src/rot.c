#include "_rot.h"

uint32_t rotl_u32(uint32_t value, uint8_t times) {
    return (value << times) | (value >> (32 - times));
}