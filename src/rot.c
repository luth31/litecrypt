#include "_rot.h"

uint8_t rotl_u8(uint8_t value, uint8_t times) {
    return (value << times) | (value >> (8 - times));
}

uint8_t rotr_u8(uint8_t value, uint8_t times) {
    return (value >> times) | (value << (8 - times));
}
