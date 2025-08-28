#pragma once

#include <stdlib.h>
#include <stdint.h>

#define QR_BLOCK_SIZE 64
#define QR_HASH_SIZE  32

uint8_t *qrhash_256(const uint8_t *string, int len);
uint8_t *qrhash_hmac256(const uint8_t *key, int key_len, const uint8_t *bytes, int bytes_len);

void DebugBinaryString(const uint8_t *binary, size_t len);
void DebugBinaryRawString(const uint8_t *binary, size_t len);
