#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>

#include "qrhash256.h"

#define LIGHT_ROUNDS   3
#define HEAVY_ROUNDS   3
#define QUARTER_ROUNDS 3

#define WORDS_SIZE 16
#define CONSTANTS_SIZE 24

#define ROTL32(v, n) ((v << n) | (v >> (32 - n)))
#define ROTL32DP(v, a, b) ROTL32(v, ((a + b) % (19)) + 5)

/* stores 32 ints in Little Endian */
/* pretty beefy hash | change number of rounds in HashRoundAll */
/* custom hmac implementation (padding is changed) */

static const uint32_t constants[CONSTANTS_SIZE] = {
    0x14fe67e1, 0x36c08b32, 0x1dc36716, 0x1e949545, 
    0xed4b27d,  0x7dfcca31, 0x689b415,  0xc46edf6, 
    0x7a2c1f7c, 0x70e3a822, 0x39f399be, 0x17db893c, 
    0x61abfc0a, 0x60c9d358, 0x3242774d, 0x17628af7, 
    0x17871058, 0x7014420c, 0x5c1d3e0d, 0x1cca6499, 
    0x1a613223, 0x75f2db23, 0x3a6bb8c8, 0x6847b911,
};

static void HashRemix32Int(uint32_t *a, uint32_t *b, uint32_t *c);

static inline uint32_t LoadLE32(const uint8_t *src) {
    return ((uint32_t)src[0])       |
           ((uint32_t)src[1] << 8)  |
           ((uint32_t)src[2] << 16) |
           ((uint32_t)src[3] << 24);
}

static inline uint32_t LoadPLE32(const uint8_t *src, uint8_t len) {
    uint32_t rd = 0;

    for(int i = 0; i < len && i < sizeof(uint32_t); i++)
        rd |= (uint32_t)(src[i]) << (i * 8);

    return rd;
}

static inline void StoreLE32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v);
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

static void HashHeavyQuarterMix(uint32_t *a, uint32_t *b, uint32_t *c, uint32_t *d) {
    /* mix diagonally */
    HashRemix32Int(a, b, c);
    HashRemix32Int(b, c, d);
    HashRemix32Int(c, d, a);
    HashRemix32Int(d, a, b);
}

static void HashQuarterRound(uint32_t *a, uint32_t *b, uint32_t *c, uint32_t *d) {
    *a += *b; *b ^= *d; *b = ROTL32DP(*b, *a, *d); *a = ROTL32DP(*a, *b, *d);
    *c += *d; *a ^= *c; *d = ROTL32DP(*d, *b, *d); *c = ROTL32DP(*c, *c, *a);
    *a += *b; *c ^= *d; *b = ROTL32DP(*b, *a, *a);  *a = ROTL32DP(*a, *b, *c);
    *c += *d; *a ^= *b; *d = ROTL32DP(*d, *c, *c);  *c = ROTL32DP(*c, *d, *a);
}

static void HashHeavyQuarterRound(uint32_t *a, uint32_t *b, uint32_t *c, uint32_t *d) {
    HashHeavyQuarterMix(a, b, c, d);
    HashQuarterRound(a, b, c, d);
}

static void HashLightAdd(uint32_t words[WORDS_SIZE]) {
    for(int i = 0; i < WORDS_SIZE; i++)
        words[i] += (words[(i + 1) % WORDS_SIZE] << 16) | ((words[(i + 2) % WORDS_SIZE]) & 0xFFFF);
}

static void HashRemix32Int(uint32_t *a, uint32_t *b, uint32_t *c) {
    *a *= *c;
    *a ^= *b;
    *a += (*c + *b);
    *a  = ROTL32DP(*a, (*c ^ *b), (*b | *c));
    *a ^= *c << 15;
    *a ^= *b >> 15;
}

static void HashHeavyRound(uint32_t *a, uint32_t *b) {
    *a += *b; *a += (constants[*b % CONSTANTS_SIZE] ^ *b); 
    *a  = ROTL32(*a, 13);
    *b += *a; *b += (constants[*a % CONSTANTS_SIZE] ^ *a); 
    *b  = ROTL32(*b, 14);
    *a ^= *b; 
    *b *= ROTL32(*b, 15); 
    *a  = ROTL32(*a, 26);
    *b ^= *a; 
    *b *= ROTL32(*a, 11); 
    *b  = ROTL32(*b, 23);
}

static void HashRoundAll(uint32_t state[WORDS_SIZE]) {
    for(int i = 0; i < HEAVY_ROUNDS; i++) {
        HashHeavyRound(&state[0],  &state[5]);
        HashHeavyRound(&state[1],  &state[6]);
        HashHeavyRound(&state[2],  &state[7]);
        HashHeavyRound(&state[3],  &state[4]);

        HashHeavyRound(&state[4],  &state[9]);
        HashHeavyRound(&state[5],  &state[10]);
        HashHeavyRound(&state[6],  &state[11]);
        HashHeavyRound(&state[7],  &state[8]);

        HashHeavyRound(&state[8],  &state[13]);
        HashHeavyRound(&state[9],  &state[14]);
        HashHeavyRound(&state[10], &state[15]);
        HashHeavyRound(&state[11], &state[12]);

        HashHeavyRound(&state[12], &state[1]);
        HashHeavyRound(&state[13], &state[2]);
        HashHeavyRound(&state[14], &state[3]);
        HashHeavyRound(&state[15], &state[0]);
    }

    for(int i = 0; i < QUARTER_ROUNDS; i++) {
        /* columns */
        HashHeavyQuarterRound(&state[0], &state[4], &state[8], &state[12]);
        HashHeavyQuarterRound(&state[1], &state[5], &state[9], &state[13]);
        HashHeavyQuarterRound(&state[2], &state[6], &state[10], &state[14]);
        HashHeavyQuarterRound(&state[3], &state[7], &state[11], &state[15]);

        /* diaganol*/
        HashHeavyQuarterRound(&state[0], &state[5], &state[10], &state[15]);
        HashHeavyQuarterRound(&state[1], &state[6], &state[11], &state[12]);
        HashHeavyQuarterRound(&state[2], &state[7], &state[8],  &state[13]);
        HashHeavyQuarterRound(&state[3], &state[4], &state[9],  &state[14]);
    }

    for(int i = 0; i < LIGHT_ROUNDS; i++)
        HashLightAdd(state);
}

static void HashState(uint32_t words[WORDS_SIZE], uint32_t out[WORDS_SIZE]) {
    memcpy(out, words, QR_BLOCK_SIZE);
    HashRoundAll(out);
}

static void HashCompressOutput(uint32_t words[WORDS_SIZE], uint8_t out[QR_HASH_SIZE]) {
    for (int i = 0; i < QR_HASH_SIZE / 4; i++) {
        uint32_t compressed = ROTL32(words[i], 17) ^ (words[i + 8] + constants[words[i] % CONSTANTS_SIZE]); /* mix words that would be unused */

        /* add to output while mixing it */
        StoreLE32(out + (i * 4), compressed);
    }
}

uint8_t *qrhash_256(const uint8_t *string, int len) {
    int offset = 0;
    int block_size = 0;

    uint32_t state[WORDS_SIZE] = {
        0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
        0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
        0xC1059ED8, 0x367CD507, 0x3070DD17, 0xF70E5939,
        0xFFC00B31, 0x68581511, 0x64F98FA7, 0xBEFA4FA4
    };

    uint32_t blocks[WORDS_SIZE] = {0};
    uint8_t *out = calloc(1, QR_HASH_SIZE);

    while(offset < len) {
        block_size = (len - offset) < QR_BLOCK_SIZE ? (len - offset) : QR_BLOCK_SIZE;

        memset(blocks, 0, QR_BLOCK_SIZE);
        for(int i = 0; i < QR_BLOCK_SIZE / 4; i++) {
            int coff = offset + (i * 4);
            int remaining = len - coff;

            if(remaining >= 4)
                blocks[i] = LoadLE32(string + coff);
            else if(remaining > 0)
                blocks[i] = LoadPLE32(string + coff, remaining);
            else
                blocks[i] = 0;
        }

        for(int i = 0; i < WORDS_SIZE; i++)
            state[i] ^= blocks[i];

        HashState(state, state);

        offset += QR_BLOCK_SIZE;
    }

    /* ensure avalanche */
    state[0] ^= len;
    state[3] ^= len;
    state[7] ^= len;
    state[11] ^= len;
    state[15] ^= len;

    HashState(state, state);
    HashCompressOutput(state, out);
    return out;
}

uint8_t *qrhash_hmac256(const uint8_t *key, int key_len, const uint8_t *bytes, int bytes_len) {
    uint8_t key_block[QR_BLOCK_SIZE]   = {0};
    uint8_t out_padding[QR_BLOCK_SIZE] = {0};
    uint8_t in_padding[QR_BLOCK_SIZE]  = {0};

    if(key_len > QR_BLOCK_SIZE) {
        uint8_t *key_hash = qrhash_256(key, key_len);
        memcpy(key_block, key_hash, QR_HASH_SIZE);
        free(key_hash);
    } else {
        memcpy(key_block, key, key_len);
    }

    for(int i = 0; i < QR_BLOCK_SIZE; i++) {
        out_padding[i] = key_block[i] ^ 0x5C;
        in_padding[i]  = key_block[i] ^ 0x36;
    }

    uint8_t *inner_data = calloc(1, QR_BLOCK_SIZE + bytes_len);
    memcpy(inner_data, in_padding, QR_BLOCK_SIZE);
    memcpy(inner_data + QR_BLOCK_SIZE, bytes, bytes_len);

    uint8_t *inner_hash = qrhash_256(inner_data, QR_BLOCK_SIZE + bytes_len);
    
    uint8_t outer_data[QR_BLOCK_SIZE + QR_HASH_SIZE] = {0};
    memcpy(outer_data, out_padding, QR_BLOCK_SIZE);
    memcpy(outer_data + QR_BLOCK_SIZE, inner_hash, QR_HASH_SIZE);

    uint8_t *hmac_hash = qrhash_256(outer_data, QR_BLOCK_SIZE + QR_HASH_SIZE);

    free(inner_hash);
    free(inner_data);

    return hmac_hash;
}

void DebugBinaryString(const uint8_t *binary, size_t len) {
    for(int i = 0; i < len; i++)
        printf("\\x%02x", ((uint8_t *)binary)[i]);

    printf("\r\n");
}

void DebugBinaryRawString(const uint8_t *binary, size_t len) {
    for(int i = 0; i < len; i++)
        printf("%c", binary[i]);

    printf("\r\n");
}

int main(int argc, char **argv) {
    char *key = strdup(argv[1]);
    char *data = strdup(argv[2]);

    int key_len = strlen(key);
    int data_len = strlen(data);

    printf("key=(%s) key_len=%d data=(%s) data_len=%d\r\n", key, key_len, data, data_len);

    char *opt_hash = qrhash_hmac256(key, key_len, data, data_len);

    DebugBinaryString(opt_hash, QR_HASH_SIZE);
    DebugBinaryRawString(opt_hash, QR_HASH_SIZE);
}

