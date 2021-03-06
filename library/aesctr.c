// AES-NI ctr mode functions modified from strongswan 5.6.2

/*
 * Copyright (C) 2015 Martin Willi
 * Copyright (C) 2015 revosec AG
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

#if defined(__amd64__) || defined(__i386__) || defined(__aarch64__)

#include <string.h>

#define CTR_CRYPT_PARALLELISM 4
#define AES_BLOCK_SIZE 16

#if defined(__amd64__) || defined(__i386__)

#include <smmintrin.h>
#include <wmmintrin.h>
#define u128_t __m128i
#define load128(b) _mm_loadu_si128((void *)(b))
#define store128(b,n) _mm_storeu_si128((void *)(b), (n))
#define xor128(a,b) _mm_xor_si128(a,b)
#define aes_first(d,k) xor128(d,k)
#define aes_step(d,k) _mm_aesenc_si128(d,k)
#define aes_final(d,k1,k2) _mm_aesenclast_si128(_mm_aesenc_si128(d,k1),k2)
#define SWAP_VEC _mm_setr_epi8(15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0)
#define increment_be(x) \
    x = _mm_shuffle_epi8(x, SWAP_VEC); \
    x = _mm_add_epi64(x, _mm_set_epi32(0, 0, 0, 1)); \
    x = _mm_shuffle_epi8(x, SWAP_VEC)

#else

#include <arm_neon.h>
#define u128_t uint8x16_t
#define load128(b) vld1q_u8((uint8_t *)(b))
#define store128(b,n) vst1q_u8((uint8_t *)(b),n)
#define xor128(a,b) veorq_u8(a,b)
#define aes_first(d,k) aes_step(d,k)
#define aes_step(d,k) vaesmcq_u8(vaeseq_u8(d,k))
#define aes_final(d,k1,k2) veorq_u8(vaeseq_u8(d,k1),k2)
#define increment_be(x) \
    x = bswap128(x); \
    x = vreinterpretq_u8_u64(vaddq_u64(vreinterpretq_u64_u8(x), get_u64_one())); \
    x = bswap128(x)

static inline uint8x16_t bswap128(uint8x16_t x)
{
    uint64x2_t y = vreinterpretq_u64_u8(vrev64q_u8(x));
    uint64x2_t z = vcombine_u64(vget_high_u64(y), vget_low_u64(y));
    return vreinterpretq_u8_u64(z);
}

static inline uint64x2_t get_u64_one()
{
    static const uint32_t __attribute__((aligned(16))) data[4] = {1, 0, 0, 0};
    return vreinterpretq_u64_u32(vld1q_u32(data));
}

#endif

static void encrypt_ctr128(void *this_state, void *this_key,
                           size_t *nc_off, unsigned char stream_block[16],
                           size_t len, unsigned char *in, unsigned char *out);
static void encrypt_ctr192(void *this_state, void *this_key,
                           size_t *nc_off, unsigned char stream_block[16],
                           size_t len, unsigned char *in, unsigned char *out);
static void encrypt_ctr256(void *this_state, void *this_key,
                           size_t *nc_off, unsigned char stream_block[16],
                           size_t len, unsigned char *in, unsigned char *out);

void mbedtls_asm_aesni_ctr(unsigned char *rk, int nr, size_t length,
                           size_t *nc_off, unsigned char stream_block[16],
                           unsigned char nonce_counter[16],
                           unsigned char *input,
                           unsigned char *output)
{
    u128_t sk[15];
    int u, c;
    size_t n = *nc_off;

    if (n != 0) {
        for (; n < 16 && length > 0; n++, length--) {
            c = *input++;
            *output++ = (unsigned char)( c ^ stream_block[n] );
        }
    }

    if (length == 0) {
        n &= 0xf;
        *nc_off = n;
        return;
    }

    switch (nr) {
        case 10:
            for (u = 0; u <= 10; u++) {
                sk[u] = load128((void *)(rk + (u << 4)));
            }
            encrypt_ctr128(nonce_counter, sk, nc_off, stream_block, length, input, output);
            break;
        case 12:
            for (u = 0; u <= 12; u++) {
                sk[u] = load128((void *)(rk + (u << 4)));
            }
            encrypt_ctr192(nonce_counter, sk, nc_off, stream_block, length, input, output);
            break;
        case 14:
            for (u = 0; u <= 14; u++) {
                sk[u] = load128((void *)(rk + (u << 4)));
            }
            encrypt_ctr256(nonce_counter, sk, nc_off, stream_block, length, input, output);
            break;
    }
}

/**
 * AES-128 CTR encryption
 */
static void encrypt_ctr128(void *this_state, void *this_key,
                           size_t *nc_off, unsigned char stream_block[16],
                           size_t len, unsigned char *in, unsigned char *out)
{
    u128_t t1, t2, t3, t4;
    u128_t d1, d2, d3, d4;
    u128_t *ks, state, b, *bi, *bo;
    unsigned int i, blocks, pblocks, rem;

    state = load128((u128_t*)this_state);
    blocks = len / AES_BLOCK_SIZE;
    pblocks = blocks - (blocks % CTR_CRYPT_PARALLELISM);
    rem = len % AES_BLOCK_SIZE;
    *nc_off = rem;
    bi = (u128_t*)in;
    bo = (u128_t*)out;

    ks = (u128_t *)this_key;

    for (i = 0; i < pblocks; i += CTR_CRYPT_PARALLELISM)
    {
        d1 = load128(bi + i + 0);
        d2 = load128(bi + i + 1);
        d3 = load128(bi + i + 2);
        d4 = load128(bi + i + 3);

        t1 = aes_first(state, ks[0]);
        increment_be(state);
        t2 = aes_first(state, ks[0]);
        increment_be(state);
        t3 = aes_first(state, ks[0]);
        increment_be(state);
        t4 = aes_first(state, ks[0]);
        increment_be(state);

        t1 = aes_step(t1, ks[1]);
        t2 = aes_step(t2, ks[1]);
        t3 = aes_step(t3, ks[1]);
        t4 = aes_step(t4, ks[1]);
        t1 = aes_step(t1, ks[2]);
        t2 = aes_step(t2, ks[2]);
        t3 = aes_step(t3, ks[2]);
        t4 = aes_step(t4, ks[2]);
        t1 = aes_step(t1, ks[3]);
        t2 = aes_step(t2, ks[3]);
        t3 = aes_step(t3, ks[3]);
        t4 = aes_step(t4, ks[3]);
        t1 = aes_step(t1, ks[4]);
        t2 = aes_step(t2, ks[4]);
        t3 = aes_step(t3, ks[4]);
        t4 = aes_step(t4, ks[4]);
        t1 = aes_step(t1, ks[5]);
        t2 = aes_step(t2, ks[5]);
        t3 = aes_step(t3, ks[5]);
        t4 = aes_step(t4, ks[5]);
        t1 = aes_step(t1, ks[6]);
        t2 = aes_step(t2, ks[6]);
        t3 = aes_step(t3, ks[6]);
        t4 = aes_step(t4, ks[6]);
        t1 = aes_step(t1, ks[7]);
        t2 = aes_step(t2, ks[7]);
        t3 = aes_step(t3, ks[7]);
        t4 = aes_step(t4, ks[7]);
        t1 = aes_step(t1, ks[8]);
        t2 = aes_step(t2, ks[8]);
        t3 = aes_step(t3, ks[8]);
        t4 = aes_step(t4, ks[8]);

        t1 = aes_final(t1, ks[9], ks[10]);
        t2 = aes_final(t2, ks[9], ks[10]);
        t3 = aes_final(t3, ks[9], ks[10]);
        t4 = aes_final(t4, ks[9], ks[10]);
        t1 = xor128(t1, d1);
        t2 = xor128(t2, d2);
        t3 = xor128(t3, d3);
        t4 = xor128(t4, d4);
        store128(bo + i + 0, t1);
        store128(bo + i + 1, t2);
        store128(bo + i + 2, t3);
        store128(bo + i + 3, t4);
    }

    for (i = pblocks; i < blocks; i++)
    {
        d1 = load128(bi + i);

        t1 = aes_first(state, ks[0]);
        increment_be(state);

        t1 = aes_step(t1, ks[1]);
        t1 = aes_step(t1, ks[2]);
        t1 = aes_step(t1, ks[3]);
        t1 = aes_step(t1, ks[4]);
        t1 = aes_step(t1, ks[5]);
        t1 = aes_step(t1, ks[6]);
        t1 = aes_step(t1, ks[7]);
        t1 = aes_step(t1, ks[8]);

        t1 = aes_final(t1, ks[9], ks[10]);
        t1 = xor128(t1, d1);
        store128(bo + i, t1);
    }

    if (rem)
    {
        memset(&b, 0, sizeof(b));
        memcpy(&b, bi + blocks, rem);

        d1 = load128(&b);
        t1 = aes_first(state, ks[0]);
        increment_be(state);

        t1 = aes_step(t1, ks[1]);
        t1 = aes_step(t1, ks[2]);
        t1 = aes_step(t1, ks[3]);
        t1 = aes_step(t1, ks[4]);
        t1 = aes_step(t1, ks[5]);
        t1 = aes_step(t1, ks[6]);
        t1 = aes_step(t1, ks[7]);
        t1 = aes_step(t1, ks[8]);

        t1 = aes_final(t1, ks[9], ks[10]);
        store128((void *)stream_block, t1);
        t1 = xor128(t1, d1);
        store128(&b, t1);

        memcpy(bo + blocks, &b, rem);
    }

    store128(this_state, state);
}

/**
 * AES-192 CTR encryption
 */
static void encrypt_ctr192(void *this_state, void *this_key,
                           size_t *nc_off, unsigned char stream_block[16],
                           size_t len, unsigned char *in, unsigned char *out)
{
    u128_t t1, t2, t3, t4;
    u128_t d1, d2, d3, d4;
    u128_t *ks, state, b, *bi, *bo;
    unsigned int i, blocks, pblocks, rem;

    state = load128((u128_t*)this_state);
    blocks = len / AES_BLOCK_SIZE;
    pblocks = blocks - (blocks % CTR_CRYPT_PARALLELISM);
    rem = len % AES_BLOCK_SIZE;
    *nc_off = rem;
    bi = (u128_t*)in;
    bo = (u128_t*)out;

    ks = (u128_t *)this_key;

    for (i = 0; i < pblocks; i += CTR_CRYPT_PARALLELISM)
    {
        d1 = load128(bi + i + 0);
        d2 = load128(bi + i + 1);
        d3 = load128(bi + i + 2);
        d4 = load128(bi + i + 3);

        t1 = aes_first(state, ks[0]);
        increment_be(state);
        t2 = aes_first(state, ks[0]);
        increment_be(state);
        t3 = aes_first(state, ks[0]);
        increment_be(state);
        t4 = aes_first(state, ks[0]);
        increment_be(state);

        t1 = aes_step(t1, ks[1]);
        t2 = aes_step(t2, ks[1]);
        t3 = aes_step(t3, ks[1]);
        t4 = aes_step(t4, ks[1]);
        t1 = aes_step(t1, ks[2]);
        t2 = aes_step(t2, ks[2]);
        t3 = aes_step(t3, ks[2]);
        t4 = aes_step(t4, ks[2]);
        t1 = aes_step(t1, ks[3]);
        t2 = aes_step(t2, ks[3]);
        t3 = aes_step(t3, ks[3]);
        t4 = aes_step(t4, ks[3]);
        t1 = aes_step(t1, ks[4]);
        t2 = aes_step(t2, ks[4]);
        t3 = aes_step(t3, ks[4]);
        t4 = aes_step(t4, ks[4]);
        t1 = aes_step(t1, ks[5]);
        t2 = aes_step(t2, ks[5]);
        t3 = aes_step(t3, ks[5]);
        t4 = aes_step(t4, ks[5]);
        t1 = aes_step(t1, ks[6]);
        t2 = aes_step(t2, ks[6]);
        t3 = aes_step(t3, ks[6]);
        t4 = aes_step(t4, ks[6]);
        t1 = aes_step(t1, ks[7]);
        t2 = aes_step(t2, ks[7]);
        t3 = aes_step(t3, ks[7]);
        t4 = aes_step(t4, ks[7]);
        t1 = aes_step(t1, ks[8]);
        t2 = aes_step(t2, ks[8]);
        t3 = aes_step(t3, ks[8]);
        t4 = aes_step(t4, ks[8]);
        t1 = aes_step(t1, ks[9]);
        t2 = aes_step(t2, ks[9]);
        t3 = aes_step(t3, ks[9]);
        t4 = aes_step(t4, ks[9]);
        t1 = aes_step(t1, ks[10]);
        t2 = aes_step(t2, ks[10]);
        t3 = aes_step(t3, ks[10]);
        t4 = aes_step(t4, ks[10]);

        t1 = aes_final(t1, ks[11], ks[12]);
        t2 = aes_final(t2, ks[11], ks[12]);
        t3 = aes_final(t3, ks[11], ks[12]);
        t4 = aes_final(t4, ks[11], ks[12]);
        t1 = xor128(t1, d1);
        t2 = xor128(t2, d2);
        t3 = xor128(t3, d3);
        t4 = xor128(t4, d4);
        store128(bo + i + 0, t1);
        store128(bo + i + 1, t2);
        store128(bo + i + 2, t3);
        store128(bo + i + 3, t4);
    }

    for (i = pblocks; i < blocks; i++)
    {
        d1 = load128(bi + i);

        t1 = aes_first(state, ks[0]);
        increment_be(state);

        t1 = aes_step(t1, ks[1]);
        t1 = aes_step(t1, ks[2]);
        t1 = aes_step(t1, ks[3]);
        t1 = aes_step(t1, ks[4]);
        t1 = aes_step(t1, ks[5]);
        t1 = aes_step(t1, ks[6]);
        t1 = aes_step(t1, ks[7]);
        t1 = aes_step(t1, ks[8]);
        t1 = aes_step(t1, ks[9]);
        t1 = aes_step(t1, ks[10]);

        t1 = aes_final(t1, ks[11], ks[12]);
        t1 = xor128(t1, d1);
        store128(bo + i, t1);
    }

    if (rem)
    {
        memset(&b, 0, sizeof(b));
        memcpy(&b, bi + blocks, rem);

        d1 = load128(&b);
        t1 = aes_first(state, ks[0]);
        increment_be(state);

        t1 = aes_step(t1, ks[1]);
        t1 = aes_step(t1, ks[2]);
        t1 = aes_step(t1, ks[3]);
        t1 = aes_step(t1, ks[4]);
        t1 = aes_step(t1, ks[5]);
        t1 = aes_step(t1, ks[6]);
        t1 = aes_step(t1, ks[7]);
        t1 = aes_step(t1, ks[8]);
        t1 = aes_step(t1, ks[9]);
        t1 = aes_step(t1, ks[10]);

        t1 = aes_final(t1, ks[11], ks[12]);
        store128((void *)stream_block, t1);
        t1 = xor128(t1, d1);
        store128(&b, t1);

        memcpy(bo + blocks, &b, rem);
    }

    store128(this_state, state);
}

/**
 * AES-256 CTR encryption
 */
static void encrypt_ctr256(void *this_state, void *this_key,
                           size_t *nc_off, unsigned char stream_block[16],
                           size_t len, unsigned char *in, unsigned char *out)
{
    u128_t t1, t2, t3, t4;
    u128_t d1, d2, d3, d4;
    u128_t *ks, state, b, *bi, *bo;
    unsigned int i, blocks, pblocks, rem;

    state = load128((u128_t*)this_state);
    blocks = len / AES_BLOCK_SIZE;
    pblocks = blocks - (blocks % CTR_CRYPT_PARALLELISM);
    rem = len % AES_BLOCK_SIZE;
    *nc_off = rem;
    bi = (u128_t*)in;
    bo = (u128_t*)out;

    ks = (u128_t *)this_key;

    for (i = 0; i < pblocks; i += CTR_CRYPT_PARALLELISM)
    {
        d1 = load128(bi + i + 0);
        d2 = load128(bi + i + 1);
        d3 = load128(bi + i + 2);
        d4 = load128(bi + i + 3);

        t1 = aes_first(state, ks[0]);
        increment_be(state);
        t2 = aes_first(state, ks[0]);
        increment_be(state);
        t3 = aes_first(state, ks[0]);
        increment_be(state);
        t4 = aes_first(state, ks[0]);
        increment_be(state);

        t1 = aes_step(t1, ks[1]);
        t2 = aes_step(t2, ks[1]);
        t3 = aes_step(t3, ks[1]);
        t4 = aes_step(t4, ks[1]);
        t1 = aes_step(t1, ks[2]);
        t2 = aes_step(t2, ks[2]);
        t3 = aes_step(t3, ks[2]);
        t4 = aes_step(t4, ks[2]);
        t1 = aes_step(t1, ks[3]);
        t2 = aes_step(t2, ks[3]);
        t3 = aes_step(t3, ks[3]);
        t4 = aes_step(t4, ks[3]);
        t1 = aes_step(t1, ks[4]);
        t2 = aes_step(t2, ks[4]);
        t3 = aes_step(t3, ks[4]);
        t4 = aes_step(t4, ks[4]);
        t1 = aes_step(t1, ks[5]);
        t2 = aes_step(t2, ks[5]);
        t3 = aes_step(t3, ks[5]);
        t4 = aes_step(t4, ks[5]);
        t1 = aes_step(t1, ks[6]);
        t2 = aes_step(t2, ks[6]);
        t3 = aes_step(t3, ks[6]);
        t4 = aes_step(t4, ks[6]);
        t1 = aes_step(t1, ks[7]);
        t2 = aes_step(t2, ks[7]);
        t3 = aes_step(t3, ks[7]);
        t4 = aes_step(t4, ks[7]);
        t1 = aes_step(t1, ks[8]);
        t2 = aes_step(t2, ks[8]);
        t3 = aes_step(t3, ks[8]);
        t4 = aes_step(t4, ks[8]);
        t1 = aes_step(t1, ks[9]);
        t2 = aes_step(t2, ks[9]);
        t3 = aes_step(t3, ks[9]);
        t4 = aes_step(t4, ks[9]);
        t1 = aes_step(t1, ks[10]);
        t2 = aes_step(t2, ks[10]);
        t3 = aes_step(t3, ks[10]);
        t4 = aes_step(t4, ks[10]);
        t1 = aes_step(t1, ks[11]);
        t2 = aes_step(t2, ks[11]);
        t3 = aes_step(t3, ks[11]);
        t4 = aes_step(t4, ks[11]);
        t1 = aes_step(t1, ks[12]);
        t2 = aes_step(t2, ks[12]);
        t3 = aes_step(t3, ks[12]);
        t4 = aes_step(t4, ks[12]);

        t1 = aes_final(t1, ks[13], ks[14]);
        t2 = aes_final(t2, ks[13], ks[14]);
        t3 = aes_final(t3, ks[13], ks[14]);
        t4 = aes_final(t4, ks[13], ks[14]);
        t1 = xor128(t1, d1);
        t2 = xor128(t2, d2);
        t3 = xor128(t3, d3);
        t4 = xor128(t4, d4);
        store128(bo + i + 0, t1);
        store128(bo + i + 1, t2);
        store128(bo + i + 2, t3);
        store128(bo + i + 3, t4);
    }

    for (i = pblocks; i < blocks; i++)
    {
        d1 = load128(bi + i);

        t1 = aes_first(state, ks[0]);
        increment_be(state);

        t1 = aes_step(t1, ks[1]);
        t1 = aes_step(t1, ks[2]);
        t1 = aes_step(t1, ks[3]);
        t1 = aes_step(t1, ks[4]);
        t1 = aes_step(t1, ks[5]);
        t1 = aes_step(t1, ks[6]);
        t1 = aes_step(t1, ks[7]);
        t1 = aes_step(t1, ks[8]);
        t1 = aes_step(t1, ks[9]);
        t1 = aes_step(t1, ks[10]);
        t1 = aes_step(t1, ks[11]);
        t1 = aes_step(t1, ks[12]);

        t1 = aes_final(t1, ks[13], ks[14]);
        t1 = xor128(t1, d1);
        store128(bo + i, t1);
    }

    if (rem)
    {
        memset(&b, 0, sizeof(b));
        memcpy(&b, bi + blocks, rem);

        d1 = load128(&b);
        t1 = aes_first(state, ks[0]);
        increment_be(state);

        t1 = aes_step(t1, ks[1]);
        t1 = aes_step(t1, ks[2]);
        t1 = aes_step(t1, ks[3]);
        t1 = aes_step(t1, ks[4]);
        t1 = aes_step(t1, ks[5]);
        t1 = aes_step(t1, ks[6]);
        t1 = aes_step(t1, ks[7]);
        t1 = aes_step(t1, ks[8]);
        t1 = aes_step(t1, ks[9]);
        t1 = aes_step(t1, ks[10]);
        t1 = aes_step(t1, ks[11]);
        t1 = aes_step(t1, ks[12]);

        t1 = aes_final(t1, ks[13], ks[14]);
        store128((void *)stream_block, t1);
        t1 = xor128(t1, d1);
        store128(&b, t1);

        memcpy(bo + blocks, &b, rem);
    }

    store128(this_state, state);
}

#endif
