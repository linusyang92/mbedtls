// Wrapper for OpenSSL Assembly

#include "mbedtls/aesasm.h"
#include "mbedtls/aesarm.h"

#ifndef MBEDTLS_HAVE_ARM64
/*
 * AES-NI support detection routine
 */
static int aesni_supported()
{
#if defined(__i386__) || defined(__amd64__) || defined(__x86_64__)
    static int done = 0;
    static unsigned int c = 0;
    static int result = 0;

    if( ! done )
    {
        asm( "movl  $1, %%eax   \n\t"
             "cpuid             \n\t"
             : "=c" (c)
             :
             : "eax", "ebx", "edx" );
        done = 1;
        result = ( c & 0x02000000u ) != 0;
    }

    return result;
#else
    return 0;
#endif
}
#endif

static int hardaes_supported(void)
{
#if defined(MBEDTLS_HAVE_ARM64)
    return 1;
#else
    return aesni_supported();
#endif
}

int mbedtls_asm_supported(void)
{
    if (hardaes_supported()) {
        return MBEDTLS_AESASM_HAS_HARDAES;
    }
#if defined(MBEDTLS_AES_USE_ASM)
    return MBEDTLS_AESASM_HAS_ASM;
#else
    return 0;
#endif
}

#if defined(MBEDTLS_AES_USE_ASM)

#if MBEDTLS_AES_I386_WIN
int aesni_set_encrypt_key(const unsigned char *userKey, const int bits,
                        AES_KEY *key);
int aesni_set_decrypt_key(const unsigned char *userKey, const int bits,
                        AES_KEY *key);
void aesni_encrypt(const unsigned char *in, unsigned char *out,
                 const AES_KEY *key);
void aesni_decrypt(const unsigned char *in, unsigned char *out,
                 const AES_KEY *key);
#endif

int AES_set_encrypt_key(const unsigned char *userKey, const int bits,
                        AES_KEY *key);
int AES_set_decrypt_key(const unsigned char *userKey, const int bits,
                        AES_KEY *key);
void AES_encrypt(const unsigned char *in, unsigned char *out,
                 const AES_KEY *key);
void AES_decrypt(const unsigned char *in, unsigned char *out,
                 const AES_KEY *key);

static int (*set_encrypt_key)(const unsigned char *userKey, const int bits,
    AES_KEY *key) = AES_set_encrypt_key;
static int (*set_decrypt_key)(const unsigned char *userKey, const int bits,
    AES_KEY *key) = AES_set_decrypt_key;
static void (*encrypt)(const unsigned char *in, unsigned char *out,
    const AES_KEY *key) = AES_encrypt;
static void (*decrypt)(const unsigned char *in, unsigned char *out,
    const AES_KEY *key) = AES_decrypt;

static void aes_init()
{
    static int inited = 0;
    if (!inited) {
#if MBEDTLS_AES_I386_WIN
        if (hardaes_supported()) {
            set_encrypt_key = aesni_set_encrypt_key;
            set_decrypt_key = aesni_set_decrypt_key;
            encrypt = aesni_encrypt;
            decrypt = aesni_decrypt;
        }
#endif
        inited = 1;
    }
}

int mbedtls_asm_set_encrypt_key(const unsigned char *userKey, const int bits,
    AES_KEY *key)
{
    aes_init();
    return set_encrypt_key(userKey, bits, key);
}

int mbedtls_asm_set_decrypt_key(const unsigned char *userKey, const int bits,
    AES_KEY *key)
{
    aes_init();
    return set_decrypt_key(userKey, bits, key);
}

void mbedtls_asm_encrypt(const unsigned char *in, unsigned char *out,
    const AES_KEY *key)
{
    aes_init();
    encrypt(in, out, key);
}

void mbedtls_asm_decrypt(const unsigned char *in, unsigned char *out,
    const AES_KEY *key)
{
    aes_init();
    decrypt(in, out, key);
}

#endif

#if defined(__amd64__) || defined(__i386__)

#include <smmintrin.h>
#include <wmmintrin.h>

#define CTR_CRYPT_PARALLELISM 4
#define AES_BLOCK_SIZE 16

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
    __m128i sk[15];
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
                sk[u] = _mm_loadu_si128((void *)(rk + (u << 4)));
            }
            encrypt_ctr128(nonce_counter, sk, nc_off, stream_block, length, input, output);
            break;
        case 12:
            for (u = 0; u <= 12; u++) {
                sk[u] = _mm_loadu_si128((void *)(rk + (u << 4)));
            }
            encrypt_ctr192(nonce_counter, sk, nc_off, stream_block, length, input, output);
            break;
        case 14:
            for (u = 0; u <= 14; u++) {
                sk[u] = _mm_loadu_si128((void *)(rk + (u << 4)));
            }
            encrypt_ctr256(nonce_counter, sk, nc_off, stream_block, length, input, output);
            break;
    }
}

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

/**
 * Do big-endian increment on x
 */
static inline __m128i increment_be(__m128i x)
{
    __m128i swap;

    swap = _mm_setr_epi8(15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0);

    x = _mm_shuffle_epi8(x, swap);
    x = _mm_add_epi64(x, _mm_set_epi32(0, 0, 0, 1));
    x = _mm_shuffle_epi8(x, swap);

    return x;
}

/**
 * AES-128 CTR encryption
 */
static void encrypt_ctr128(void *this_state, void *this_key,
                           size_t *nc_off, unsigned char stream_block[16],
                           size_t len, unsigned char *in, unsigned char *out)
{
    __m128i t1, t2, t3, t4;
    __m128i d1, d2, d3, d4;
    __m128i *ks, state, b, *bi, *bo;
    unsigned int i, blocks, pblocks, rem;

    state = _mm_loadu_si128((__m128i*)this_state);
    blocks = len / AES_BLOCK_SIZE;
    pblocks = blocks - (blocks % CTR_CRYPT_PARALLELISM);
    rem = len % AES_BLOCK_SIZE;
    *nc_off = rem;
    bi = (__m128i*)in;
    bo = (__m128i*)out;

    ks = (__m128i *)this_key;

    for (i = 0; i < pblocks; i += CTR_CRYPT_PARALLELISM)
    {
        d1 = _mm_loadu_si128(bi + i + 0);
        d2 = _mm_loadu_si128(bi + i + 1);
        d3 = _mm_loadu_si128(bi + i + 2);
        d4 = _mm_loadu_si128(bi + i + 3);

        t1 = _mm_xor_si128(state, ks[0]);
        state = increment_be(state);
        t2 = _mm_xor_si128(state, ks[0]);
        state = increment_be(state);
        t3 = _mm_xor_si128(state, ks[0]);
        state = increment_be(state);
        t4 = _mm_xor_si128(state, ks[0]);
        state = increment_be(state);

        t1 = _mm_aesenc_si128(t1, ks[1]);
        t2 = _mm_aesenc_si128(t2, ks[1]);
        t3 = _mm_aesenc_si128(t3, ks[1]);
        t4 = _mm_aesenc_si128(t4, ks[1]);
        t1 = _mm_aesenc_si128(t1, ks[2]);
        t2 = _mm_aesenc_si128(t2, ks[2]);
        t3 = _mm_aesenc_si128(t3, ks[2]);
        t4 = _mm_aesenc_si128(t4, ks[2]);
        t1 = _mm_aesenc_si128(t1, ks[3]);
        t2 = _mm_aesenc_si128(t2, ks[3]);
        t3 = _mm_aesenc_si128(t3, ks[3]);
        t4 = _mm_aesenc_si128(t4, ks[3]);
        t1 = _mm_aesenc_si128(t1, ks[4]);
        t2 = _mm_aesenc_si128(t2, ks[4]);
        t3 = _mm_aesenc_si128(t3, ks[4]);
        t4 = _mm_aesenc_si128(t4, ks[4]);
        t1 = _mm_aesenc_si128(t1, ks[5]);
        t2 = _mm_aesenc_si128(t2, ks[5]);
        t3 = _mm_aesenc_si128(t3, ks[5]);
        t4 = _mm_aesenc_si128(t4, ks[5]);
        t1 = _mm_aesenc_si128(t1, ks[6]);
        t2 = _mm_aesenc_si128(t2, ks[6]);
        t3 = _mm_aesenc_si128(t3, ks[6]);
        t4 = _mm_aesenc_si128(t4, ks[6]);
        t1 = _mm_aesenc_si128(t1, ks[7]);
        t2 = _mm_aesenc_si128(t2, ks[7]);
        t3 = _mm_aesenc_si128(t3, ks[7]);
        t4 = _mm_aesenc_si128(t4, ks[7]);
        t1 = _mm_aesenc_si128(t1, ks[8]);
        t2 = _mm_aesenc_si128(t2, ks[8]);
        t3 = _mm_aesenc_si128(t3, ks[8]);
        t4 = _mm_aesenc_si128(t4, ks[8]);
        t1 = _mm_aesenc_si128(t1, ks[9]);
        t2 = _mm_aesenc_si128(t2, ks[9]);
        t3 = _mm_aesenc_si128(t3, ks[9]);
        t4 = _mm_aesenc_si128(t4, ks[9]);

        t1 = _mm_aesenclast_si128(t1, ks[10]);
        t2 = _mm_aesenclast_si128(t2, ks[10]);
        t3 = _mm_aesenclast_si128(t3, ks[10]);
        t4 = _mm_aesenclast_si128(t4, ks[10]);
        t1 = _mm_xor_si128(t1, d1);
        t2 = _mm_xor_si128(t2, d2);
        t3 = _mm_xor_si128(t3, d3);
        t4 = _mm_xor_si128(t4, d4);
        _mm_storeu_si128(bo + i + 0, t1);
        _mm_storeu_si128(bo + i + 1, t2);
        _mm_storeu_si128(bo + i + 2, t3);
        _mm_storeu_si128(bo + i + 3, t4);
    }

    for (i = pblocks; i < blocks; i++)
    {
        d1 = _mm_loadu_si128(bi + i);

        t1 = _mm_xor_si128(state, ks[0]);
        state = increment_be(state);

        t1 = _mm_aesenc_si128(t1, ks[1]);
        t1 = _mm_aesenc_si128(t1, ks[2]);
        t1 = _mm_aesenc_si128(t1, ks[3]);
        t1 = _mm_aesenc_si128(t1, ks[4]);
        t1 = _mm_aesenc_si128(t1, ks[5]);
        t1 = _mm_aesenc_si128(t1, ks[6]);
        t1 = _mm_aesenc_si128(t1, ks[7]);
        t1 = _mm_aesenc_si128(t1, ks[8]);
        t1 = _mm_aesenc_si128(t1, ks[9]);

        t1 = _mm_aesenclast_si128(t1, ks[10]);
        t1 = _mm_xor_si128(t1, d1);
        _mm_storeu_si128(bo + i, t1);
    }

    if (rem)
    {
        memset(&b, 0, sizeof(b));
        memcpy(&b, bi + blocks, rem);

        d1 = _mm_loadu_si128(&b);
        t1 = _mm_xor_si128(state, ks[0]);
        state = increment_be(state);

        t1 = _mm_aesenc_si128(t1, ks[1]);
        t1 = _mm_aesenc_si128(t1, ks[2]);
        t1 = _mm_aesenc_si128(t1, ks[3]);
        t1 = _mm_aesenc_si128(t1, ks[4]);
        t1 = _mm_aesenc_si128(t1, ks[5]);
        t1 = _mm_aesenc_si128(t1, ks[6]);
        t1 = _mm_aesenc_si128(t1, ks[7]);
        t1 = _mm_aesenc_si128(t1, ks[8]);
        t1 = _mm_aesenc_si128(t1, ks[9]);

        t1 = _mm_aesenclast_si128(t1, ks[10]);
        _mm_storeu_si128((void *)stream_block, t1);
        t1 = _mm_xor_si128(t1, d1);
        _mm_storeu_si128(&b, t1);

        memcpy(bo + blocks, &b, rem);
    }

    _mm_storeu_si128(this_state, state);
}

/**
 * AES-192 CTR encryption
 */
static void encrypt_ctr192(void *this_state, void *this_key,
                           size_t *nc_off, unsigned char stream_block[16],
                           size_t len, unsigned char *in, unsigned char *out)
{
    __m128i t1, t2, t3, t4;
    __m128i d1, d2, d3, d4;
    __m128i *ks, state, b, *bi, *bo;
    unsigned int i, blocks, pblocks, rem;

    state = _mm_loadu_si128((__m128i*)this_state);
    blocks = len / AES_BLOCK_SIZE;
    pblocks = blocks - (blocks % CTR_CRYPT_PARALLELISM);
    rem = len % AES_BLOCK_SIZE;
    *nc_off = rem;
    bi = (__m128i*)in;
    bo = (__m128i*)out;

    ks = (__m128i *)this_key;

    for (i = 0; i < pblocks; i += CTR_CRYPT_PARALLELISM)
    {
        d1 = _mm_loadu_si128(bi + i + 0);
        d2 = _mm_loadu_si128(bi + i + 1);
        d3 = _mm_loadu_si128(bi + i + 2);
        d4 = _mm_loadu_si128(bi + i + 3);

        t1 = _mm_xor_si128(state, ks[0]);
        state = increment_be(state);
        t2 = _mm_xor_si128(state, ks[0]);
        state = increment_be(state);
        t3 = _mm_xor_si128(state, ks[0]);
        state = increment_be(state);
        t4 = _mm_xor_si128(state, ks[0]);
        state = increment_be(state);

        t1 = _mm_aesenc_si128(t1, ks[1]);
        t2 = _mm_aesenc_si128(t2, ks[1]);
        t3 = _mm_aesenc_si128(t3, ks[1]);
        t4 = _mm_aesenc_si128(t4, ks[1]);
        t1 = _mm_aesenc_si128(t1, ks[2]);
        t2 = _mm_aesenc_si128(t2, ks[2]);
        t3 = _mm_aesenc_si128(t3, ks[2]);
        t4 = _mm_aesenc_si128(t4, ks[2]);
        t1 = _mm_aesenc_si128(t1, ks[3]);
        t2 = _mm_aesenc_si128(t2, ks[3]);
        t3 = _mm_aesenc_si128(t3, ks[3]);
        t4 = _mm_aesenc_si128(t4, ks[3]);
        t1 = _mm_aesenc_si128(t1, ks[4]);
        t2 = _mm_aesenc_si128(t2, ks[4]);
        t3 = _mm_aesenc_si128(t3, ks[4]);
        t4 = _mm_aesenc_si128(t4, ks[4]);
        t1 = _mm_aesenc_si128(t1, ks[5]);
        t2 = _mm_aesenc_si128(t2, ks[5]);
        t3 = _mm_aesenc_si128(t3, ks[5]);
        t4 = _mm_aesenc_si128(t4, ks[5]);
        t1 = _mm_aesenc_si128(t1, ks[6]);
        t2 = _mm_aesenc_si128(t2, ks[6]);
        t3 = _mm_aesenc_si128(t3, ks[6]);
        t4 = _mm_aesenc_si128(t4, ks[6]);
        t1 = _mm_aesenc_si128(t1, ks[7]);
        t2 = _mm_aesenc_si128(t2, ks[7]);
        t3 = _mm_aesenc_si128(t3, ks[7]);
        t4 = _mm_aesenc_si128(t4, ks[7]);
        t1 = _mm_aesenc_si128(t1, ks[8]);
        t2 = _mm_aesenc_si128(t2, ks[8]);
        t3 = _mm_aesenc_si128(t3, ks[8]);
        t4 = _mm_aesenc_si128(t4, ks[8]);
        t1 = _mm_aesenc_si128(t1, ks[9]);
        t2 = _mm_aesenc_si128(t2, ks[9]);
        t3 = _mm_aesenc_si128(t3, ks[9]);
        t4 = _mm_aesenc_si128(t4, ks[9]);
        t1 = _mm_aesenc_si128(t1, ks[10]);
        t2 = _mm_aesenc_si128(t2, ks[10]);
        t3 = _mm_aesenc_si128(t3, ks[10]);
        t4 = _mm_aesenc_si128(t4, ks[10]);
        t1 = _mm_aesenc_si128(t1, ks[11]);
        t2 = _mm_aesenc_si128(t2, ks[11]);
        t3 = _mm_aesenc_si128(t3, ks[11]);
        t4 = _mm_aesenc_si128(t4, ks[11]);

        t1 = _mm_aesenclast_si128(t1, ks[12]);
        t2 = _mm_aesenclast_si128(t2, ks[12]);
        t3 = _mm_aesenclast_si128(t3, ks[12]);
        t4 = _mm_aesenclast_si128(t4, ks[12]);
        t1 = _mm_xor_si128(t1, d1);
        t2 = _mm_xor_si128(t2, d2);
        t3 = _mm_xor_si128(t3, d3);
        t4 = _mm_xor_si128(t4, d4);
        _mm_storeu_si128(bo + i + 0, t1);
        _mm_storeu_si128(bo + i + 1, t2);
        _mm_storeu_si128(bo + i + 2, t3);
        _mm_storeu_si128(bo + i + 3, t4);
    }

    for (i = pblocks; i < blocks; i++)
    {
        d1 = _mm_loadu_si128(bi + i);

        t1 = _mm_xor_si128(state, ks[0]);
        state = increment_be(state);

        t1 = _mm_aesenc_si128(t1, ks[1]);
        t1 = _mm_aesenc_si128(t1, ks[2]);
        t1 = _mm_aesenc_si128(t1, ks[3]);
        t1 = _mm_aesenc_si128(t1, ks[4]);
        t1 = _mm_aesenc_si128(t1, ks[5]);
        t1 = _mm_aesenc_si128(t1, ks[6]);
        t1 = _mm_aesenc_si128(t1, ks[7]);
        t1 = _mm_aesenc_si128(t1, ks[8]);
        t1 = _mm_aesenc_si128(t1, ks[9]);
        t1 = _mm_aesenc_si128(t1, ks[10]);
        t1 = _mm_aesenc_si128(t1, ks[11]);

        t1 = _mm_aesenclast_si128(t1, ks[12]);
        t1 = _mm_xor_si128(t1, d1);
        _mm_storeu_si128(bo + i, t1);
    }

    if (rem)
    {
        memset(&b, 0, sizeof(b));
        memcpy(&b, bi + blocks, rem);

        d1 = _mm_loadu_si128(&b);
        t1 = _mm_xor_si128(state, ks[0]);
        state = increment_be(state);

        t1 = _mm_aesenc_si128(t1, ks[1]);
        t1 = _mm_aesenc_si128(t1, ks[2]);
        t1 = _mm_aesenc_si128(t1, ks[3]);
        t1 = _mm_aesenc_si128(t1, ks[4]);
        t1 = _mm_aesenc_si128(t1, ks[5]);
        t1 = _mm_aesenc_si128(t1, ks[6]);
        t1 = _mm_aesenc_si128(t1, ks[7]);
        t1 = _mm_aesenc_si128(t1, ks[8]);
        t1 = _mm_aesenc_si128(t1, ks[9]);
        t1 = _mm_aesenc_si128(t1, ks[10]);
        t1 = _mm_aesenc_si128(t1, ks[11]);

        t1 = _mm_aesenclast_si128(t1, ks[12]);
        _mm_storeu_si128((void *)stream_block, t1);
        t1 = _mm_xor_si128(t1, d1);
        _mm_storeu_si128(&b, t1);

        memcpy(bo + blocks, &b, rem);
    }

    _mm_storeu_si128(this_state, state);
}

/**
 * AES-256 CTR encryption
 */
static void encrypt_ctr256(void *this_state, void *this_key,
                           size_t *nc_off, unsigned char stream_block[16],
                           size_t len, unsigned char *in, unsigned char *out)
{
    __m128i t1, t2, t3, t4;
    __m128i d1, d2, d3, d4;
    __m128i *ks, state, b, *bi, *bo;
    unsigned int i, blocks, pblocks, rem;

    state = _mm_loadu_si128((__m128i*)this_state);
    blocks = len / AES_BLOCK_SIZE;
    pblocks = blocks - (blocks % CTR_CRYPT_PARALLELISM);
    rem = len % AES_BLOCK_SIZE;
    *nc_off = rem;
    bi = (__m128i*)in;
    bo = (__m128i*)out;

    ks = (__m128i *)this_key;

    for (i = 0; i < pblocks; i += CTR_CRYPT_PARALLELISM)
    {
        d1 = _mm_loadu_si128(bi + i + 0);
        d2 = _mm_loadu_si128(bi + i + 1);
        d3 = _mm_loadu_si128(bi + i + 2);
        d4 = _mm_loadu_si128(bi + i + 3);

        t1 = _mm_xor_si128(state, ks[0]);
        state = increment_be(state);
        t2 = _mm_xor_si128(state, ks[0]);
        state = increment_be(state);
        t3 = _mm_xor_si128(state, ks[0]);
        state = increment_be(state);
        t4 = _mm_xor_si128(state, ks[0]);
        state = increment_be(state);

        t1 = _mm_aesenc_si128(t1, ks[1]);
        t2 = _mm_aesenc_si128(t2, ks[1]);
        t3 = _mm_aesenc_si128(t3, ks[1]);
        t4 = _mm_aesenc_si128(t4, ks[1]);
        t1 = _mm_aesenc_si128(t1, ks[2]);
        t2 = _mm_aesenc_si128(t2, ks[2]);
        t3 = _mm_aesenc_si128(t3, ks[2]);
        t4 = _mm_aesenc_si128(t4, ks[2]);
        t1 = _mm_aesenc_si128(t1, ks[3]);
        t2 = _mm_aesenc_si128(t2, ks[3]);
        t3 = _mm_aesenc_si128(t3, ks[3]);
        t4 = _mm_aesenc_si128(t4, ks[3]);
        t1 = _mm_aesenc_si128(t1, ks[4]);
        t2 = _mm_aesenc_si128(t2, ks[4]);
        t3 = _mm_aesenc_si128(t3, ks[4]);
        t4 = _mm_aesenc_si128(t4, ks[4]);
        t1 = _mm_aesenc_si128(t1, ks[5]);
        t2 = _mm_aesenc_si128(t2, ks[5]);
        t3 = _mm_aesenc_si128(t3, ks[5]);
        t4 = _mm_aesenc_si128(t4, ks[5]);
        t1 = _mm_aesenc_si128(t1, ks[6]);
        t2 = _mm_aesenc_si128(t2, ks[6]);
        t3 = _mm_aesenc_si128(t3, ks[6]);
        t4 = _mm_aesenc_si128(t4, ks[6]);
        t1 = _mm_aesenc_si128(t1, ks[7]);
        t2 = _mm_aesenc_si128(t2, ks[7]);
        t3 = _mm_aesenc_si128(t3, ks[7]);
        t4 = _mm_aesenc_si128(t4, ks[7]);
        t1 = _mm_aesenc_si128(t1, ks[8]);
        t2 = _mm_aesenc_si128(t2, ks[8]);
        t3 = _mm_aesenc_si128(t3, ks[8]);
        t4 = _mm_aesenc_si128(t4, ks[8]);
        t1 = _mm_aesenc_si128(t1, ks[9]);
        t2 = _mm_aesenc_si128(t2, ks[9]);
        t3 = _mm_aesenc_si128(t3, ks[9]);
        t4 = _mm_aesenc_si128(t4, ks[9]);
        t1 = _mm_aesenc_si128(t1, ks[10]);
        t2 = _mm_aesenc_si128(t2, ks[10]);
        t3 = _mm_aesenc_si128(t3, ks[10]);
        t4 = _mm_aesenc_si128(t4, ks[10]);
        t1 = _mm_aesenc_si128(t1, ks[11]);
        t2 = _mm_aesenc_si128(t2, ks[11]);
        t3 = _mm_aesenc_si128(t3, ks[11]);
        t4 = _mm_aesenc_si128(t4, ks[11]);
        t1 = _mm_aesenc_si128(t1, ks[12]);
        t2 = _mm_aesenc_si128(t2, ks[12]);
        t3 = _mm_aesenc_si128(t3, ks[12]);
        t4 = _mm_aesenc_si128(t4, ks[12]);
        t1 = _mm_aesenc_si128(t1, ks[13]);
        t2 = _mm_aesenc_si128(t2, ks[13]);
        t3 = _mm_aesenc_si128(t3, ks[13]);
        t4 = _mm_aesenc_si128(t4, ks[13]);

        t1 = _mm_aesenclast_si128(t1, ks[14]);
        t2 = _mm_aesenclast_si128(t2, ks[14]);
        t3 = _mm_aesenclast_si128(t3, ks[14]);
        t4 = _mm_aesenclast_si128(t4, ks[14]);
        t1 = _mm_xor_si128(t1, d1);
        t2 = _mm_xor_si128(t2, d2);
        t3 = _mm_xor_si128(t3, d3);
        t4 = _mm_xor_si128(t4, d4);
        _mm_storeu_si128(bo + i + 0, t1);
        _mm_storeu_si128(bo + i + 1, t2);
        _mm_storeu_si128(bo + i + 2, t3);
        _mm_storeu_si128(bo + i + 3, t4);
    }

    for (i = pblocks; i < blocks; i++)
    {
        d1 = _mm_loadu_si128(bi + i);

        t1 = _mm_xor_si128(state, ks[0]);
        state = increment_be(state);

        t1 = _mm_aesenc_si128(t1, ks[1]);
        t1 = _mm_aesenc_si128(t1, ks[2]);
        t1 = _mm_aesenc_si128(t1, ks[3]);
        t1 = _mm_aesenc_si128(t1, ks[4]);
        t1 = _mm_aesenc_si128(t1, ks[5]);
        t1 = _mm_aesenc_si128(t1, ks[6]);
        t1 = _mm_aesenc_si128(t1, ks[7]);
        t1 = _mm_aesenc_si128(t1, ks[8]);
        t1 = _mm_aesenc_si128(t1, ks[9]);
        t1 = _mm_aesenc_si128(t1, ks[10]);
        t1 = _mm_aesenc_si128(t1, ks[11]);
        t1 = _mm_aesenc_si128(t1, ks[12]);
        t1 = _mm_aesenc_si128(t1, ks[13]);

        t1 = _mm_aesenclast_si128(t1, ks[14]);
        t1 = _mm_xor_si128(t1, d1);
        _mm_storeu_si128(bo + i, t1);
    }

    if (rem)
    {
        memset(&b, 0, sizeof(b));
        memcpy(&b, bi + blocks, rem);

        d1 = _mm_loadu_si128(&b);
        t1 = _mm_xor_si128(state, ks[0]);
        state = increment_be(state);

        t1 = _mm_aesenc_si128(t1, ks[1]);
        t1 = _mm_aesenc_si128(t1, ks[2]);
        t1 = _mm_aesenc_si128(t1, ks[3]);
        t1 = _mm_aesenc_si128(t1, ks[4]);
        t1 = _mm_aesenc_si128(t1, ks[5]);
        t1 = _mm_aesenc_si128(t1, ks[6]);
        t1 = _mm_aesenc_si128(t1, ks[7]);
        t1 = _mm_aesenc_si128(t1, ks[8]);
        t1 = _mm_aesenc_si128(t1, ks[9]);
        t1 = _mm_aesenc_si128(t1, ks[10]);
        t1 = _mm_aesenc_si128(t1, ks[11]);
        t1 = _mm_aesenc_si128(t1, ks[12]);
        t1 = _mm_aesenc_si128(t1, ks[13]);

        t1 = _mm_aesenclast_si128(t1, ks[14]);
        _mm_storeu_si128((void *)stream_block, t1);
        t1 = _mm_xor_si128(t1, d1);
        _mm_storeu_si128(&b, t1);

        memcpy(bo + blocks, &b, rem);
    }

    _mm_storeu_si128(this_state, state);
}

#endif
