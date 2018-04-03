/*
 * This file is adapted from https://github.com/CriticalBlue/mbedtls
 */

/*
 *  ARMv8-A Cryptography Extension AES support functions
 *
 *  Copyright (C) 2016, CriticalBlue Limited, All Rights Reserved
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_AESARM_C)

#include "mbedtls/aesarm.h"

#include <string.h>

#ifndef asm
#define asm __asm
#endif

#if defined(MBEDTLS_HAVE_ARM64)

#include <arm_neon.h>

/*
 * AES armv8 AES-ECB block en(de)cryption
 */
int mbedtls_aesarm_crypt_ecb( mbedtls_aes_context *ctx,
                              int mode,
                              const unsigned char input[16],
                              unsigned char output[16] )
{
    int i;
    uint8x16_t state_vec, roundkey_vec;
    uint8_t *RK = (uint8_t*)ctx->rk;

    // Load input and round key into into their vectors
    state_vec = vld1q_u8( input );

    if ( mode == MBEDTLS_AES_ENCRYPT )
    {
        // Initial AddRoundKey is in the loop due to AES instruction always doing AddRoundKey first
        for( i = 0; i < ctx->nr - 1; i++ )
        {
            // Load Round Key
            roundkey_vec = vld1q_u8( RK );
            // Forward (AESE) round (AddRoundKey, SubBytes and ShiftRows)
            state_vec = vaeseq_u8( state_vec, roundkey_vec );
            // Mix Columns (AESMC)
            state_vec = vaesmcq_u8( state_vec );
            // Move pointer ready to load next round key
            RK += 16;
        }

        // Final Forward (AESE) round (AddRoundKey, SubBytes and ShiftRows). No Mix columns
        roundkey_vec = vld1q_u8( RK ); /* RK already moved in loop */
        state_vec = vaeseq_u8( state_vec, roundkey_vec );
    }
    else
    {
        // Initial AddRoundKey is in the loop due to AES instruction always doing AddRoundKey first
        for( i = 0; i < ctx->nr - 1; i++ )
        {
            // Load Round Key
            roundkey_vec = vld1q_u8( RK );
            // Reverse (AESD) round (AddRoundKey, SubBytes and ShiftRows)
            state_vec = vaesdq_u8( state_vec, roundkey_vec );
            // Inverse Mix Columns (AESIMC)
            state_vec = vaesimcq_u8( state_vec );
            // Move pointer ready to load next round key
            RK += 16;
        }

        // Final Reverse (AESD) round (AddRoundKey, SubBytes and ShiftRows). No Mix columns
        roundkey_vec = vld1q_u8( RK ); /* RK already moved in loop */
        state_vec = vaesdq_u8( state_vec, roundkey_vec );
    }

    // Manually apply final Add RoundKey step (EOR)
    RK += 16;
    roundkey_vec = vld1q_u8( RK );
    state_vec = veorq_u8( state_vec, roundkey_vec );

    // Write results back to output array
    vst1q_u8( output, state_vec );

    return( 0 );
}

void mbedtls_aesarm_gcm_mult( unsigned char c[16],
                              const unsigned char a[16],
                              const unsigned char b[16] )
{
    // GCM's GF(2^128) polynomial basis is x^128 + x^7 + x^2 + x + 1
    const uint64x2_t base = { 0, 0x86 };            // note missing LS bit

    register uint8x16_t vc asm( "v0" );             // named registers
    register uint8x16_t va asm( "v1" );             // (to avoid conflict)
    register uint8x16_t vb asm( "v2" );
    register uint64x2_t vp asm( "v3" );

    va = vld1q_u8( a );                             // load inputs
    vb = vld1q_u8( b );
    vp = base;

    asm (
        "rbit    %1.16b, %1.16b             \n\t"   // reverse bit order
        "rbit    %2.16b, %2.16b             \n\t"
        "pmull2  %0.1q,  %1.2d,  %2.2d      \n\t"   // v0 = a.hi * b.hi
        "pmull2  v4.1q,  %0.2d,  %3.2d      \n\t"   // mul v0 by x^64, reduce
        "ext     %0.16b, %0.16b, %0.16b, #8 \n\t"
        "eor     %0.16b, %0.16b, v4.16b     \n\t"
        "ext     v5.16b, %2.16b, %2.16b, #8 \n\t"   // (swap hi and lo in b)
        "pmull   v4.1q,  %1.1d,  v5.1d      \n\t"   // v0 ^= a.lo * b.hi
        "eor     %0.16b, %0.16b, v4.16b     \n\t"
        "pmull2  v4.1q,  %1.2d,  v5.2d      \n\t"   // v0 ^= a.hi * b.lo
        "eor     %0.16b, %0.16b, v4.16b     \n\t"
        "pmull2  v4.1q,  %0.2d,  %3.2d      \n\t"   // mul v0 by x^64, reduce
        "ext     %0.16b, %0.16b, %0.16b, #8 \n\t"
        "eor     %0.16b, %0.16b, v4.16b     \n\t"
        "pmull   v4.1q,  %1.1d,  %2.1d      \n\t"   // v0 ^= a.lo * b.lo
        "eor     %0.16b, %0.16b, v4.16b     \n\t"
        "rbit    %0.16b, %0.16b             \n\t"   // reverse bits for output
        : "=w" (vc)                                 // q0:      output
        : "w" (va), "w" (vb), "w" (vp)              // q1, q2:  input
        : "v4", "v5"                                // q4, q5:  clobbered
    );

    vst1q_u8( c, vc );                              // write out
}

#endif /* MBEDTLS_HAVE_ARM64 */

#endif /* MBEDTLS_AESARM_C */
