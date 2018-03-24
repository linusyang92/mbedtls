/*
 * This file is adapted from https://github.com/CriticalBlue/mbedtls
 */

/**
 * \file aes_armv8a_ce.h
 *
 * \brief AES support functions using the ARMv8-A Cryptography Extension for
 * hardware acceleration on some ARM processors.
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

#ifndef MBEDTLS_AESARM_H
#define MBEDTLS_AESARM_H

#include "aes.h"

#if defined(MBEDTLS_HAVE_ASM) && defined(__GNUC__) &&  \
    defined(__aarch64__) && \
    ! defined(MBEDTLS_HAVE_ARM64)
#define MBEDTLS_HAVE_ARM64
#endif

#if defined(MBEDTLS_HAVE_ARM64)

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief          AES armv8 features detection routine
 *
 * \return         1 if CPU has support for the feature, 0 otherwise
 */
int mbedtls_aesarm_has_support( void );

/**
 * \brief          AES armv8 AES-ECB block en(de)cryption
 *
 * \param ctx      AES context
 * \param mode     MBEDTLS_AES_ENCRYPT or MBEDTLS_AES_DECRYPT
 * \param input    16-byte input block
 * \param output   16-byte output block
 *
 * \return         0 on success (cannot fail)
 */
int mbedtls_aesarm_crypt_ecb( mbedtls_aes_context *ctx,
                              int mode,
                              const unsigned char input[16],
                              unsigned char output[16] );

#ifdef __cplusplus
}
#endif

#endif /* MBEDTLS_HAVE_X86_64 */

#endif /* MBEDTLS_AESARM_H */
