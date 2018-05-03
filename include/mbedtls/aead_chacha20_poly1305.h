/**
 * \file aead_chacha20_poly1305.h
 *
 * \brief ChaCha20-Poly1305 AEAD construction based on RFC 7539.
 *
 *  Copyright (C) 2006-2016, ARM Limited, All Rights Reserved
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
#ifndef MBEDTLS_AEAD_CHACHA20_POLY1305_H
#define MBEDTLS_AEAD_CHACHA20_POLY1305_H

#if !defined(MBEDTLS_CONFIG_FILE)
#include "config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if !defined(MBEDTLS_AEAD_CHACHA20_POLY1305_ALT)

#include "chacha20.h"
#include "poly1305.h"

#define MBEDTLS_ERR_AEAD_CHACHA20_POLY1305_BAD_INPUT_DATA -0x000E1 /**< Invalid input parameter(s). */
#define MBEDTLS_ERR_AEAD_CHACHA20_POLY1305_BAD_STATE      -0x000E2 /**< The requested operation is not permitted in the current state */

typedef enum
{
    MBEDTLS_AEAD_CHACHA20_POLY1305_ENCRYPT,
    MBEDTLS_AEAD_CHACHA20_POLY1305_DECRYPT
}
mbedtls_aead_chacha20_poly1305_mode_t;

typedef struct
{
    mbedtls_chacha20_context chacha20_ctx;      /** ChaCha20 context */
    mbedtls_poly1305_context poly1305_ctx;      /** Poly1305 context */
    uint64_t aad_len;                           /** Length (bytes) of the Additional Authenticated Data */
    uint64_t ciphertext_len;                    /** Length (bytes) of the ciphertext */
    int state;                                  /** Current state of the context */
    mbedtls_aead_chacha20_poly1305_mode_t mode; /** Cipher mode (encrypt or decrypt) */
}
mbedtls_aead_chacha20_poly1305_context;

/**
 * \brief               Initialize ChaCha20-Poly1305 context
 *
 * \param ctx           ChaCha20-Poly1305 context to be initialized
 */
void mbedtls_aead_chacha20_poly1305_init( mbedtls_aead_chacha20_poly1305_context *ctx );

/**
 * \brief               Clear ChaCha20-Poly1305 context
 *
 * \param ctx           ChaCha20-Poly1305 context to be cleared
 */
void mbedtls_aead_chacha20_poly1305_free( mbedtls_aead_chacha20_poly1305_context *ctx );

/**
 * \brief               Set the ChaCha20-Poly1305 symmetric encryption key.
 *
 * \param ctx           The ChaCha20-Poly1305 context.
 * \param key           The 256-bit (32 bytes) key.
 *
 * \return              MBEDTLS_ERR_AEAD_CHACHA20_POLY1305_BAD_INPUT_DATA is returned
 *                      if \p ctx or \p key are NULL.
 *                      Otherwise, 0 is returned to indicate success.
 */
int mbedtls_aead_chacha20_poly1305_setkey( mbedtls_aead_chacha20_poly1305_context *ctx,
                                           const unsigned char key[32] );

/**
 * \brief               Setup ChaCha20-Poly1305 context for encryption or decryption.
 *
 * \note                If the context is being used for AAD only (no data to
 *                      encrypt or decrypt) then \p mode can be set to any value.
 *
 * \param ctx           The ChaCha20-Poly1305 context.
 * \param nonce         The nonce/IV to use for the message. This must be unique
 *                      for every message encrypted under the same key.
 * \param mode          Specifies whether the context is used to encrypt or
 *                      decrypt data.
 *
 * \return              MBEDTLS_ERR_AEAD_CHACHA20_POLY1305_BAD_INPUT_DATA is returned
 *                      if \p ctx or \p mac are NULL.
 *                      Otherwise, 0 is returned to indicate success.
 */
int mbedtls_aead_chacha20_poly1305_starts( mbedtls_aead_chacha20_poly1305_context *ctx,
                                           const unsigned char nonce[12],
                                           mbedtls_aead_chacha20_poly1305_mode_t mode );

/**
 * \brief               Process additional authenticated data (AAD).
 *
 *                      This function processes data that is authenticated, but
 *                      not encrypted.
 *
 * \note                This function is called before data is encrypted/decrypted.
 *                      I.e. call this function to process the AAD before calling
 *                      mbedtls_aead_chacha20_poly1305_update.
 *
 *                      You may call this function multiple times to process
 *                      an arbitrary amount of AAD. It is permitted to call
 *                      this function 0 times, if no AAD is used.
 *
 *                      This function cannot be called any more if data has
 *                      been processed by mbedtls_aead_chacha20_poly1305_update,
 *                      or if the context has been finished.
 *
 * \param ctx           The ChaCha20-Poly1305 context.
 * \param aad_len       The length (in bytes) of the AAD. The length has no
 *                      restrictions.
 * \param aad           Buffer containing the AAD.
 *                      This pointer can be NULL if aad_len == 0.
 *
 * \return              MBEDTLS_ERR_AEAD_CHACHA20_POLY1305_BAD_INPUT_DATA is returned
 *                      if \p ctx or \p aad are NULL.
 *                      MBEDTLS_ERR_AEAD_CHACHA20_POLY1305_BAD_STATE is returned if
 *                      the context has not been setup, the context has been
 *                      finished, or if the AAD has been finished.
 *                      Otherwise, 0 is returned to indicate success.
 */
int mbedtls_aead_chacha20_poly1305_update_aad( mbedtls_aead_chacha20_poly1305_context *ctx,
                                               size_t aad_len,
                                               const unsigned char *aad );

/**
 * \brief               Encrypt/decrypt data.
 *
 *                      The direction (encryption or decryption) depends on the
 *                      mode that was given when calling
 *                      mbedtls_aead_chacha20_poly1305_starts.
 *
 *                      You may call this function multiple times to process
 *                      an arbitrary amount of data. It is permitted to call
 *                      this function 0 times, if no data is to be encrypted
 *                      or decrypted.
 *
 * \param ctx           The ChaCha20-Poly1305 context.
 * \param len           The length (in bytes) of the data to encrypt or decrypt.
 * \param input         Buffer containing the data to encrypt or decrypt.
 *                      This pointer can be NULL if len == 0.
 * \param output        Buffer to where the encrypted or decrypted data is written.
 *                      This pointer can be NULL if len == 0.
 *
 * \return              MBEDTLS_ERR_AEAD_CHACHA20_POLY1305_BAD_INPUT_DATA is returned
 *                      if \p ctx, \p input, or \p output are NULL.
 *                      MBEDTLS_ERR_AEAD_CHACHA20_POLY1305_BAD_STATE is returned if
 *                      the context has not been setup, or if the context has been
 *                      finished.
 *                      Otherwise, 0 is returned to indicate success.
 */
int mbedtls_aead_chacha20_poly1305_update( mbedtls_aead_chacha20_poly1305_context *ctx,
                                            size_t len,
                                            const unsigned char *input,
                                            unsigned char *output );

/**
 * \brief               Compute the ChaCha20-Poly1305 MAC.
 *
 * \param ctx           The ChaCha20-Poly1305 context.
 * \param mac           Buffer to where the 128-bit (16 bytes) MAC is written.
 *
 * \return              MBEDTLS_ERR_AEAD_CHACHA20_POLY1305_BAD_INPUT_DATA is returned
 *                      if \p ctx or \p mac are NULL.
 *                      MBEDTLS_ERR_AEAD_CHACHA20_POLY1305_BAD_STATE is returned if
 *                      the context has not been setup.
 *                      Otherwise, 0 is returned to indicate success.
 */
int mbedtls_aead_chacha20_poly1305_finish( mbedtls_aead_chacha20_poly1305_context *ctx,
                                           unsigned char mac[16] );

#else /* !MBEDTLS_AEAD_CHACHA20_POLY1305_ALT */
#include "aead_chacha20_poly1305_alt.h"
#endif /* !MBEDTLS_AEAD_CHACHA20_POLY1305_ALT */

/**
 * \brief               Encrypt or decrypt data, and produce a MAC with ChaCha20-Poly1305.
 *
 * \param key           The 256-bit (32 bytes) encryption key to use.
 * \param nonce         The 96-bit (12 bytes) nonce/IV to use.
 * \param mode          Specifies whether the data in the \p input buffer is to
 *                      be encrypted or decrypted. If there is no data to encrypt
 *                      or decrypt (i.e. \p ilen is 0) then the value of this
 *                      parameter does not matter.
 * \param aad_len       The length (in bytes) of the AAD data to process.
 * \param aad           Buffer containing the additional authenticated data (AAD).
 *                      This pointer can be NULL if aad_len == 0.
 * \param ilen          The length (in bytes) of the data to encrypt or decrypt.
 * \param input         Buffer containing the data to encrypt or decrypt.
 *                      This pointer can be NULL if ilen == 0.
 * \param output        Buffer to where the encrypted or decrypted data is written.
 *                      This pointer can be NULL if ilen == 0.
 * \param mac           Buffer to where the computed 128-bit (16 bytes) MAC is written.
 *
 * \return              MBEDTLS_ERR_AEAD_CHACHA20_POLY1305_BAD_INPUT_DATA is returned
 *                      if one or more of the required parameters are NULL.
 *                      Otherwise, 0 is returned to indicate success.
 */
int mbedtls_aead_chacha20_poly1305_crypt_and_mac( const unsigned char key[32],
                                                  const unsigned char nonce[12],
                                                  mbedtls_aead_chacha20_poly1305_mode_t mode,
                                                  size_t aad_len,
                                                  const unsigned char *aad,
                                                  size_t ilen,
                                                  const unsigned char *input,
                                                  unsigned char *output,
                                                  unsigned char mac[16] );

/**
 * \brief               Checkup routine
 *
 * \return              0 if successful, or 1 if the test failed
 */
int mbedtls_aead_chacha20_poly1305_self_test( int verbose );

#endif /* MBEDTLS_AEAD_CHACHA20_POLY1305_H */
