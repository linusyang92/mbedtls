// Wrapper for OpenSSL Assembly

#ifndef MBEDTLS_AESASM_H
#define MBEDTLS_AESASM_H

#ifndef MBEDTLS_AESASM_WRAPPER

#define MBEDTLS_AESASM_HAS_ASM 0x1
#define MBEDTLS_AESASM_HAS_HARDAES 0x2

int mbedtls_asm_supported(void);

#endif

#if defined(__GNUC__)

#if defined(__i386__) && defined(_WIN32)
  #define MBEDTLS_AES_USE_ASM 1
  #define MBEDTLS_AES_I386_WIN 1
#endif

#if defined(__arm__) && defined(__linux__)
  #define MBEDTLS_AES_USE_ASM 1
  #define MBEDTLS_AES_ARM_LINUX 1
#endif

#if defined(__mips__) && defined(__linux__)
  #define MBEDTLS_AES_USE_ASM 1
  #if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    #define MBEDTLS_AES_MIPS_LINUX 1
  #else
    #define MBEDTLS_AES_MIPSBE_LINUX 1
  #endif
#endif

#endif

#ifndef MBEDTLS_AESASM_WRAPPER

#if defined(MBEDTLS_AES_USE_ASM)
/* OpenSSL assembly functions */
#include <stdint.h>

#define AES_MAXNR 14
typedef struct {
  uint32_t rd_key[4 * (AES_MAXNR + 1)];
  uint32_t rounds;
} AES_KEY;
int mbedtls_asm_set_encrypt_key(const unsigned char *userKey, const int bits,
    AES_KEY *key);
int mbedtls_asm_set_decrypt_key(const unsigned char *userKey, const int bits,
    AES_KEY *key);
void mbedtls_asm_encrypt(const unsigned char *in, unsigned char *out,
    const AES_KEY *key);
void mbedtls_asm_decrypt(const unsigned char *in, unsigned char *out,
    const AES_KEY *key);
#endif

#if defined(__i386__) || defined(__amd64__)
#include <string.h>
void mbedtls_asm_aesni_ctr(unsigned char *rk, int nr, size_t length,
                           size_t *nc_off, unsigned char stream_block[16],
                           unsigned char nonce_counter[16],
                           unsigned char *input,
                           unsigned char *output);
#endif

#endif

#endif
