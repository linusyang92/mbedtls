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

static inline void aes_init()
{
    static int inited = 0;
    if (MBEDTLS_UNLIKELY(!inited)) {
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
