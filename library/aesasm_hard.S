/* Wrapper for OpenSSL Assembly */

#define MBEDTLS_AESASM_WRAPPER 1
#include "mbedtls/aesasm.h"

#if MBEDTLS_AES_I386_WIN
    #include "asm/i386_aesni_win.S"
#endif
