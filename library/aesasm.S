/* Wrapper for OpenSSL Assembly */

#define MBEDTLS_AESASM_WRAPPER 1
#include "mbedtls/aesasm.h"

#if MBEDTLS_AES_I386_WIN
    #include "asm/i386_win.S"
#endif

#if MBEDTLS_AES_ARM_LINUX
    #include "asm/arm_linux.S"
#endif

#if MBEDTLS_AES_MIPS_LINUX
    #include "asm/mips_linux.S"
#endif

#if MBEDTLS_AES_MIPSBE_LINUX
    #include "asm/mipsbe_linux.S"
#endif
