// Dolbeau's avx2 optimization from libsodium

#include "mbedtls/chacha20.h"
#include "mbedtls/chacha20_vec.h"

#ifdef MBEDTLS_CHACHA20_HASVEC_X86

#include <emmintrin.h>
#include <immintrin.h>
#include <smmintrin.h>
#include <tmmintrin.h>

CHACHA20_SIMD_FUNC(avx2)
{
    unsigned char *c = out;
    SIMD_INIT
#include "chacha_x86_u8.h"
#include "chacha_x86_u4.h"
#include "chacha_x86_u1.h"
#include "chacha_x86_u0.h"
}

#endif
