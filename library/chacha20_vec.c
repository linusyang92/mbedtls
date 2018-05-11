// Dolbeau's SIMD optimization from libsodium & bench.cr.yp.to

#include "mbedtls/chacha20.h"
#include "mbedtls/chacha20_vec.h"

#ifdef MBEDTLS_CHACHA20_HASVEC_X86

#include <emmintrin.h>
#include <immintrin.h>

CHACHA20_SIMD_FUNC(ssse3)
{
    unsigned char *c = out;
    SIMD_INIT
#include "chacha_x86_u4.h"
#include "chacha_x86_u1.h"
#include "chacha_x86_u0.h"
}
#endif

#ifdef MBEDTLS_CHACHA20_HASVEC_ARM

#include <arm_neon.h>

CHACHA20_SIMD_FUNC(neon)
{
    SIMD_INIT
#include "chacha_arm_u4.h"
#include "chacha_arm_u1.h"
#include "chacha_arm_u0.h"
}
#endif
