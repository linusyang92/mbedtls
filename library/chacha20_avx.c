// Dolbeau's avx2 optimization from libsodium

#if defined(__i386__) || defined(__amd64__)

#define MBEDTLS_CHACHA20_HASVEC
#define MBEDTLS_CHACHA20_HASVEC_X86
#define CPUID_EBX_AVX2    0x00000020
#define CPUID_ECX_XSAVE   0x04000000
#define CPUID_ECX_OSXSAVE 0x08000000
#define CPUID_ECX_AVX     0x10000000
#define XCR0_SSE 0x00000002
#define XCR0_AVX 0x00000004
#include <emmintrin.h>
#include <immintrin.h>
#include <smmintrin.h>
#include <tmmintrin.h>
#ifdef _WIN32
#include <intrin.h>
#endif

#include "mbedtls/chacha20.h"
#define CHACHA20_CTR_INDEX ( 12U )
#define ROUNDS 20
#define SIMD_INIT \
    uint32_t *x = ctx->initial_state; \
    if (bytes == 0) { \
        return; \
    }
#define SIMD_FUNC(plat) \
void mbedtls_chacha20_ ## plat ( \
    mbedtls_chacha20_context *ctx, \
    size_t bytes, \
    const unsigned char *m, \
    unsigned char *out )

void
get_cpuid(unsigned int cpu_info[4U], const unsigned int cpu_info_type);

int mbedtls_chacha20_support_avx2(void)
{
    static int inited = 0;
    static int supported = 0;
    if (inited) {
        return supported;
    } else {
        unsigned int id;
        unsigned int cpu_info[4] = {0};
        int has_avx = 0;

        get_cpuid(cpu_info, 0x0);
        if ((id = cpu_info[0]) == 0U) {
            return 0; /* LCOV_EXCL_LINE */
        }
        get_cpuid(cpu_info, 0x00000001);

        has_avx = 0;
        if ((cpu_info[2] & (CPUID_ECX_AVX | CPUID_ECX_XSAVE | CPUID_ECX_OSXSAVE)) ==
            (CPUID_ECX_AVX | CPUID_ECX_XSAVE | CPUID_ECX_OSXSAVE)) {
            uint32_t xcr0 = 0U;
# ifdef _WIN32
            xcr0 = (uint32_t) _xgetbv(0);
# else
            __asm__ __volatile__(".byte 0x0f, 0x01, 0xd0" /* XGETBV */
                                 : "=a"(xcr0)
                                 : "c"((uint32_t) 0U)
                                 : "%edx");
# endif
            if ((xcr0 & (XCR0_SSE | XCR0_AVX)) == (XCR0_SSE | XCR0_AVX)) {
                has_avx = 1;
            }
        }

        if (has_avx) {
            unsigned int cpu_info7[4];

            get_cpuid(cpu_info7, 0x00000007);
            supported = ((cpu_info7[1] & CPUID_EBX_AVX2) != 0x0);
        }
        inited = 1;
    }
    return supported;
}

SIMD_FUNC(avx2)
{
    unsigned char *c = out;
    SIMD_INIT
#include "chacha_x86_u8.h"
#include "chacha_x86_u4.h"
#include "chacha_x86_u1.h"
#include "chacha_x86_u0.h"
}

#endif
