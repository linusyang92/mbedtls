// Dolbeau's SIMD optimization from libsodium & bench.cr.yp.to

#if defined(__i386__) || defined(__amd64__)
#define MBEDTLS_CHACHA20_HASVEC
#define MBEDTLS_CHACHA20_HASVEC_X86
#define CPUID_ECX_SSSE3   0x00000200
#include <emmintrin.h>
#include <immintrin.h>
#endif

#if defined(__aarch64__) || \
    (defined(__arm__) && __ARM_NEON__)
#define MBEDTLS_CHACHA20_HASVEC
#define MBEDTLS_CHACHA20_HASVEC_ARM
#include <arm_neon.h>
#endif

#ifdef MBEDTLS_CHACHA20_HASVEC
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

#ifdef MBEDTLS_CHACHA20_HASVEC_X86
void
get_cpuid(unsigned int cpu_info[4U], const unsigned int cpu_info_type)
{
    cpu_info[0] = cpu_info[1] = cpu_info[2] = cpu_info[3] = 0;
# ifdef __i386__
    __asm__ __volatile__(
        "pushfl; pushfl; "
        "popl %0; "
        "movl %0, %1; xorl %2, %0; "
        "pushl %0; "
        "popfl; pushfl; popl %0; popfl"
        : "=&r"(cpu_info[0]), "=&r"(cpu_info[1])
        : "i"(0x200000));
    if (((cpu_info[0] ^ cpu_info[1]) & 0x200000) == 0x0) {
        return; /* LCOV_EXCL_LINE */
    }
# endif
# ifdef __i386__
    __asm__ __volatile__("xchgl %%ebx, %k1; cpuid; xchgl %%ebx, %k1"
                         : "=a"(cpu_info[0]), "=&r"(cpu_info[1]),
                           "=c"(cpu_info[2]), "=d"(cpu_info[3])
                         : "0"(cpu_info_type), "2"(0U));
# elif defined(__x86_64__)
    __asm__ __volatile__("xchgq %%rbx, %q1; cpuid; xchgq %%rbx, %q1"
                         : "=a"(cpu_info[0]), "=&r"(cpu_info[1]),
                           "=c"(cpu_info[2]), "=d"(cpu_info[3])
                         : "0"(cpu_info_type), "2"(0U));
# else
    __asm__ __volatile__("cpuid"
                         : "=a"(cpu_info[0]), "=b"(cpu_info[1]),
                           "=c"(cpu_info[2]), "=d"(cpu_info[3])
                         : "0"(cpu_info_type), "2"(0U));
# endif
}

int mbedtls_chacha20_support_ssse3(void)
{
    static int inited = 0;
    static int supported = 0;
    if (inited) {
        return supported;
    } else {
        unsigned int id;
        unsigned int cpu_info[4] = {0};

        get_cpuid(cpu_info, 0x0);
        if ((id = cpu_info[0]) == 0U) {
            return 0; /* LCOV_EXCL_LINE */
        }
        get_cpuid(cpu_info, 0x00000001);

        supported = ((cpu_info[2] & CPUID_ECX_SSSE3) != 0x0);
        inited = 1;
    }
    return supported;
}

SIMD_FUNC(ssse3)
{
    unsigned char *c = out;
    SIMD_INIT
#include "chacha_x86_u4.h"
#include "chacha_x86_u1.h"
#include "chacha_x86_u0.h"
}
#endif

#ifdef MBEDTLS_CHACHA20_HASVEC_ARM
SIMD_FUNC(neon)
{
    SIMD_INIT
#include "chacha_arm_u4.h"
#include "chacha_arm_u1.h"
#include "chacha_arm_u0.h"
}
#endif

#endif
