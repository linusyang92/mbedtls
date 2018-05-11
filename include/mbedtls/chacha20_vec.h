#ifndef MBEDTLS_CHACHA20_VEC_H
#define MBEDTLS_CHACHA20_VEC_H

#define ROUNDS 20
#define SIMD_INIT \
    uint32_t *x = ctx->initial_state; \
    if (bytes == 0) { \
        return; \
    }

#endif
