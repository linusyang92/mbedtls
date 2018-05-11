/*
 * This file is adapted from https://github.com/CriticalBlue/mbedtls
 */

#if defined(__aarch64__)

#include "mbedtls/sha1.h"

#include <arm_neon.h>

#if defined(__BYTE_ORDER__)
# if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#  define IS_BIG_ENDIAN
#  pragma message("Big-endian ARM architecture")
# else
#  define IS_LITTLE_ENDIAN
# endif
#else
# error macro __BYTE_ORDER__ is not defined for this compiler
#endif

void mbedtls_armv8a_ce_sha1_process( mbedtls_sha1_context *ctx, const unsigned char data[64] )
{
	/* declare variables */

	uint32x4_t k0, k1, k2, k3;
	uint32x4_t abcd, abcd0;
	uint32x4_t w0, w1, w2, w3;
	uint32_t   a, e, e0, e1;
	uint32x4_t wk0, wk1;

	/* set K0..K3 constants */

	k0 = vdupq_n_u32( 0x5A827999 );
	k1 = vdupq_n_u32( 0x6ED9EBA1 );
	k2 = vdupq_n_u32( 0x8F1BBCDC );
	k3 = vdupq_n_u32( 0xCA62C1D6 );

	/* load state */

	abcd = vld1q_u32( ctx->state );
	abcd0 = abcd;
	e = ctx->state[4];

	/* load message */

	w0 = vld1q_u32( (uint32_t const *)(data) );
	w1 = vld1q_u32( (uint32_t const *)(data + 16) );
	w2 = vld1q_u32( (uint32_t const *)(data + 32) );
	w3 = vld1q_u32( (uint32_t const *)(data + 48) );

	#ifdef IS_LITTLE_ENDIAN
	w0 = vreinterpretq_u32_u8( vrev32q_u8( vreinterpretq_u8_u32( w0 ) ) );
	w1 = vreinterpretq_u32_u8( vrev32q_u8( vreinterpretq_u8_u32( w1 ) ) );
	w2 = vreinterpretq_u32_u8( vrev32q_u8( vreinterpretq_u8_u32( w2 ) ) );
	w3 = vreinterpretq_u32_u8( vrev32q_u8( vreinterpretq_u8_u32( w3 ) ) );
	#endif

	/* initialize wk0 wk1 */

	wk0 = vaddq_u32( w0, k0 );
	wk1 = vaddq_u32( w1, k0 );

	/* perform rounds */

	a = vgetq_lane_u32( abcd, 0 );
	e1 = vsha1h_u32( a );
	abcd = vsha1cq_u32( abcd, e, wk0 ); /* 0 */
	wk0 = vaddq_u32( w2, k0 );
	w0 = vsha1su0q_u32( w0, w1, w2 );

	a = vgetq_lane_u32( abcd, 0 );
	e0 = vsha1h_u32( a );
	abcd = vsha1cq_u32( abcd, e1, wk1 ); /* 1 */
	wk1 = vaddq_u32( w3, k0 );
	w0 = vsha1su1q_u32( w0, w3 );
	w1 = vsha1su0q_u32( w1, w2, w3 );

	a = vgetq_lane_u32( abcd, 0 );
	e1 = vsha1h_u32( a );
	abcd = vsha1cq_u32( abcd, e0, wk0 ); /* 2 */
	wk0 = vaddq_u32( w0, k0 );
	w1 = vsha1su1q_u32( w1, w0 );
	w2 = vsha1su0q_u32( w2, w3, w0 );

	a = vgetq_lane_u32( abcd, 0 );
	e0 = vsha1h_u32( a );
	abcd = vsha1cq_u32( abcd, e1, wk1 ); /* 3 */
	wk1 = vaddq_u32( w1, k1 );
	w2 = vsha1su1q_u32( w2, w1 );
	w3 = vsha1su0q_u32( w3, w0, w1 );

	a = vgetq_lane_u32( abcd, 0 );
	e1 = vsha1h_u32( a );
	abcd = vsha1cq_u32( abcd, e0, wk0 ); /* 4 */
	wk0 = vaddq_u32( w2, k1 );
	w3 = vsha1su1q_u32( w3, w2 );
	w0 = vsha1su0q_u32( w0, w1, w2 );

	a = vgetq_lane_u32( abcd, 0 );
	e0 = vsha1h_u32( a );
	abcd = vsha1pq_u32( abcd, e1, wk1 ); /* 5 */
	wk1 = vaddq_u32( w3, k1 );
	w0 = vsha1su1q_u32( w0, w3 );
	w1 = vsha1su0q_u32( w1, w2, w3 );

	a = vgetq_lane_u32( abcd, 0 );
	e1 = vsha1h_u32( a );
	abcd = vsha1pq_u32( abcd, e0, wk0 ); /* 6 */
	wk0 = vaddq_u32( w0, k1 );
	w1 = vsha1su1q_u32( w1, w0 );
	w2 = vsha1su0q_u32( w2, w3, w0 );

	a = vgetq_lane_u32( abcd, 0 );
	e0 = vsha1h_u32( a );
	abcd = vsha1pq_u32( abcd, e1, wk1 ); /* 7 */
	wk1 = vaddq_u32( w1, k1 );
	w2 = vsha1su1q_u32( w2, w1 );
	w3 = vsha1su0q_u32( w3, w0, w1 );

	a = vgetq_lane_u32( abcd, 0 );
	e1 = vsha1h_u32( a );
	abcd = vsha1pq_u32( abcd, e0, wk0 ); /* 8 */
	wk0 = vaddq_u32( w2, k2 );
	w3 = vsha1su1q_u32( w3, w2 );
	w0 = vsha1su0q_u32( w0, w1, w2 );

	a = vgetq_lane_u32( abcd, 0 );
	e0 = vsha1h_u32( a );
	abcd = vsha1pq_u32( abcd, e1, wk1 ); /* 9 */
	wk1 = vaddq_u32( w3, k2 );
	w0 = vsha1su1q_u32( w0, w3 );
	w1 = vsha1su0q_u32( w1, w2, w3 );

	a = vgetq_lane_u32( abcd, 0 );
	e1 = vsha1h_u32( a );
	abcd = vsha1mq_u32( abcd, e0, wk0 ); /* 10 */
	wk0 = vaddq_u32( w0, k2 );
	w1 = vsha1su1q_u32( w1, w0 );
	w2 = vsha1su0q_u32( w2, w3, w0 );

	a = vgetq_lane_u32( abcd, 0 );
	e0 = vsha1h_u32( a );
	abcd = vsha1mq_u32( abcd, e1, wk1 ); /* 11 */
	wk1 = vaddq_u32( w1, k2 );
	w2 = vsha1su1q_u32( w2, w1 );
	w3 = vsha1su0q_u32( w3, w0, w1 );

	a = vgetq_lane_u32( abcd, 0 );
	e1 = vsha1h_u32( a );
	abcd = vsha1mq_u32( abcd, e0, wk0 ); /* 12 */
	wk0 = vaddq_u32( w2, k2 );
	w3 = vsha1su1q_u32( w3, w2 );
	w0 = vsha1su0q_u32( w0, w1, w2 );

	a = vgetq_lane_u32( abcd, 0 );
	e0 = vsha1h_u32( a );
	abcd = vsha1mq_u32( abcd, e1, wk1 ); /* 13 */
	wk1 = vaddq_u32( w3, k3 );
	w0 = vsha1su1q_u32( w0, w3 );
	w1 = vsha1su0q_u32( w1, w2, w3 );

	a = vgetq_lane_u32( abcd, 0 );
	e1 = vsha1h_u32( a );
	abcd = vsha1mq_u32( abcd, e0, wk0 ); /* 14 */
	wk0 = vaddq_u32( w0, k3 );
	w1 = vsha1su1q_u32( w1, w0 );
	w2 = vsha1su0q_u32( w2, w3, w0 );

	a = vgetq_lane_u32( abcd, 0 );
	e0 = vsha1h_u32( a );
	abcd = vsha1pq_u32( abcd, e1, wk1 ); /* 15 */
	wk1 = vaddq_u32( w1, k3 );
	w2 = vsha1su1q_u32( w2, w1 );
	w3 = vsha1su0q_u32( w3, w0, w1 );

	a = vgetq_lane_u32( abcd, 0 );
	e1 = vsha1h_u32( a );
	abcd = vsha1pq_u32( abcd, e0, wk0 ); /* 16 */
	wk0 = vaddq_u32( w2, k3 );
	w3 = vsha1su1q_u32( w3, w2 );
	w0 = vsha1su0q_u32( w0, w1, w2 );

	a = vgetq_lane_u32( abcd, 0 );
	e0 = vsha1h_u32( a );
	abcd = vsha1pq_u32( abcd, e1, wk1 ); /* 17 */
	wk1 = vaddq_u32( w3, k3 );
	w0 = vsha1su1q_u32( w0, w3 );

	a = vgetq_lane_u32( abcd, 0 );
	e1 = vsha1h_u32( a );
	abcd = vsha1pq_u32( abcd, e0, wk0 ); /* 18 */

	a = vgetq_lane_u32( abcd, 0 );
	e0 = vsha1h_u32( a );
	abcd = vsha1pq_u32( abcd, e1, wk1 ); /* 19 */

	e = e + e0;
	abcd = vaddq_u32( abcd0, abcd );

	/* save state */

	vst1q_u32(ctx->state, abcd );
	ctx->state[4] = e;
}
#endif
