/* 
 * SHA-256 hash in x86/x86-64 assembly
 * 
 * Copyright (c) 2017 Project Nayuki. (MIT License)
 * https://www.nayuki.io/page/fast-sha2-hashes-in-x86-assembly
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 * the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 * - The above copyright notice and this permission notice shall be included in
 *   all copies or substantial portions of the Software.
 * - The Software is provided "as is", without warranty of any kind, express or
 *   implied, including but not limited to the warranties of merchantability,
 *   fitness for a particular purpose and noninfringement. In no event shall the
 *   authors or copyright holders be liable for any claim, damages or other
 *   liability, whether in an action of contract, tort or otherwise, arising from,
 *   out of or in connection with the Software or the use or other dealings in the
 *   Software.
 */

#if defined(__i386__)

/* void sha256_compress(uint32_t state[static 8], const uint8_t block[static 64]) */
#ifndef _WIN32
.globl sha256_compress
sha256_compress:
#else
.globl _sha256_compress
_sha256_compress:
#endif
	/* 
	 * Storage usage:
	 *   Bytes  Location   Description
	 *       4  eax        Temporary for calculation per round
	 *       4  ebx        Temporary for calculation per round
	 *       4  ecx        Temporary for calculation per round
	 *       4  edx        Temporary for calculation per round
	 *       4  ebp        Temporary for calculation per round
	 *       4  esi        (During state loading and update) base address of state array argument
	 *                     (During hash rounds) temporary for calculation per round
	 *       4  edi        Base address of block array argument (during key schedule loading rounds only)
	 *       4  esp        x86 stack pointer
	 *      32  [esp+  0]  SHA-256 state variables A,B,C,D,E,F,G,H (4 bytes each)
	 *      64  [esp+ 32]  Key schedule of 16 * 4 bytes
	 *       4  [esp+ 96]  Caller's value of ebx
	 *       4  [esp+100]  Caller's value of esi
	 *       4  [esp+104]  Caller's value of edi
	 *       4  [esp+108]  Caller's value of ebp
	 */
	
	#define SCHED(i)  ((((i)&0xF)+8)*4)(%esp)
	
	#define ROUNDa(i, a, b, c, d, e, f, g, h, k)  \
		movl    (i*4)(%edi), %ebp;  \
		bswapl  %ebp;               \
		movl    %ebp, SCHED(i);     \
		ROUNDTAIL(i, a, b, c, d, e, f, g, h, k)
	
	#define ROUNDb(i, a, b, c, d, e, f, g, h, k)  \
		movl  SCHED(i-15), %eax;  \
		movl  SCHED(i-16), %ebp;  \
		movl  %eax, %ebx;         \
		addl  SCHED(i- 7), %ebp;  \
		movl  %eax, %ecx;         \
		rorl  $18, %ebx;          \
		shrl  $3, %ecx;           \
		rorl  $7, %eax;           \
		xorl  %ecx, %ebx;         \
		xorl  %ebx, %eax;         \
		addl  %eax, %ebp;         \
		movl  SCHED(i- 2), %eax;  \
		movl  %eax, %ebx;         \
		movl  %eax, %ecx;         \
		rorl  $19, %ebx;          \
		shrl  $10, %ecx;          \
		rorl  $17, %eax;          \
		xorl  %ecx, %ebx;         \
		xorl  %ebx, %eax;         \
		addl  %eax, %ebp;         \
		movl  %ebp, SCHED(i);     \
		ROUNDTAIL(i, a, b, c, d, e, f, g, h, k)
	
	#define STATE(i)  (i*4)(%esp)
	
	#define ROUNDTAIL(i, a, b, c, d, e, f, g, h, k)  \
		/* Part 0 */               \
		movl  STATE(e), %eax;      \
		movl  %eax, %ebx;          \
		movl  %eax, %ecx;          \
		movl  %eax, %edx;          \
		rorl  $11, %eax;           \
		rorl  $25, %ebx;           \
		rorl  $6, %ecx;            \
		movl  STATE(h), %esi;      \
		xorl  %ebx, %eax;          \
		xorl  %eax, %ecx;          \
		addl  %ebp, %esi;          \
		movl  STATE(g), %ebx;      \
		movl  STATE(f), %eax;      \
		xorl  %ebx, %eax;          \
		andl  %edx, %eax;          \
		xorl  %ebx, %eax;          \
		leal  k(%ecx,%eax), %ecx;  \
		addl  %ecx, %esi;          \
		/* Part 1 */               \
		addl  %esi, STATE(d);      \
		/* Part 2 */               \
		movl  STATE(a), %eax;      \
		movl  %eax, %ebx;          \
		movl  %eax, %ecx;          \
		movl  %eax, %edx;          \
		rorl  $13, %eax;           \
		rorl  $22, %ebx;           \
		rorl  $2, %ecx;            \
		xorl  %ebx, %eax;          \
		xorl  %eax, %ecx;          \
		movl  STATE(c), %eax;      \
		addl  %ecx, %esi;          \
		movl  %eax, %ecx;          \
		movl  STATE(b), %ebx;      \
		orl   %ebx, %ecx;          \
		andl  %ebx, %eax;          \
		andl  %edx, %ecx;          \
		orl   %eax, %ecx;          \
		addl  %ecx, %esi;          \
		movl  %esi, STATE(h);
	
	/* Allocate scratch space, save registers */
	subl  $112, %esp
	movl  %ebx,  96(%esp)
	movl  %esi, 100(%esp)
	movl  %edi, 104(%esp)
	movl  %ebp, 108(%esp)
	
	/* Copy state */
	movl  116(%esp), %esi  /* Argument: state */
	movl   0(%esi), %eax;  movl %eax,  0(%esp)
	movl   4(%esi), %eax;  movl %eax,  4(%esp)
	movl   8(%esi), %eax;  movl %eax,  8(%esp)
	movl  12(%esi), %eax;  movl %eax, 12(%esp)
	movl  16(%esi), %eax;  movl %eax, 16(%esp)
	movl  20(%esi), %eax;  movl %eax, 20(%esp)
	movl  24(%esi), %eax;  movl %eax, 24(%esp)
	movl  28(%esi), %eax;  movl %eax, 28(%esp)
	
	/* Do 64 rounds of hashing */
	movl    120(%esp), %edi  /* Argument: block */
	ROUNDa( 0, 0, 1, 2, 3, 4, 5, 6, 7, 0x428A2F98)
	ROUNDa( 1, 7, 0, 1, 2, 3, 4, 5, 6, 0x71374491)
	ROUNDa( 2, 6, 7, 0, 1, 2, 3, 4, 5, 0xB5C0FBCF)
	ROUNDa( 3, 5, 6, 7, 0, 1, 2, 3, 4, 0xE9B5DBA5)
	ROUNDa( 4, 4, 5, 6, 7, 0, 1, 2, 3, 0x3956C25B)
	ROUNDa( 5, 3, 4, 5, 6, 7, 0, 1, 2, 0x59F111F1)
	ROUNDa( 6, 2, 3, 4, 5, 6, 7, 0, 1, 0x923F82A4)
	ROUNDa( 7, 1, 2, 3, 4, 5, 6, 7, 0, 0xAB1C5ED5)
	ROUNDa( 8, 0, 1, 2, 3, 4, 5, 6, 7, 0xD807AA98)
	ROUNDa( 9, 7, 0, 1, 2, 3, 4, 5, 6, 0x12835B01)
	ROUNDa(10, 6, 7, 0, 1, 2, 3, 4, 5, 0x243185BE)
	ROUNDa(11, 5, 6, 7, 0, 1, 2, 3, 4, 0x550C7DC3)
	ROUNDa(12, 4, 5, 6, 7, 0, 1, 2, 3, 0x72BE5D74)
	ROUNDa(13, 3, 4, 5, 6, 7, 0, 1, 2, 0x80DEB1FE)
	ROUNDa(14, 2, 3, 4, 5, 6, 7, 0, 1, 0x9BDC06A7)
	ROUNDa(15, 1, 2, 3, 4, 5, 6, 7, 0, 0xC19BF174)
	ROUNDb(16, 0, 1, 2, 3, 4, 5, 6, 7, 0xE49B69C1)
	ROUNDb(17, 7, 0, 1, 2, 3, 4, 5, 6, 0xEFBE4786)
	ROUNDb(18, 6, 7, 0, 1, 2, 3, 4, 5, 0x0FC19DC6)
	ROUNDb(19, 5, 6, 7, 0, 1, 2, 3, 4, 0x240CA1CC)
	ROUNDb(20, 4, 5, 6, 7, 0, 1, 2, 3, 0x2DE92C6F)
	ROUNDb(21, 3, 4, 5, 6, 7, 0, 1, 2, 0x4A7484AA)
	ROUNDb(22, 2, 3, 4, 5, 6, 7, 0, 1, 0x5CB0A9DC)
	ROUNDb(23, 1, 2, 3, 4, 5, 6, 7, 0, 0x76F988DA)
	ROUNDb(24, 0, 1, 2, 3, 4, 5, 6, 7, 0x983E5152)
	ROUNDb(25, 7, 0, 1, 2, 3, 4, 5, 6, 0xA831C66D)
	ROUNDb(26, 6, 7, 0, 1, 2, 3, 4, 5, 0xB00327C8)
	ROUNDb(27, 5, 6, 7, 0, 1, 2, 3, 4, 0xBF597FC7)
	ROUNDb(28, 4, 5, 6, 7, 0, 1, 2, 3, 0xC6E00BF3)
	ROUNDb(29, 3, 4, 5, 6, 7, 0, 1, 2, 0xD5A79147)
	ROUNDb(30, 2, 3, 4, 5, 6, 7, 0, 1, 0x06CA6351)
	ROUNDb(31, 1, 2, 3, 4, 5, 6, 7, 0, 0x14292967)
	ROUNDb(32, 0, 1, 2, 3, 4, 5, 6, 7, 0x27B70A85)
	ROUNDb(33, 7, 0, 1, 2, 3, 4, 5, 6, 0x2E1B2138)
	ROUNDb(34, 6, 7, 0, 1, 2, 3, 4, 5, 0x4D2C6DFC)
	ROUNDb(35, 5, 6, 7, 0, 1, 2, 3, 4, 0x53380D13)
	ROUNDb(36, 4, 5, 6, 7, 0, 1, 2, 3, 0x650A7354)
	ROUNDb(37, 3, 4, 5, 6, 7, 0, 1, 2, 0x766A0ABB)
	ROUNDb(38, 2, 3, 4, 5, 6, 7, 0, 1, 0x81C2C92E)
	ROUNDb(39, 1, 2, 3, 4, 5, 6, 7, 0, 0x92722C85)
	ROUNDb(40, 0, 1, 2, 3, 4, 5, 6, 7, 0xA2BFE8A1)
	ROUNDb(41, 7, 0, 1, 2, 3, 4, 5, 6, 0xA81A664B)
	ROUNDb(42, 6, 7, 0, 1, 2, 3, 4, 5, 0xC24B8B70)
	ROUNDb(43, 5, 6, 7, 0, 1, 2, 3, 4, 0xC76C51A3)
	ROUNDb(44, 4, 5, 6, 7, 0, 1, 2, 3, 0xD192E819)
	ROUNDb(45, 3, 4, 5, 6, 7, 0, 1, 2, 0xD6990624)
	ROUNDb(46, 2, 3, 4, 5, 6, 7, 0, 1, 0xF40E3585)
	ROUNDb(47, 1, 2, 3, 4, 5, 6, 7, 0, 0x106AA070)
	ROUNDb(48, 0, 1, 2, 3, 4, 5, 6, 7, 0x19A4C116)
	ROUNDb(49, 7, 0, 1, 2, 3, 4, 5, 6, 0x1E376C08)
	ROUNDb(50, 6, 7, 0, 1, 2, 3, 4, 5, 0x2748774C)
	ROUNDb(51, 5, 6, 7, 0, 1, 2, 3, 4, 0x34B0BCB5)
	ROUNDb(52, 4, 5, 6, 7, 0, 1, 2, 3, 0x391C0CB3)
	ROUNDb(53, 3, 4, 5, 6, 7, 0, 1, 2, 0x4ED8AA4A)
	ROUNDb(54, 2, 3, 4, 5, 6, 7, 0, 1, 0x5B9CCA4F)
	ROUNDb(55, 1, 2, 3, 4, 5, 6, 7, 0, 0x682E6FF3)
	ROUNDb(56, 0, 1, 2, 3, 4, 5, 6, 7, 0x748F82EE)
	ROUNDb(57, 7, 0, 1, 2, 3, 4, 5, 6, 0x78A5636F)
	ROUNDb(58, 6, 7, 0, 1, 2, 3, 4, 5, 0x84C87814)
	ROUNDb(59, 5, 6, 7, 0, 1, 2, 3, 4, 0x8CC70208)
	ROUNDb(60, 4, 5, 6, 7, 0, 1, 2, 3, 0x90BEFFFA)
	ROUNDb(61, 3, 4, 5, 6, 7, 0, 1, 2, 0xA4506CEB)
	ROUNDb(62, 2, 3, 4, 5, 6, 7, 0, 1, 0xBEF9A3F7)
	ROUNDb(63, 1, 2, 3, 4, 5, 6, 7, 0, 0xC67178F2)
	
	/* Add to state */
	movl  116(%esp), %esi  /* Argument: state */
	movl   0(%esp), %eax;  addl %eax,  0(%esi)
	movl   4(%esp), %eax;  addl %eax,  4(%esi)
	movl   8(%esp), %eax;  addl %eax,  8(%esi)
	movl  12(%esp), %eax;  addl %eax, 12(%esi)
	movl  16(%esp), %eax;  addl %eax, 16(%esi)
	movl  20(%esp), %eax;  addl %eax, 20(%esi)
	movl  24(%esp), %eax;  addl %eax, 24(%esi)
	movl  28(%esp), %eax;  addl %eax, 28(%esi)
	
	/* Restore registers */
	movl   96(%esp), %ebx
	movl  100(%esp), %esi
	movl  104(%esp), %edi
	movl  108(%esp), %ebp
	addl  $112, %esp
	retl
    
#elif defined(__amd64__)

/* void sha256_compress(uint32_t state[static 8], const uint8_t block[static 64]) */
.globl sha256_compress
sha256_compress:
	/* 
	 * Storage usage:
	 *   Bytes  Location  Description
	 *       4  eax       Temporary for calculation per round
	 *       4  ebx       Temporary for calculation per round
	 *       4  ecx       Temporary for calculation per round
	 *       4  edx       Temporary for calculation per round
	 *       8  rsi       Base address of block array argument (read-only)
	 *       8  rdi       Base address of state array argument (read-only)
	 *       8  rsp       x86-64 stack pointer
	 *       4  r8d       SHA-256 state variable A
	 *       4  r9d       SHA-256 state variable B
	 *       4  r10d      SHA-256 state variable C
	 *       4  r11d      SHA-256 state variable D
	 *       4  r12d      SHA-256 state variable E
	 *       4  r13d      SHA-256 state variable F
	 *       4  r14d      SHA-256 state variable G
	 *       4  r15d      SHA-256 state variable H
	 *      64  [rsp+0]   Circular buffer of most recent 16 key schedule items, 4 bytes each
	 *      16  xmm0      Caller's value of r10 (only low 64 bits are used)
	 *      16  xmm1      Caller's value of r11 (only low 64 bits are used)
	 *      16  xmm2      Caller's value of r12 (only low 64 bits are used)
	 *      16  xmm3      Caller's value of r13 (only low 64 bits are used)
	 *      16  xmm4      Caller's value of r14 (only low 64 bits are used)
	 *      16  xmm5      Caller's value of r15 (only low 64 bits are used)
	 *      16  xmm6      Caller's value of rbx (only low 64 bits are used)
	 */
	
	#define SCHED(i)  (((i)&0xF)*4)(%rsp)
	
	#define ROUNDa(i, a, b, c, d, e, f, g, h, k)  \
		movl    (i*4)(%rsi), %ebx;  \
		bswapl  %ebx;               \
		movl    %ebx, SCHED(i);     \
		ROUNDTAIL(a, b, c, d, e, f, g, h, k)
	
	#define ROUNDb(i, a, b, c, d, e, f, g, h, k)  \
		movl  SCHED(i-15), %eax;  \
		movl  SCHED(i-16), %ebx;  \
		addl  SCHED(i- 7), %ebx;  \
		movl  %eax, %ecx;         \
		movl  %eax, %edx;         \
		rorl  $18, %ecx;          \
		shrl  $3, %edx;           \
		rorl  $7, %eax;           \
		xorl  %edx, %ecx;         \
		xorl  %ecx, %eax;         \
		addl  %eax, %ebx;         \
		movl  SCHED(i- 2), %eax;  \
		movl  %eax, %ecx;         \
		movl  %eax, %edx;         \
		rorl  $19, %ecx;          \
		shrl  $10, %edx;          \
		rorl  $17, %eax;          \
		xorl  %edx, %ecx;         \
		xorl  %ecx, %eax;         \
		addl  %eax, %ebx;         \
		movl  %ebx, SCHED(i);     \
		ROUNDTAIL(a, b, c, d, e, f, g, h, k)
	
	#define ROUNDTAIL(a, b, c, d, e, f, g, h, k)  \
		/* Part 0 */               \
		movl  %e, %ecx;            \
		movl  %e, %edx;            \
		movl  %e, %eax;            \
		rorl  $11, %ecx;           \
		rorl  $25, %edx;           \
		rorl  $6, %eax;            \
		xorl  %edx, %ecx;          \
		xorl  %ecx, %eax;          \
		addl  %ebx, %h;            \
		movl  %g, %ecx;            \
		xorl  %f, %ecx;            \
		andl  %e, %ecx;            \
		xorl  %g, %ecx;            \
		leal  k(%rax,%rcx), %eax;  \
		addl  %eax, %h;            \
		/* Part 1 */               \
		addl  %h, %d;              \
		/* Part 2 */               \
		movl  %a, %ecx;            \
		movl  %a, %edx;            \
		movl  %a, %eax;            \
		rorl  $13, %ecx;           \
		rorl  $22, %edx;           \
		rorl  $2, %eax;            \
		xorl  %edx, %ecx;          \
		xorl  %ecx, %eax;          \
		movl  %c, %ecx;            \
		addl  %eax, %h;            \
		movl  %c, %eax;            \
		orl   %b, %eax;            \
		andl  %b, %ecx;            \
		andl  %a, %eax;            \
		orl   %ecx, %eax;          \
		addl  %eax, %h;
	
	/* Save registers, allocate scratch space */
	movq  %r10, %xmm0
	movq  %r11, %xmm1
	movq  %r12, %xmm2
	movq  %r13, %xmm3
	movq  %r14, %xmm4
	movq  %r15, %xmm5
	movq  %rbx, %xmm6
	subq  $64, %rsp
	
	/* Load state */
#ifdef _WIN32
	movq  %rsi, %xmm7
	movq  %rdi, %xmm8
	movq  %rcx, %rdi
	movq  %rdx, %rsi
#endif
	movl   0(%rdi), %r8d   /* a */
	movl   4(%rdi), %r9d   /* b */
	movl   8(%rdi), %r10d  /* c */
	movl  12(%rdi), %r11d  /* d */
	movl  16(%rdi), %r12d  /* e */
	movl  20(%rdi), %r13d  /* f */
	movl  24(%rdi), %r14d  /* g */
	movl  28(%rdi), %r15d  /* h */
	
	/* Do 64 rounds of hashing */
	ROUNDa( 0, r8d , r9d , r10d, r11d, r12d, r13d, r14d, r15d,  0x428A2F98)
	ROUNDa( 1, r15d, r8d , r9d , r10d, r11d, r12d, r13d, r14d,  0x71374491)
	ROUNDa( 2, r14d, r15d, r8d , r9d , r10d, r11d, r12d, r13d, -0x4A3F0431)
	ROUNDa( 3, r13d, r14d, r15d, r8d , r9d , r10d, r11d, r12d, -0x164A245B)
	ROUNDa( 4, r12d, r13d, r14d, r15d, r8d , r9d , r10d, r11d,  0x3956C25B)
	ROUNDa( 5, r11d, r12d, r13d, r14d, r15d, r8d , r9d , r10d,  0x59F111F1)
	ROUNDa( 6, r10d, r11d, r12d, r13d, r14d, r15d, r8d , r9d , -0x6DC07D5C)
	ROUNDa( 7, r9d , r10d, r11d, r12d, r13d, r14d, r15d, r8d , -0x54E3A12B)
	ROUNDa( 8, r8d , r9d , r10d, r11d, r12d, r13d, r14d, r15d, -0x27F85568)
	ROUNDa( 9, r15d, r8d , r9d , r10d, r11d, r12d, r13d, r14d,  0x12835B01)
	ROUNDa(10, r14d, r15d, r8d , r9d , r10d, r11d, r12d, r13d,  0x243185BE)
	ROUNDa(11, r13d, r14d, r15d, r8d , r9d , r10d, r11d, r12d,  0x550C7DC3)
	ROUNDa(12, r12d, r13d, r14d, r15d, r8d , r9d , r10d, r11d,  0x72BE5D74)
	ROUNDa(13, r11d, r12d, r13d, r14d, r15d, r8d , r9d , r10d, -0x7F214E02)
	ROUNDa(14, r10d, r11d, r12d, r13d, r14d, r15d, r8d , r9d , -0x6423F959)
	ROUNDa(15, r9d , r10d, r11d, r12d, r13d, r14d, r15d, r8d , -0x3E640E8C)
	ROUNDb(16, r8d , r9d , r10d, r11d, r12d, r13d, r14d, r15d, -0x1B64963F)
	ROUNDb(17, r15d, r8d , r9d , r10d, r11d, r12d, r13d, r14d, -0x1041B87A)
	ROUNDb(18, r14d, r15d, r8d , r9d , r10d, r11d, r12d, r13d,  0x0FC19DC6)
	ROUNDb(19, r13d, r14d, r15d, r8d , r9d , r10d, r11d, r12d,  0x240CA1CC)
	ROUNDb(20, r12d, r13d, r14d, r15d, r8d , r9d , r10d, r11d,  0x2DE92C6F)
	ROUNDb(21, r11d, r12d, r13d, r14d, r15d, r8d , r9d , r10d,  0x4A7484AA)
	ROUNDb(22, r10d, r11d, r12d, r13d, r14d, r15d, r8d , r9d ,  0x5CB0A9DC)
	ROUNDb(23, r9d , r10d, r11d, r12d, r13d, r14d, r15d, r8d ,  0x76F988DA)
	ROUNDb(24, r8d , r9d , r10d, r11d, r12d, r13d, r14d, r15d, -0x67C1AEAE)
	ROUNDb(25, r15d, r8d , r9d , r10d, r11d, r12d, r13d, r14d, -0x57CE3993)
	ROUNDb(26, r14d, r15d, r8d , r9d , r10d, r11d, r12d, r13d, -0x4FFCD838)
	ROUNDb(27, r13d, r14d, r15d, r8d , r9d , r10d, r11d, r12d, -0x40A68039)
	ROUNDb(28, r12d, r13d, r14d, r15d, r8d , r9d , r10d, r11d, -0x391FF40D)
	ROUNDb(29, r11d, r12d, r13d, r14d, r15d, r8d , r9d , r10d, -0x2A586EB9)
	ROUNDb(30, r10d, r11d, r12d, r13d, r14d, r15d, r8d , r9d ,  0x06CA6351)
	ROUNDb(31, r9d , r10d, r11d, r12d, r13d, r14d, r15d, r8d ,  0x14292967)
	ROUNDb(32, r8d , r9d , r10d, r11d, r12d, r13d, r14d, r15d,  0x27B70A85)
	ROUNDb(33, r15d, r8d , r9d , r10d, r11d, r12d, r13d, r14d,  0x2E1B2138)
	ROUNDb(34, r14d, r15d, r8d , r9d , r10d, r11d, r12d, r13d,  0x4D2C6DFC)
	ROUNDb(35, r13d, r14d, r15d, r8d , r9d , r10d, r11d, r12d,  0x53380D13)
	ROUNDb(36, r12d, r13d, r14d, r15d, r8d , r9d , r10d, r11d,  0x650A7354)
	ROUNDb(37, r11d, r12d, r13d, r14d, r15d, r8d , r9d , r10d,  0x766A0ABB)
	ROUNDb(38, r10d, r11d, r12d, r13d, r14d, r15d, r8d , r9d , -0x7E3D36D2)
	ROUNDb(39, r9d , r10d, r11d, r12d, r13d, r14d, r15d, r8d , -0x6D8DD37B)
	ROUNDb(40, r8d , r9d , r10d, r11d, r12d, r13d, r14d, r15d, -0x5D40175F)
	ROUNDb(41, r15d, r8d , r9d , r10d, r11d, r12d, r13d, r14d, -0x57E599B5)
	ROUNDb(42, r14d, r15d, r8d , r9d , r10d, r11d, r12d, r13d, -0x3DB47490)
	ROUNDb(43, r13d, r14d, r15d, r8d , r9d , r10d, r11d, r12d, -0x3893AE5D)
	ROUNDb(44, r12d, r13d, r14d, r15d, r8d , r9d , r10d, r11d, -0x2E6D17E7)
	ROUNDb(45, r11d, r12d, r13d, r14d, r15d, r8d , r9d , r10d, -0x2966F9DC)
	ROUNDb(46, r10d, r11d, r12d, r13d, r14d, r15d, r8d , r9d , -0x0BF1CA7B)
	ROUNDb(47, r9d , r10d, r11d, r12d, r13d, r14d, r15d, r8d ,  0x106AA070)
	ROUNDb(48, r8d , r9d , r10d, r11d, r12d, r13d, r14d, r15d,  0x19A4C116)
	ROUNDb(49, r15d, r8d , r9d , r10d, r11d, r12d, r13d, r14d,  0x1E376C08)
	ROUNDb(50, r14d, r15d, r8d , r9d , r10d, r11d, r12d, r13d,  0x2748774C)
	ROUNDb(51, r13d, r14d, r15d, r8d , r9d , r10d, r11d, r12d,  0x34B0BCB5)
	ROUNDb(52, r12d, r13d, r14d, r15d, r8d , r9d , r10d, r11d,  0x391C0CB3)
	ROUNDb(53, r11d, r12d, r13d, r14d, r15d, r8d , r9d , r10d,  0x4ED8AA4A)
	ROUNDb(54, r10d, r11d, r12d, r13d, r14d, r15d, r8d , r9d ,  0x5B9CCA4F)
	ROUNDb(55, r9d , r10d, r11d, r12d, r13d, r14d, r15d, r8d ,  0x682E6FF3)
	ROUNDb(56, r8d , r9d , r10d, r11d, r12d, r13d, r14d, r15d,  0x748F82EE)
	ROUNDb(57, r15d, r8d , r9d , r10d, r11d, r12d, r13d, r14d,  0x78A5636F)
	ROUNDb(58, r14d, r15d, r8d , r9d , r10d, r11d, r12d, r13d, -0x7B3787EC)
	ROUNDb(59, r13d, r14d, r15d, r8d , r9d , r10d, r11d, r12d, -0x7338FDF8)
	ROUNDb(60, r12d, r13d, r14d, r15d, r8d , r9d , r10d, r11d, -0x6F410006)
	ROUNDb(61, r11d, r12d, r13d, r14d, r15d, r8d , r9d , r10d, -0x5BAF9315)
	ROUNDb(62, r10d, r11d, r12d, r13d, r14d, r15d, r8d , r9d , -0x41065C09)
	ROUNDb(63, r9d , r10d, r11d, r12d, r13d, r14d, r15d, r8d , -0x398E870E)
	
	/* Add to state */
	addl  %r8d ,  0(%rdi)
	addl  %r9d ,  4(%rdi)
	addl  %r10d,  8(%rdi)
	addl  %r11d, 12(%rdi)
	addl  %r12d, 16(%rdi)
	addl  %r13d, 20(%rdi)
	addl  %r14d, 24(%rdi)
	addl  %r15d, 28(%rdi)
	
	/* Restore registers */
	movq  %xmm0, %r10
	movq  %xmm1, %r11
	movq  %xmm2, %r12
	movq  %xmm3, %r13
	movq  %xmm4, %r14
	movq  %xmm5, %r15
	movq  %xmm6, %rbx
#ifdef _WIN32
	movq  %xmm7, %rsi
	movq  %xmm8, %rdi
#endif
	addq  $64, %rsp
	retq
    
#endif
