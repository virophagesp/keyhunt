/*-
 * Copyright (c) 2015 Taylor R. Campbell
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * SHA-3: FIPS-202, Permutation-Based Hash and Extendable-Ouptut Functions
 */

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "keccak.h"

#include "sha3.h"

#define	MIN(a,b)	((a) < (b) ? (a) : (b))

void *(*volatile sha3_explicit_memset_impl)(void *, int, size_t) = &memset;
static void *
explicit_memset(void *buf, int c, size_t n)
{

	return (*sha3_explicit_memset_impl)(buf, c, n);
}

static inline uint64_t
le64dec(const void *buf)
{
	const uint8_t *p = (const uint8_t *)buf;

	return (((uint64_t)p[0]) |
	    ((uint64_t)p[1] << 8) |
	    ((uint64_t)p[2] << 16) |
	    ((uint64_t)p[3] << 24) |
	    ((uint64_t)p[4] << 32) |
	    ((uint64_t)p[5] << 40) |
	    ((uint64_t)p[6] << 48) |
	    ((uint64_t)p[7] << 56));
}

static inline void
le64enc(void *buf, uint64_t v)
{
	uint8_t *p = (uint8_t *)buf;

	*p++ = v; v >>= 8;
	*p++ = v; v >>= 8;
	*p++ = v; v >>= 8;
	*p++ = v; v >>= 8;
	*p++ = v; v >>= 8;
	*p++ = v; v >>= 8;
	*p++ = v; v >>= 8;
	*p++ = v;
}

/*
 * Common body.  All the SHA-3 functions share code structure.  They
 * differ only in the size of the chunks they split the message into:
 * for digest size d, they are split into chunks of 200 - d bytes.
 */

static inline unsigned
sha3_rate(unsigned d)
{
	const unsigned cw = 2*d/8;	/* capacity in words */

	return 25 - cw;
}

static void
sha3_init(struct sha3 *C, unsigned rw)
{
	unsigned iw;

	C->nb = 8*rw;
	for (iw = 0; iw < 25; iw++)
		C->A[iw] = 0;
}

static void
sha3_update(struct sha3 *C, const uint8_t *data, size_t len, unsigned rw)
{
	uint64_t T;
	unsigned ib, iw;		/* index of byte/word */

	assert(0 < C->nb);

	/* If there's a partial word, try to fill it.  */
	if ((C->nb % 8) != 0) {
		T = 0;
		for (ib = 0; ib < MIN(len, C->nb % 8); ib++)
			T |= (uint64_t)data[ib] << (8*ib);
		C->A[rw - (C->nb + 7)/8] ^= T << (8*(8 - (C->nb % 8)));
		C->nb -= ib;
		data += ib;
		len -= ib;

		/* If we filled the buffer, permute now.  */
		if (C->nb == 0) {
			keccakf1600(C->A);
			C->nb = 8*rw;
		}

		/* If that exhausted the input, we're done.  */
		if (len == 0)
			return;
	}

	/* At a word boundary.  Fill any partial buffer.  */
	assert((C->nb % 8) == 0);
	if (C->nb < 8*rw) {
		for (iw = 0; iw < MIN(len, C->nb)/8; iw++)
			C->A[rw - C->nb/8 + iw] ^= le64dec(data + 8*iw);
		C->nb -= 8*iw;
		data += 8*iw;
		len -= 8*iw;

		/* If we filled the buffer, permute now.  */
		if (C->nb == 0) {
			keccakf1600(C->A);
			C->nb = 8*rw;
		} else {
			/* Otherwise, less than a word left.  */
			assert(len < 8);
			goto partial;
		}
	}

	/* At a buffer boundary.  Absorb input one buffer at a time.  */
	assert(C->nb == 8*rw);
	while (8*rw <= len) {
		for (iw = 0; iw < rw; iw++)
			C->A[iw] ^= le64dec(data + 8*iw);
		keccakf1600(C->A);
		data += 8*rw;
		len -= 8*rw;
	}

	/* Partially fill the buffer with as many words as we can.  */
	for (iw = 0; iw < len/8; iw++)
		C->A[rw - C->nb/8 + iw] ^= le64dec(data + 8*iw);
	C->nb -= 8*iw;
	data += 8*iw;
	len -= 8*iw;

partial:
	/* Partially fill the last word with as many bytes as we can.  */
	assert(len < 8);
	assert(0 < C->nb);
	assert((C->nb % 8) == 0);
	T = 0;
	for (ib = 0; ib < len; ib++)
		T |= (uint64_t)data[ib] << (8*ib);
	C->A[rw - C->nb/8] ^= T;
	C->nb -= ib;
	assert(0 < C->nb);
}

static inline void
sha3_or_keccak_final(uint8_t *h, unsigned d, struct sha3 *C, unsigned rw, uint64_t padding)
{
	unsigned nw, iw;

	assert(d <= 8*25);
	assert(0 < C->nb);

	/* Append 01, pad with 10*1 up to buffer boundary, LSB first.  */
	nw = (C->nb + 7)/8;
	assert(0 < nw);
	assert(nw <= rw);
	C->A[rw - nw] ^= padding << (8*(8*nw - C->nb));
	C->A[rw - 1] ^= 0x8000000000000000ULL;

	/* Permute one last time.  */
	keccakf1600(C->A);

	/* Reveal the first 8d bits of state, forget 1600-8d of them.  */
	for (iw = 0; iw < d/8; iw++)
		le64enc(h + 8*iw, C->A[iw]);
	h += 8*iw;
	d -= 8*iw;
	if (0 < d) {
		/* For SHA3-224, we need to expose a partial word.  */
		uint64_t T = C->A[iw];
		do {
			*h++ = T & 0xff;
			T >>= 8;
		} while (--d);
	}
	(void)explicit_memset(C->A, 0, sizeof C->A);
	C->nb = 0;
}

static void
sha3_final(uint8_t *h, unsigned d, struct sha3 *C, unsigned rw)
{
    sha3_or_keccak_final(h, d, C, rw, 0x06);
}

static void
keccak_final(uint8_t *h, unsigned d, struct sha3 *C, unsigned rw)
{
    sha3_or_keccak_final(h, d, C, rw, 0x01);
}

void
SHA3_256_Init(SHA3_256_CTX *C)
{

	sha3_init(&C->C256, sha3_rate(SHA3_256_DIGEST_LENGTH));
}

void
SHA3_256_Update(SHA3_256_CTX *C, const uint8_t *data, size_t len)
{

	sha3_update(&C->C256, data, len, sha3_rate(SHA3_256_DIGEST_LENGTH));
}

void
SHA3_256_Final(uint8_t h[SHA3_256_DIGEST_LENGTH], SHA3_256_CTX *C)
{

	sha3_final(h, SHA3_256_DIGEST_LENGTH, &C->C256,
	    sha3_rate(SHA3_256_DIGEST_LENGTH));
}

void
KECCAK_256_Final(uint8_t h[SHA3_256_DIGEST_LENGTH], SHA3_256_CTX *C)
{

	keccak_final(h, SHA3_256_DIGEST_LENGTH, &C->C256,
	    sha3_rate(SHA3_256_DIGEST_LENGTH));
}
