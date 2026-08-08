/*
 *	Tempesta xFW Jenkins hash implementation
 *
 * This file is based on the Linux kernel implementation of Jenkins hash
 * (jhash), originally derived from Bob Jenkins' lookup3 algorithm.
 *
 * Original Linux kernel source:
 *   include/linux/jhash.h
 *
 * Original algorithm:
 *   https://burtleburtle.net/bob/hash/
 *
 * The code has been minimally adapted to allow building and running
 * Tempesta xFW benchmarks in userspace:
 * - Linux kernel dependencies removed;
 * - userspace-compatible types and helpers used;
 * - hash algorithm preserved.
 *
 * No functional changes to the hashing algorithm were intentionally made.
 *
 * SPDX-FileCopyrightText: © 2026 Tempesta Technologies, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#pragma once

#include <stdint.h>
#include <stddef.h>

static inline uint32_t
rol32(uint32_t word, unsigned int shift)
{
	return (word << shift) | (word >> (32 - shift));
}

static inline uint32_t
__get_unaligned_cpu32(const void *p)
{
	const uint8_t *b = (const uint8_t *)p;

	return ((uint32_t)b[0]) |
	       ((uint32_t)b[1] << 8) |
	       ((uint32_t)b[2] << 16) |
	       ((uint32_t)b[3] << 24);
}

/* Best hash sizes are of power of two */
#define jhash_size(n)   ((uint32_t)1<<(n))
/* Mask the hash value, i.e (value & jhash_mask(n)) instead of (value % n) */
#define jhash_mask(n)   (jhash_size(n)-1)

/* __jhash_mix -- mix 3 32-bit values reversibly. */
#define __jhash_mix(a, b, c)			\
{						\
	a -= c;  a ^= rol32(c, 4);  c += b;	\
	b -= a;  b ^= rol32(a, 6);  a += c;	\
	c -= b;  c ^= rol32(b, 8);  b += a;	\
	a -= c;  a ^= rol32(c, 16); c += b;	\
	b -= a;  b ^= rol32(a, 19); a += c;	\
	c -= b;  c ^= rol32(b, 4);  b += a;	\
}

/* __jhash_final - final mixing of 3 32-bit values (a,b,c) into c */
#define __jhash_final(a, b, c)			\
{						\
	c ^= b; c -= rol32(b, 14);		\
	a ^= c; a -= rol32(c, 11);		\
	b ^= a; b -= rol32(a, 25);		\
	c ^= b; c -= rol32(b, 16);		\
	a ^= c; a -= rol32(c, 4);		\
	b ^= a; b -= rol32(a, 14);		\
	c ^= b; c -= rol32(b, 24);		\
}

/* An arbitrary initial parameter */
#define JHASH_INITVAL		0xdeadbeef

/* jhash - hash an arbitrary key
 * @k: sequence of bytes as key
 * @length: the length of the key
 * @initval: the previous hash, or an arbitray value
 *
 * The generic version, hashes an arbitrary sequence of bytes.
 * No alignment or length assumptions are made about the input key.
 *
 * Returns the hash value of the key. The result depends on endianness.
 */
static inline uint32_t
jhash(const void *key, uint32_t length, uint32_t initval)
{
	uint32_t a, b, c;
	const uint8_t *k = (uint8_t *)key;

	/* Set up the internal state */
	a = b = c = JHASH_INITVAL + length + initval;

	/* All but the last block: affect some 32 bits of (a,b,c) */
	while (length > 12) {
		a += __get_unaligned_cpu32(k);
		b += __get_unaligned_cpu32(k + 4);
		c += __get_unaligned_cpu32(k + 8);
		__jhash_mix(a, b, c);
		length -= 12;
		k += 12;
	}

	/* Last block: affect all 32 bits of (c) */
	switch (length) {
	case 12:
		c += (uint32_t)k[11] << 24;
		__attribute__((fallthrough));
	case 11:
		c += (uint32_t)k[10] << 16;
		__attribute__((fallthrough));
	case 10:
		c += (uint32_t)k[9] << 8;
		__attribute__((fallthrough));
	case 9:
		c += k[8];
		__attribute__((fallthrough));
	case 8:
		b += (uint32_t)k[7] << 24;
		__attribute__((fallthrough));
	case 7:
		b += (uint32_t)k[6] << 16;
		__attribute__((fallthrough));
	case 6:
		b += (uint32_t)k[5] << 8;
		__attribute__((fallthrough));
	case 5:
		b += k[4];
		__attribute__((fallthrough));
	case 4:
		a += (uint32_t)k[3] << 24;
		__attribute__((fallthrough));
	case 3:
		a += (uint32_t)k[2] << 16;
		__attribute__((fallthrough));
	case 2:
		a += (uint32_t)k[1] << 8;
		__attribute__((fallthrough));
	case 1:
		a += k[0];
		__jhash_final(a, b, c);
		break;
	case 0:
		/* Nothing left to add */
		break;
	}

	return c;
}

/* jhash2 - hash an array of uint32_t's
 * @k: the key which must be an array of uint32_t's
 * @length: the number of uint32_t's in the key
 * @initval: the previous hash, or an arbitray value
 *
 * Returns the hash value of the key.
 */
static inline uint32_t
jhash2(const uint32_t *k, uint32_t length, uint32_t initval)
{
	uint32_t a, b, c;

	/* Set up the internal state */
	a = b = c = JHASH_INITVAL + (length << 2) + initval;

	/* Handle most of the key */
	while (length > 3) {
		a += k[0];
		b += k[1];
		c += k[2];
		__jhash_mix(a, b, c);
		length -= 3;
		k += 3;
	}

	/* Handle the last 3 uint32_t's */
	switch (length) {
	case 3:
		c += k[2];
		__attribute__((fallthrough));
	case 2:
		b += k[1];
		__attribute__((fallthrough));
	case 1: a += k[0];
		__jhash_final(a, b, c);
		break;
	case 0:	/* Nothing left to add */
		break;
	}

	return c;
}


/* __jhash_nwords - hash exactly 3, 2 or 1 word(s) */
static inline uint32_t
__jhash_nwords(uint32_t a, uint32_t b, uint32_t c, uint32_t initval)
{
	a += initval;
	b += initval;
	c += initval;

	__jhash_final(a, b, c);

	return c;
}

static inline uint32_t
jhash_3words(uint32_t a, uint32_t b, uint32_t c, uint32_t initval)
{
	return __jhash_nwords(a, b, c, initval + JHASH_INITVAL + (3 << 2));
}

static inline uint32_t
jhash_2words(uint32_t a, uint32_t b, uint32_t initval)
{
	return __jhash_nwords(a, b, 0, initval + JHASH_INITVAL + (2 << 2));
}

static inline uint32_t
jhash_1word(uint32_t a, uint32_t initval)
{
	return __jhash_nwords(a, 0, 0, initval + JHASH_INITVAL + (1 << 2));
}
