/*
 *	Tempesta xFW XXH64 implementation
 *
 * This implementation is based on the xxHash algorithm
 * by Yann Collet and adapted for eBPF/XDP usage.
 *
 * The implementation follows the XXH64 reference algorithm,
 * including short and long input processing primitives:
 * - XXH64_round();
 * - XXH64_mergeRound();
 * - XXH64_mergeAccs();
 * - XXH64_avalanche().
 *
 * Packet-specific users can build fixed-size hashing paths
 * without generic variable-length processing required by
 * the original implementation.
 *
 * Original project:
 *   https://github.com/Cyan4973/xxHash
 *
 * The code is adapted for eBPF environment:
 * - no dynamic memory allocation;
 * - no variable-length processing loops;
 * - fixed-size packet tuple hashing;
 * - verifier-friendly operations.
 *
 * SPDX-FileCopyrightText: © 2026 Tempesta Technologies, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#pragma once

#ifdef BPF_PROGRAM
#include "vmlinux.h"
#else
#include <linux/types.h>
#endif

/**
 * xxHash64 prime constants.
 *
 * Source:
 *	xxhash.h
 *	XXH_PRIME64_*
 */
#define XXH_PRIME64_1 0x9E3779B185EBCA87ULL
#define XXH_PRIME64_2 0xC2B2AE3D27D4EB4FULL
#define XXH_PRIME64_3 0x165667B19E3779F9ULL
#define XXH_PRIME64_4 0x85EBCA77C2B2AE63ULL
#define XXH_PRIME64_5 0x27D4EB2F165667C5ULL

/**
 * Initialize four accumulators.
 *
 * Source:
 *	xxhash.h
 *	XXH64_initAccs()
 *
 * Original:
 *
 * acc[0] = seed + PRIME64_1 + PRIME64_2;
 * acc[1] = seed + PRIME64_2;
 * acc[2] = seed + 0;
 * acc[3] = seed - PRIME64_1;
 */
static __always_inline void
xxh64_init_accs(__u64 acc[4], __u64 seed)
{
	acc[0] = seed + XXH_PRIME64_1 + XXH_PRIME64_2;
	acc[1] = seed + XXH_PRIME64_2;
	acc[2] = seed;
	acc[3] = seed - XXH_PRIME64_1;
}

/**
 * Load 8 bytes as little-endian uint64.
 *
 * This replaces:
 *
 *	XXH_get64bits(ptr)
 *
 * from xxHash.
 */
static __always_inline __u64
xxh_load64_le(const __u8 *p)
{
	return ((__u64)p[0]) | ((__u64)p[1] << 8) | ((__u64)p[2] << 16) |
	       ((__u64)p[3] << 24) | ((__u64)p[4] << 32) |
	       ((__u64)p[5] << 40) | ((__u64)p[6] << 48) |
	       ((__u64)p[7] << 56);
}

/**
 * Rotate left operation.
 *
 * Equivalent to XXH_rotl64() from xxHash reference implementation.
 *
 * The xxHash userspace implementation selects architecture-specific
 * intrinsics, while eBPF uses the portable shift/or implementation
 * accepted by the verifier.
 */
static __always_inline __u64
xxh_rotl64(__u64 x, __u32 r)
{
	return (x << r) | (x >> (64 - r));
}

/**
 * xxHash64 mixing round.
 *
 * Source:
 *	xxhash.h
 *	XXH64_round()
 *
 * Original code:
 *
 * acc += input * PRIME64_2;
 * acc = XXH_rotl64(acc,31);
 * acc *= PRIME64_1;
 */
static __always_inline __u64
xxh64_round(__u64 acc, __u64 input)
{
	acc += input * XXH_PRIME64_2;
	acc = xxh_rotl64(acc, 31);
	acc *= XXH_PRIME64_1;

	return acc;
}

/**
 * Merge one accumulator into the final XXH64 hash state.
 *
 * Source:
 *	xxhash.h
 *	XXH64_mergeRound()
 *
 * Original:
 *
 * val  = XXH64_round(0, val);
 * acc ^= val;
 * acc  = acc * XXH_PRIME64_1 + XXH_PRIME64_4;
 */
static __always_inline __u64
xxh64_merge_round(__u64 acc, __u64 val)
{
	val  = xxh64_round(0, val);
	acc ^= val;
	acc  = acc * XXH_PRIME64_1 + XXH_PRIME64_4;

	return acc;
}

/**
 * Merge four accumulators.
 *
 * Source:
 *	xxhash.h
 *	XXH64_mergeAccs()
 *
 * Original:
 *
 * h64 = rotl(acc[0],1) + rotl(acc[1],7)
 *       + rotl(acc[2],12) + rotl(acc[3],18);
 *
 * h64 = XXH64_mergeRound(h64, acc[0]);
 * h64 = XXH64_mergeRound(h64, acc[1]);
 * h64 = XXH64_mergeRound(h64, acc[2]);
 * h64 = XXH64_mergeRound(h64, acc[3]);
 */
static __always_inline __u64
xxh64_merge_accs(__u64 acc[4])
{
	__u64 h64;

	h64 = xxh_rotl64(acc[0], 1) + xxh_rotl64(acc[1], 7) +
	      xxh_rotl64(acc[2], 12) + xxh_rotl64(acc[3], 18);

	h64 = xxh64_merge_round(h64, acc[0]);
	h64 = xxh64_merge_round(h64, acc[1]);
	h64 = xxh64_merge_round(h64, acc[2]);
	h64 = xxh64_merge_round(h64, acc[3]);

	return h64;
}

/**
 * Process one 64-bit input block.
 *
 * This helper extracts the 8-byte processing step from
 * XXH64_finalize() in the xxHash reference implementation.
 *
 * Original source:
 *   https://github.com/Cyan4973/xxHash/blob/dev/xxhash.c
 *
 * Original code from XXH64_finalize():
 *
 *	while (len >= 8) {
 *		xxh_u64 const k1 = XXH64_round(0, XXH_get64bits(ptr));
 *
 *		ptr += 8;
 *		hash ^= k1;
 *		hash = XXH_rotl64(hash, 27) * XXH_PRIME64_1 + XXH_PRIME64_4;
 *		len -= 8;
 *	}
 *
 * This implementation replaces XXH_get64bits(ptr) with
 * a pre-packed 64-bit input value. The caller must ensure
 * that the value has the same little-endian byte layout as
 * the original input buffer.
 *
 * The generic xxHash implementation processes arbitrary-size
 * input using a loop. For SYN flood protection the hashed
 * tuple size is known in advance, so eBPF code can unroll the
 * required number of 64-bit block operations and avoid
 * variable-length processing.
 */
static __always_inline __u64
xxh64_update64(__u64 hash, __u64 input)
{
	const __u64 k1 = xxh64_round(0, input);

	hash ^= k1;
	hash = xxh_rotl64(hash, 27) * XXH_PRIME64_1 + XXH_PRIME64_4;
	
	return hash;
}

/*
 * Final avalanche step.
 *
 * Source:
 *	xxhash.h
 *	XXH64_avalanche()
 *
 * Original code:
 *
 * h ^= h >> 33;
 * h *= PRIME64_2;
 * h ^= h >> 29;
 * h *= PRIME64_3;
 * h ^= h >> 32;
 */
static __always_inline __u64
xxh64_avalanche(__u64 h)
{
	h ^= h >> 33;
	h *= XXH_PRIME64_2;
	h ^= h >> 29;
	h *= XXH_PRIME64_3;
	h ^= h >> 32;

	return h;
}
