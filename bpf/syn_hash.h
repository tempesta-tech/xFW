/*
 *	Tempesta xFW SYN tuple XXH64 hashing
 *
 * This implementation provides XXH64-based hashing for TCP SYN
 * tuple identification in eBPF/XDP programs.
 *
 * The hash algorithm is based on xxHash64 by Yann Collet.
 *
 * Original project:
 *   https://github.com/Cyan4973/xxHash
 *
 * Reference implementation:
 *   https://github.com/Cyan4973/xxHash/blob/dev/xxhash.c
 *
 * Implemented XXH64 primitives:
 *
 *   - XXH64_round()
 *   - XXH64_mergeRound()
 *   - XXH64_mergeAccs()
 *   - XXH64_avalanche()
 *
 * Packet-specific hashing functions use fixed-size serialized
 * TCP SYN tuples instead of the generic variable-length input
 * processing used by the original implementation.
 *
 * Adaptation for eBPF:
 *
 *   - no dynamic memory allocation;
 *   - no variable-length processing loops;
 *   - explicit little-endian loads for packet data;
 *   - verifier-friendly fixed-size operations.
 *
 * SPDX-FileCopyrightText: © 2026 Tempesta Technologies, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#pragma once

#include "xxh64_hash.h"
#include "../bpf_uapi/static_assert.h"

typedef struct XfwIpv4SynTuple {
	uint32_t src_ip;
	uint32_t dst_ip;
	uint32_t seq;
	uint16_t sport;
	uint16_t dport;
} XfwIpv4SynTuple;

typedef struct XfwIpv6SynTuple {
	uint8_t	src_ip[16];
	uint8_t dst_ip[16];
	uint32_t seq;
	uint16_t sport;
	uint16_t dport;
} XfwIpv6SynTuple;

/*
 * Build the final 64-bit block:
 *
 *	TCP initial sequence number
 *	source port
 *	destination port
 *
 * Layout in memory:
 *
 * offset 0:
 *	seq    (4 bytes)
 *
 * offset 4:
 *	sport  (2 bytes)
 *
 * offset 6:
 *	dport  (2 bytes)
 *
 * This corresponds to one XXH64 input block.
 */
static __always_inline uint64_t
syn_ports_seq(uint16_t sport, uint16_t dport, uint32_t seq)
{
	return (uint64_t)seq | ((uint64_t)sport << 32) |
		((uint64_t)dport << 48);
}

/*
 * Calculate xxHash64 for IPv4 SYN tuple.
 *
 * The serialized input layout is exactly 16 bytes:
 *
 * offset 0:
 *	src_ip      (4 bytes)
 *
 * offset 4:
 *	dst_ip      (4 bytes)
 *
 * offset 8:
 *	seq         (4 bytes)
 *
 * offset 12:
 *	sport       (2 bytes)
 *
 * offset 14:
 *	dport       (2 bytes)
 *
 * The layout matches the memory representation of
 * XfwIpv4SynTuple and therefore can be processed as two
 * consecutive 64-bit little-endian input blocks.
 *
 * The original XXH64 implementation processes remaining
 * input bytes in XXH64_finalize():
 *
 * Source:
 *   https://github.com/Cyan4973/xxHash/blob/dev/xxhash.h
 *
 * Relevant code:
 *
 *	while (len >= 8) {
 *		xxh_u64 const k1 = XXH64_round(0, XXH_get64bits(ptr));
 *		ptr += 8;
 *		hash ^= k1;
 *		hash = XXH_rotl64(hash, 27) * XXH_PRIME64_1 + XXH_PRIME64_4;
 *		len -= 8;
 *	}
 *
 * Since the SYN tuple size is fixed (16 bytes), the generic
 * xxHash loop is manually unrolled into two calls:
 *
 *	xxh64_update64(hash, first_8_bytes);
 *	xxh64_update64(hash, second_8_bytes);
 *
 * The initial hash value follows XXH64_endian_align():
 *
 *	h64 = seed + XXH_PRIME64_5;
 *	h64 += len;
 *
 * For a 16-byte input:
 *
 *	hash = seed + XXH_PRIME64_5 + 16;
 *
 * After all input blocks are processed, XXH64 applies the
 * avalanche stage.
 */
static __always_inline uint64_t
syn_xxh64_ipv4(XfwIpv4SynTuple *syn_tuple, uint64_t seed)
{
	uint64_t hash;
	uint64_t block;

	STATIC_ASSERT(sizeof(XfwIpv4SynTuple) == 16,
		      "XfwIpv4SynTuple size must be 16 bytes");

	/*
	 * Short input initialization.
	 *
	 * From XXH64_endian_align():
	 *
	 *     h64 = seed + PRIME64_5 + len
	 */
	hash = seed + XXH_PRIME64_5 + 16;

	/* Construct first 8-byte block. */
	block = (uint64_t)syn_tuple->src_ip |
		((uint64_t)syn_tuple->dst_ip << 32);
	hash = xxh64_update64(hash, block);

	/* Construct second 8-byte block. */
	block = syn_ports_seq(syn_tuple->sport, syn_tuple->dport,
			      syn_tuple->seq);
	hash = xxh64_update64(hash, block);

	return xxh64_avalanche(hash);
}

/*
 * Calculate XXH64 hash for IPv6 SYN tuple.
 *
 * Input size:
 *
 *	src IPv6     16 bytes
 *	dst IPv6     16 bytes
 *	seq           4 bytes
 *	sport         2 bytes
 *	dport         2 bytes
 *
 * Total:
 *
 *	40 bytes
 *
 * Because len >= 32, XXH64 does NOT use the short path.
 *
 * It uses:
 *
 *	XXH64_initAccs()
 *	XXH64_consumeLong()
 *	XXH64_mergeAccs()
 *
 * followed by XXH64_finalize().
 */
static __always_inline uint64_t
syn_xxh64_ipv6(XfwIpv6SynTuple *syn_tuple, uint64_t seed)
{
	uint64_t acc[4];
	uint64_t hash;
	uint64_t block;

	STATIC_ASSERT(sizeof(XfwIpv6SynTuple) == 40,
		      "XfwIpv6SynTuple size must be 40 bytes");

	/*
	 * Long input initialization (see XXH64_endian_align()).
	 *
	 * For inputs >= 32 bytes, XXH64 uses the long-input path:
	 *
	 *	XXH64_initAccs(acc, seed);
	 *
	 *	Input blocks are processed by:
	 *
	 *	XXH64_consumeLong(acc, input, len, align);
	 *
	 *	After all 32-byte chunks are consumed, the four
	 *	accumulators are merged:
	 *
	 *	h64 = XXH64_mergeAccs(acc);
	 *
	 * This implementation manually expands the fixed-size
	 * operations required for the IPv6 SYN tuple instead of
	 * using the generic variable-length loop.
	 */
	xxh64_init_accs(acc, seed);

	/*
	 * First 32 bytes:
	 *
	 * src IPv6 + dst IPv6
	 *
	 * Equivalent to four iterations of XXH64_consumeLong().
	 */
	block = xxh_load64_le(&syn_tuple->src_ip[0]);
	acc[0] = xxh64_round(acc[0], block);

	block = xxh_load64_le(&syn_tuple->src_ip[8]);
	acc[1] = xxh64_round(acc[1], block);

	block = xxh_load64_le(&syn_tuple->dst_ip[0]);
	acc[2] = xxh64_round(acc[2], block);

	block = xxh_load64_le(&syn_tuple->dst_ip[8]);
	acc[3] = xxh64_round(acc[3], block);

	hash = xxh64_merge_accs(acc);

	/*
	 * Add total input length.
	 *
	 * Source:
	 *
	 *     XXH64_endian_align()
	 *
	 * Original:
	 *
	 *     h64 += (xxh_u64)len;
	 *
	 * Total SYN tuple length is 40 bytes.
	 */
	hash += 40;

	/*
	 * Process the remaining 8 bytes.
	 *
	 * This corresponds to the first branch of
	 * XXH64_finalize():
	 *
	 *	while (len >= 8) {
	 *		...
	 *	}
	 *
	 * The generic loop is replaced with a single
	 * fixed-size operation because SYN tuple length
	 * is known at compile time.
	 */
	block = syn_ports_seq(syn_tuple->sport, syn_tuple->dport,
			      syn_tuple->seq);
	hash = xxh64_update64(hash, block);

	return xxh64_avalanche(hash);
}
