/**
 *	Tempesta xFW bitset, shared between ebpf program and user-space tools
 *
 * Note: we don't include system headers as bpf uses generated vmlinux.h,
 * but user-space tools are using system headers.
 *
 * SPDX-FileCopyrightText: © 2026 Tempesta Technologies, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#pragma once

#ifndef BPF_PROGRAM
#include <linux/types.h>
#else
#include "vmlinux.h"
#endif

#include "static_assert.h"
/**
 * Compute byte count / uint64_t count for given number of bits.
 */
#define BITSET_BYTE_COUNT(bits) (((bits) + 7) / 8)
#define BITSET_U64_COUNT(bits)  (((bits) + 63) / 64)

/**
 * Declare a fixed-size BPF-compatible bitset
 *
 * @param name - struct name
 * @param MaxBit - maximum bit index (enum-like)
 *
 * Example:
 *   DECLARE_BITSET64(MyBitset, 127);
 */
#define DECLARE_BITSET64(name, MaxBit)					\
typedef struct								\
{									\
	STATIC_ASSERT((MaxBit) > 0, "BitSet must be > 0");		\
	STATIC_ASSERT(BITSET_U64_COUNT(MaxBit+1) * 64 >= (MaxBit+1),	\
		      "Invalid U64 count");				\
	uint64_t data[BITSET_U64_COUNT(MaxBit+1)];				\
}  __attribute__((aligned(64))) name
