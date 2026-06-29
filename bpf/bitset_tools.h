/**
 *	Tempesta xFW bitset operations
 *
 * SPDX-FileCopyrightText: © 2026 Tempesta Technologies, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#pragma once
#include "../generated/vmlinux.h"

/**
 * Inline BPF-compatible set/test functions for uint64_t array
 * - Assumes idx <= MaxBit
 * - No runtime checks (Verifier-friendly)
 * 
 * Note: We cannot use inline assembly in eBPF programs, so we rely on
 * standard C bitwise operations to manipulate the bitset.
 */
static __always_inline void
bpf_bitset64_set(uint64_t *bits, uint8_t idx)
{
	bits[idx / 64] |= ((uint64_t)1 << (idx % 64));
}

static __always_inline bool
bpf_bitset64_test(const uint64_t *bits, uint8_t idx)
{
	return (bits[idx / 64] & ((uint64_t)1 << (idx % 64))) != 0;
}
