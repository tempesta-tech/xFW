/**
 *	Tempesta xFW user-space API for the eBPF programs
 *
 * BPF map types, user-space access patterns, and alignment guidelines:
 * this section describes when alignment (padding / cacheline alignment)
 * is useful depending on map type and access pattern.
 *
 * 1. ARRAY / HASH maps (lookup/update only):
 * 
 * Kernel access:
 *   - bpf_map_lookup_elem()
 *   - bpf_map_update_elem()
 *
 * User-space:
 *   - single element access
 *   - no bulk memory interpretation
 *
 * Alignment:
 *   - NO special alignment required
 *   - use natural struct alignment
 *
 * Reason:
 *   kernel copies values by value_size, no shared raw buffer view
 *
 * 2. mmap-based maps (ARRAY / HASH mmap support):
 * 
 * Kernel access:
 *   - memory is directly mapped into user-space
 *
 * User-space:
 *   - direct pointer access to kernel memory
 *   - no copy, raw shared layout
 *
 * Alignment:
 *   - MUST match kernel-defined value_size layout
 *   - natural alignment is usually sufficient
 *   - DO NOT introduce artificial padding unless ABI defines it
 *
 * Optional:
 *   - alignas(64) ONLY if struct is per-CPU / hot-path
 *
 * 3. batch API (bulk operations):
 * 
 * Kernel access:
 *   - bpf_map_lookup_batch()
 *   - bpf_map_update_batch()
 *
 * User-space:
 *   - raw array buffer passed to kernel
 *
 * Alignment:
 *   - stable, fixed-size elements required
 *   - 8-byte alignment strongly recommended
 *   - alignas(64) optional for cache efficiency (not ABI requirement)
 *
 * Reason:
 *   kernel iterates over raw contiguous buffer
 *
 * 4. per-CPU maps (critical case):
 *
 * Kernel access:
 *   - per-CPU storage replicated per core
 *
 * User-space:
 *   - aggregation across CPUs
 *   - potential false sharing in user-space hot loops
 *
 * Alignment:
 *   - alignas(64) RECOMMENDED for per-CPU counters/buckets
 *   - prevents false sharing when user-space aggregates frequently
 *
 * 5. performance hot-path structures (non-ABI or shared hot state):
 * 
 * Use case:
 *   - rate limiters
 *   - counters updated at high frequency
 *   - lock-free shared stats
 *
 * Alignment:
 *   - alignas(64) recommended (cache line isolation)
 * 
 * SPDX-FileCopyrightText: © 2026 Tempesta Technologies, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#pragma once

#ifdef BPF_PROGRAM
#include "vmlinux.h"
#else
#include <arpa/inet.h>
#include <linux/types.h>
#endif

#include "protocols.h"
#include "static_assert.h"

#define XFW_IP_VER_4		1
#define XFW_IP_VER_6		2

enum {
	XFW_L4_PROTO_ICMP	= IPPROTO_ICMP,
	XFW_L4_PROTO_ICMPV6	= IPPROTO_ICMPV6,
	XFW_L4_PROTO_TCP	= IPPROTO_TCP,
	XFW_L4_PROTO_UDP	= IPPROTO_UDP,
};

typedef __be16		XfwPort;

typedef union {
	__be32		addr32[4];
	struct in6_addr	in6;
} XfwIp;

STATIC_ASSERT(sizeof(XfwIp) == sizeof(struct in6_addr), "Invalid XfwIp size");
STATIC_ASSERT(sizeof(XfwIp) == sizeof(__be32[4]), "Invalid XfwIp size");
STATIC_ASSERT(sizeof(XfwIp) == 16, "Invalid XfwIp size");
