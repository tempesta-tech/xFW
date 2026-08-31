/**
 *	Tempesta xFW common compiler intrinsics & constants
 *
 * SPDX-FileCopyrightText: © 2026 Tempesta Technologies, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#pragma once

#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "../bpf_uapi/static_assert.h"

#ifndef UINT8_MAX
#define UINT8_MAX		255
#endif

#ifndef UINT16_MAX
#define UINT16_MAX		65535
#endif

#ifndef UINT64_MAX
#define UINT64_MAX		18446744073709551615ULL
#endif

#ifndef NSEC_PER_SEC
#define NSEC_PER_SEC		1000000000L
#endif

#ifndef E2BIG
#define E2BIG			7
#endif
#ifndef EINVAL
#define EINVAL			22
#endif

/* Resolved by libbpf from kernel configuration. */
extern unsigned long CONFIG_HZ __kconfig;
#define JIFFIES_PER_SEC		CONFIG_HZ

/* Defined in new bpf_helpers.h */
#ifndef likely
#define likely(X)              __builtin_expect(!!(X), 1)
#endif
#ifndef unlikely
#define unlikely(X)            __builtin_expect(!!(X), 0)
#endif

#define __packed		__attribute__((__packed__))

#ifndef memset
#define memset(dest, chr, n)	__builtin_memset((dest), (chr), (n))
#endif

#ifndef memcpy
#define memcpy(dest, src, n)	__builtin_memcpy((dest), (src), (n))
#endif

#ifndef memcmp
#define memcmp(s1, s2, n)	__builtin_memcmp((s1), (s2), (n))
#endif

#ifndef memmove
#define memmove(dest, src, n)	__builtin_memmove((dest), (src), (n))
#endif

#ifndef READ_ONCE
#define READ_ONCE(X)							\
({									\
	typeof(X) __val = *(volatile typeof(X) *)&(X);			\
	barrier();							\
	__val;								\
})
#endif

#ifndef WRITE_ONCE
#define WRITE_ONCE(X, V)						\
({									\
	typeof(X) __val = (V);						\
	(*(volatile typeof(X) *)&(X)) = (__val);			\
	barrier();							\
	__val;								\
})
#endif

#define SWAP(x, y)							\
do {									\
	typeof(x) t = x;						\
	x = y;								\
	y = t;								\
} while (0)
