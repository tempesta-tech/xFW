/**
 *	Tempesta xFW helpers for IP headers
 *
 * SPDX-FileCopyrightText: © 2026 Tempesta Technologies, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#pragma once

#ifdef BPF_PROGRAM
#include "vmlinux.h"

#define HTONL	bpf_htonl

#else
#include <arpa/inet.h>
#include <linux/types.h>

#define HTONL	htonl
#endif

static __always_inline void
xfw_ipv4_to_ipv6_mapped(__be32 ipv4, __be32 addr[4])
{
	addr[0] = 0;
	addr[1] = 0;
	addr[2] = HTONL(0x0000ffff);
	addr[3] = ipv4;
}

static __always_inline bool
xfw_is_ipv6_mapped_to_ipv4(const __be32 addr[4])
{
	return (addr[0] == 0 && addr[1] == 0 &&
	       (addr[2] == 0 || addr[2] == HTONL(0xffff)));
}

static __always_inline void
xfw_ipv6_addr_cpy(__be32 *dst, const struct in6_addr *src)
{
#ifdef BPF_PROGRAM
	dst[0] = src->in6_u.u6_addr32[0];
	dst[1] = src->in6_u.u6_addr32[1];
	dst[2] = src->in6_u.u6_addr32[2];
	dst[3] = src->in6_u.u6_addr32[3];
#else
	memcpy(dst, src->s6_addr, sizeof(__be32) * 4);
#endif
}

static __always_inline void
xfw_assign_ip4_addr(__be32 ipv4, __be32 addr[4])
{
	addr[0] = 0;
	addr[1] = 0;
	addr[2] = 0;
	addr[3] = ipv4;
}
