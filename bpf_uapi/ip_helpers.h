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

/*
 * Check whether @addr is an IPv4-compatible IPv6 address (::a.b.c.d).
 *
 * IPv4-compatible IPv6 addresses were defined for transition mechanisms but
 * have been deprecated by RFC 4291 and must not be used by new applications.
 */
static __always_inline int
xfw_is_ipv4_compatible_ipv6(const __be32 addr[4])
{
	return addr[0] == 0 && addr[1] == 0 && addr[2] == 0;
}

/*
 * Check whether @addr is an IPv4-mapped IPv6 address (::ffff:a.b.c.d).
 *
 * IPv4-mapped IPv6 addresses are used to represent IPv4 peers in the IPv6
 * socket API and remain part of the current IPv6 specification.
 */
static __always_inline int
xfw_is_ipv4_mapped_ipv6(const __be32 addr[4])
{
	return addr[0] == 0 && addr[1] == 0 && addr[2] == bpf_htonl(0xffff);
}

/*
 * Return true if @addr is an IPv4-embedded IPv6 address.
 *
 * Matches both deprecated IPv4-compatible (::a.b.c.d) and IPv4-mapped
 * (::ffff:a.b.c.d) IPv6 address formats.
 *
 * RFC 6890 marks these prefixes as invalid IPv6 packet source and
 * destination addresses (Source=False, Destination=False).
 */
static __always_inline bool
xfw_is_ipv4_embedded_ipv6(const __be32 addr[4])
{
	if (addr[0] || addr[1])
		return false;

	return addr[2] == 0 || addr[2] == bpf_htonl(0xffff);
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
