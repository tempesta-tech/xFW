/**
 *	Tempesta xFW L3/L4 protocol-specific user-space API
 *
 * See the rules for shared struct declarations in bpf_uapi.h.
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

#include "bpf_uapi.h"

#ifdef __cplusplus
#include "ip_helpers.h"
#endif

typedef struct XfwIpv4LpmKey {
	uint32_t	prefixlen;
	__be32		addr;

#ifdef __cplusplus
	bool operator==(const XfwIpv4LpmKey&) const = default;
#endif
} XfwIpv4LpmKey;

typedef struct XfwIpv6LpmKey {
	uint32_t	prefixlen;
	__be32		addr[4];
	
#ifdef __cplusplus
	bool operator==(const XfwIpv6LpmKey&) const = default;
#endif
} XfwIpv6LpmKey;

/*
 * @proto		- ICMP for IPv4 or IPv6 protocol ID
 * @type		- ICMP message type
 */
typedef struct XfwIcmpKey {
	uint8_t		proto;
	uint8_t		type;

#ifdef __cplusplus
	explicit XfwIcmpKey(uint8_t p) noexcept
		: proto(p)
		, type(UINT8_MAX)
	{}

	XfwIcmpKey() noexcept
		: proto(UINT8_MAX)
		, type(UINT8_MAX)
	{}

	bool operator==(const XfwIcmpKey&) const = default;
#endif
} XfwIcmpKey;

/**
 * @ipver		- IP protocol version
 * @proto		- L4 proto field from an IP header
 * @addr		- IP address, zero-prefixed for IPv4
 */
typedef struct XfwDstKey {
	uint8_t		ipver;
	uint8_t		proto;
	XfwPort		port;
	XfwIp		addr;

#ifdef __cplusplus
	XfwDstKey() noexcept
		: ipver{ 0 }
		, proto{ 0 }
		, port{ 0 }
		, addr{}
	{}

	explicit XfwDstKey(uint8_t ipver, uint8_t l4_proto, __be16 port,
			   __be32 ip) noexcept
		: ipver(ipver)
		, proto(l4_proto)
		, port(port)
	{
		xfw_ipv4_to_ipv6_mapped(ip, addr.addr32);
	}

	explicit XfwDstKey(uint8_t ipver, uint8_t l4_proto, __be16 port,
			   __be32 ip6_0, __be32 ip6_1, __be32 ip6_2,
			   __be32 ip6_3) noexcept
		: ipver(ipver)
		, proto(l4_proto)
		, port(port)
		, addr{ .addr32 = { ip6_0, ip6_1, ip6_2, ip6_3 } }
	{}

	bool
	operator==(const XfwDstKey &k) const noexcept
	{
		return memcmp(this, &k, sizeof(*this)) == 0;
	}
#endif
} XfwDstKey;
STATIC_ASSERT(sizeof(XfwDstKey) == 20, "Invalid XfwDstKey size");
