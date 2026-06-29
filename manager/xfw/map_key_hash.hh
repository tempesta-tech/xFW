/**
 *	Tempesta xFW network data types
 *
 * SPDX-FileCopyrightText: © 2026 Tempesta Technologies, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#pragma once
#include <string.h>
#include "../../common/bpf_uapi_proto_keys.h"

template<typename T>
inline void
hash_combine(std::size_t &seed, const T &v) noexcept
{
	seed ^= std::hash<T>{}(v) + 0x9e3779b9 + (seed << 6) + (seed >> 2);
}

struct XfwIpv4LpmKeyHash
{
	std::size_t
	operator()(const XfwIpv4LpmKey &k) const noexcept
	{
		std::size_t h = 0;
		hash_combine(h, k.prefixlen);
		hash_combine(h, k.addr);
		return h;
	}
};

struct XfwIpv6LpmKeyHash
{
	std::size_t
	operator()(const XfwIpv6LpmKey &k) const noexcept
	{
		std::size_t h = 0;
		hash_combine(h, k.prefixlen);
		for (__be32 word : k.addr)
			hash_combine(h, word);
		return h;
	}
};

struct XfwDstKeyHash
{
	std::size_t
	operator()(const XfwDstKey &k) const noexcept
	{
		std::size_t h = 0;
		hash_combine(h, k.ipver);
		hash_combine(h, k.proto);
		hash_combine(h, k.port);
		for (__be32 word : k.addr.addr32)
			hash_combine(h, word);
		return h;
	}
};

struct XfwIcmpKeyHash
{
	std::size_t
	operator()(const XfwIcmpKey &k) const noexcept
	{
		std::size_t h = 0;
		hash_combine(h, k.proto);
		hash_combine(h, k.type);
		return h;
	}
};
