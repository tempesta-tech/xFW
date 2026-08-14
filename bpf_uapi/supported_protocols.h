/**
 *	Supported protocols in ip_proto filter
 *
 * SPDX-FileCopyrightText: © 2026 Tempesta Technologies, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#pragma once
#ifdef BPF_PROGRAM
#include "vmlinux.h"
#include "../bpf/compiler.h"
#else
#include <cstdint>
#endif

#include "protocols.h"

enum XfwSupportedProtocols : uint8_t {
	XFW_L4_PROTO_ICMP		= IPPROTO_ICMP,
	XFW_L4_PROTO_TCP		= IPPROTO_TCP,
	XFW_L4_PROTO_UDP		= IPPROTO_UDP,
	XFW_L4_PROTO_GRE		= IPPROTO_GRE,
	XFW_L4_PROTO_ICMPV6		= IPPROTO_ICMPV6,
	/*
	 * The IPv4 Protocol and IPv6 Next Header fields are 8 bits wide
	 * (RFC 791, RFC 8200), so there are 256 possible protocol values.
	 */
	XFW_SUPPORTED_PROTOCOL_MAX	= UINT8_MAX
};
