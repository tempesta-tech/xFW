/**
 *	Supported protocols in ip_proto filter
 *
 * SPDX-FileCopyrightText: © 2026 Tempesta Technologies, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#pragma once
#ifdef BPF_PROGRAM
#include "vmlinux.h"
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
	XFW_SUPPORTED_PROTOCOL_MAX
};
