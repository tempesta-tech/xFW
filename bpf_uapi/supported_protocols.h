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

enum XfwSupportedProtocols : uint8_t {
	ICMP			= 1,
	TCP			= 6,
	UDP			= 17,
	GRE			= 47,
	ICMPV6			= 58,
	XFW_SUPPORTED_PROTOCOL_MAX
};
