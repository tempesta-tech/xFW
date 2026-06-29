/**
 *	DefaultIndex enum
 *
 * SPDX-FileCopyrightText: © 2026 Tempesta Technologies, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#pragma once

/**
 * Indices for the "defaults_" array (default XFW rules).
 *
 * Each value corresponds to a specific combination of:
 *  - rule (src_ip, src_port, dst, icmp),
 *  - protocol (TCP / UDP ),
 *  - IP version (IPv4 / IPv6).
 *
 * These indices allow accessing array elements semantically, instead of using raw numbers.
 *
 * This enum is used **across different system layers**:
 *  - client application,
 *  - grpc serialization,
 *  - server representation,
 *  - eBPF program.
 */
enum DefaultIndex : uint8_t
{
	XFW_DEFAULT_SRC_IP_TCP_IP4,
	XFW_DEFAULT_SRC_IP_TCP_IP6,
	XFW_DEFAULT_SRC_IP_UDP_IP4,
	XFW_DEFAULT_SRC_IP_UDP_IP6,
	XFW_DEFAULT_SRC_PORT_TCP_IP4,
	XFW_DEFAULT_SRC_PORT_TCP_IP6,
	XFW_DEFAULT_SRC_PORT_UDP_IP4,
	XFW_DEFAULT_SRC_PORT_UDP_IP6,
	XFW_DEFAULT_DST_TCP_IP4,
	XFW_DEFAULT_DST_TCP_IP6,
	XFW_DEFAULT_DST_UDP_IP4,
	XFW_DEFAULT_DST_UDP_IP6,
	XFW_DEFAULT_ICMP_IP4,
	XFW_DEFAULT_ICMP_IP6,
	XFW_DEFAULT_MAX
};
