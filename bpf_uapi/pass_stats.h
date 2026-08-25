/**
 *	Tempesta BPF PASS packet statistics.
 *
 * SPDX-FileCopyrightText: © 2026 Tempesta Technologies, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#pragma once

#include "statistics_types.h"

enum XfwPassStat {
	/* Rule-based pass. */
	XFW_SRC_PORT_ALLOWED,
	XFW_SRC_IP_ALLOWED,
	XFW_ARP_INGRESS,
	XFW_GRE_INGRESS,
	XFW_SUPPORTED_PROTOCOL_INGRESS,

	/* Pass when rules are not loaded. */
	XFW_PRELOAD_INGRESS,

	/* Pass from TC on packet parsing failures. */
	XFW_L2_UNKNOWN_EGRESS,
	XFW_ETH_BADHDR_EGRESS,
	XFW_L4_UNSUPPORTED_EGRESS,
	XFW_IP4_BADHDR_EGRESS,
	XFW_IP6_BADHDR_EGRESS,
	XFW_TCP_BADHDR_EGRESS,
	XFW_UDP_BADHDR_EGRESS,

	/* Pass on internal errors. */
	XFW_METADATA_CREATION_FAILED,
	XFW_ASSERT_FAILED,

	XFW_PASS_STAT_MAX
};

#if defined(__clang__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wc99-designator"
// We intentionally use C99-style array designators ([index] = value)
// because this syntax makes the mapping between enum values and
// string literals explicit and less error-prone.
//
// GCC and Clang warn in C++ mode that this is a "C99 extension"
// (-Wc99-designator), but the generated code is perfectly valid and
// supported by both compilers. We suppress the warning to keep the
// initialization concise and consistent between C and C++ builds.
#endif
static const struct XfwStatInfo xfw_pass_stats[] = {
	[XFW_SRC_PORT_ALLOWED]			= {"xfw_src_port_allowed",
						   "Whitelisted by 'src_port: allow' rule"},
	[XFW_SRC_IP_ALLOWED]			= {"xfw_src_ip_allowed",
						   "Whitelisted by 'src_ip: allow' rule"},
	[XFW_ARP_INGRESS]			= { "xfw_arp_ingress",
						    "Allowed on parsing: ARP packet"},
	[XFW_GRE_INGRESS]			= { "xfw_gre_ingress",
						    "Allowed on parsing: GRE packet"},
	[XFW_SUPPORTED_PROTOCOL_INGRESS]	= { "xfw_supported_protocol_ingress",
						    "Allowed on parsing: packet "
						    "with supported protocol"},
	[XFW_PRELOAD_INGRESS]			= {"xfw_preload_ingress",
						   "Allowed: xFW rules are not loaded"},
	[XFW_L2_UNKNOWN_EGRESS]			= {"xfw_l2_unknown_egress",
						   "Allowed on parsing: unknown "
						   "EtherType"},
	[XFW_ETH_BADHDR_EGRESS]			= {"xfw_eth_badhdr_egress",
						   "Allowed on parsing: bad "
						   "ethernet header"},
	[XFW_L4_UNSUPPORTED_EGRESS]		= {"xfw_l4_unsupported_egress",
						   "Allowed on parsing: unsupported"
						   " IP proto"},
	[XFW_IP4_BADHDR_EGRESS]			= {"xfw_ip4_badhdr_egress",
						   "Allowed on parsing: IPv4 bad"
						   " header"},
	[XFW_IP6_BADHDR_EGRESS]			= {"xfw_ip6_badhdr_egress",
						   "Allowed on parsing: IPv6 bad"
						   " header"},
	[XFW_TCP_BADHDR_EGRESS]			= {"xfw_tcp_badhdr_egress",
						   "Allowed on parsing: TCP bad "
						   "header"},
	[XFW_UDP_BADHDR_EGRESS]			= {"xfw_udp_badhdr_egress",
						   "Allowed on parsing: UDP bad "
						   "header"},
	[XFW_METADATA_CREATION_FAILED]		= {"xfw_metadata_creation_failed",
						   "Internal error: metadata creation failed"},
	[XFW_ASSERT_FAILED]			= {"xfw_assert_failed",
						   "Internal error: internal assert failed"}
};
XFW_STAT_ARRAY_ASSERT(xfw_pass_stats, XFW_PASS_STAT_MAX);

#if defined(__clang__)
#pragma clang diagnostic pop
#endif
