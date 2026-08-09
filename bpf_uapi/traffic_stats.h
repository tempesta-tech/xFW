/**
 *	Tempesta Bpf trafic statistic.
 *
 * SPDX-FileCopyrightText: © 2026 Tempesta Technologies, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#pragma once

#include "statistics_types.h"

enum XfwTrafficStat {
	XFW_SYN,
	XFW_ACK,
	XFW_SYNACK,
	XFW_FIN,
	XFW_RST,
	XFW_IP4_TOTAL_INGRESS,
	XFW_IP6_TOTAL_INGRESS,
	XFW_TCP_TOTAL_INGRESS,
	XFW_UDP_TOTAL_INGRESS,
	XFW_ICMP_TOTAL_INGRESS,
	XFW_TOTAL_DOWNSTREAM_INGRESS,
	XFW_PASSED_DOWNSTREAM_INGRESS,
	XFW_IP4_TOTAL_EGRESS,
	XFW_IP6_TOTAL_EGRESS,
	XFW_TCP_TOTAL_EGRESS,
	XFW_UDP_TOTAL_EGRESS,
	XFW_TOTAL_DOWNSTREAM_EGRESS,
	XFW_TOTAL_UPSTREAM_EGRESS,
	XFW_PASSED_DOWNSTREAM_EGRESS,
	XFW_PASSED_UPSTREAM_EGRESS,
	XFW_SYNCOOKIE_RECEIVED,

	XFW_TRAFFIC_STAT_MAX
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
static const struct XfwStatInfo xfw_traffic_stats[] = {
	[XFW_SYN]				= {"xfw_syn",
						   "Packets with SYN"},
	[XFW_ACK]				= {"xfw_ack",
						   "Packets with ACK"},
	[XFW_SYNACK]				= {"xfw_synack",
						   "Packets with SYN+ACK"},
	[XFW_FIN]				= {"xfw_fin",
						   "Packets with FIN"},
	[XFW_RST]				= {"xfw_rst",
						   "Packets with RST"},
	[XFW_IP4_TOTAL_INGRESS]			= {"xfw_ip4_total_ingress",
						   "IPv4 total ingress"},
	[XFW_IP6_TOTAL_INGRESS]			= {"xfw_ip6_total_ingress",
						   "IPv6 total ingress"},
	[XFW_TCP_TOTAL_INGRESS]			= {"xfw_tcp_total_ingress",
						   "TCP total ingress"},
	[XFW_UDP_TOTAL_INGRESS]			= {"xfw_udp_total_ingress",
						   "UDP total ingress"},
	[XFW_ICMP_TOTAL_INGRESS]		= {"xfw_icmp_total_ingress",
						   "ICMP total ingress"},
	[XFW_TOTAL_DOWNSTREAM_INGRESS]		= {"xfw_total_downstream_ingress",
						   "Total trafic from downstream to xFW"},
	[XFW_PASSED_DOWNSTREAM_INGRESS]		= {"xfw_passed_downstream_ingress",
						   "Passed trafic from downstream to xFW"},
	[XFW_IP4_TOTAL_EGRESS]			= {"xfw_ip4_total_egress",
						   "IP4 total egress"},
	[XFW_IP6_TOTAL_EGRESS]			= {"xfw_ip6_total_egress",
						   "IP6 total egress"},
	[XFW_TCP_TOTAL_EGRESS]			= {"xfw_tcp_total_egress",
						   "TPC total egress"},
	[XFW_UDP_TOTAL_EGRESS]			= {"xfw_udp_total_egress",
						   "UDP total egress"},
	[XFW_TOTAL_DOWNSTREAM_EGRESS]		= {"xfw_total_downstream_egress",
						   "Total trafic from xFW to upstream"},
	[XFW_TOTAL_UPSTREAM_EGRESS]		= {"xfw_total_upstream_egress",
						   "Total trafic from xFW to downstream"},
	[XFW_PASSED_DOWNSTREAM_EGRESS]		= {"xfw_passed_downstream_egress",
						   "Passed trafic from xFW to upstream"},
	[XFW_PASSED_UPSTREAM_EGRESS]		= {"xfw_passed_upstream_egress",
						   "Passed trafic from xFW to downstream"},
	[XFW_SYNCOOKIE_RECEIVED]		= {"xfw_syncookie_received",
						   "Received packet with valid syncookie"}
};
XFW_STAT_ARRAY_ASSERT(xfw_traffic_stats, XFW_TRAFFIC_STAT_MAX);

#if defined(__clang__)
#pragma clang diagnostic pop
#endif
