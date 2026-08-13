/**
 *	Tempesta xFW DROP packet statistics.
 *
 * This statistic is logged as security events to ClickHouse.
 *
 * SPDX-FileCopyrightText: © 2026 Tempesta Technologies, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#pragma once

#include "statistics_types.h"

enum XfwDropStat {
	XFW_DROP_ICMP_BLOCKED,
	XFW_DROP_SYN_RATE_LIMITED,
	XFW_DROP_RST_RATE_LIMITED,
	XFW_DROP_ICMP_RATE_LIMITED,
	XFW_DROP_ICMP_DEFAULT_BLOCKED,
	XFW_DROP_ICMP_DEFAULT_RATE_LIMITED,
	XFW_DROP_DST_BLOCKED,
	XFW_DROP_DST_RATE_LIMITED,
	XFW_DROP_SRC_PORT_BLOCKED,
	XFW_DROP_SRC_PORT_RATE_LIMITED,
	XFW_DROP_SRC_PORT_DEFAULT_BLOCKED,
	XFW_DROP_SRC_PORT_DEFAULT_RATE_LIMITED,
	XFW_DROP_SRC_IP_BLOCKED,
	XFW_DROP_SRC_IP_RATE_LIMITED,
	XFW_DROP_SRC_IP_DEFAULT_BLOCKED,
	XFW_DROP_SRC_IP_DEFAULT_RATE_LIMITED,
	XFW_DROP_TCP_ANOM_BAD_FLAGS,
	XFW_DROP_TCP_ANOM_SYN_BAD_SEQ,
	XFW_DROP_TCP_ANOM_SYN_NO_OPTIONS,
	XFW_DROP_TCP_ANOM_SYN_HAS_DATA,
	XFW_DROP_TCP_ANOM_ZERO_PORT,
	XFW_DROP_UDP_ANOM_ZERO_PORT,
	XFW_DROP_L2_UNKNOWN_INGRESS,
	XFW_DROP_ETH_BADHDR_INGRESS,
	XFW_DROP_IP4_BADHDR_INGRESS,
	XFW_DROP_IP4_FRAGMENTED_INGRESS,
	XFW_DROP_IP6_BADHDR_INGRESS,
	XFW_DROP_IP6_FRAGMENTED_INGRESS,
	XFW_DROP_TCP_BADHDR_INGRESS,
	XFW_DROP_UDP_BADHDR_INGRESS,
	XFW_DROP_ICMP_BADHDR_INGRESS,
	XFW_DROP_L4_UNSUPPORTED_INGRESS,
	XFW_DROP_TCP_AUTH_FAILED,
	XFW_DROP_TCP_AUTH_TIMEOUT,
	XFW_DROP_SYNCOOKIE_FAILED,
	XFW_DROP_SYN_BLOCKED,
	XFW_DROP_DNS_BADHDR_INGRESS,
	XFW_DROP_DNS_QRY_RCODE_NOT_OK,
	XFW_DROP_DNS_BAD_QUESTION,
	XFW_DROP_DNS_MULTIPLE_QUESTIONS,
	XFW_DROP_DNS_ANS_OR_AUTHS_IN_QUERY,
	XFW_DROP_DNS_IXFR_ANOMALY,
	XFW_DROP_DNS_QRY_BAD_ARCOUNT,
	XFW_DROP_DNS_NOT_ASKED_RESPONSE,
	XFW_DROP_DNS_LARGE_RESPONSE,
	XFW_DROP_DNS_RESP_ANS_OVERLIMIT,
	XFW_DROP_DNS_BAD_RR,
	XFW_DROP_DNS_ANSWER_ANOMALY,

	XFW_DROP_STAT_MAX
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
static const struct XfwStatInfo xfw_drop_stats[] = {
	[XFW_DROP_ICMP_BLOCKED]			= {"xfw_icmp_blocked",
						   "Blocked by 'icmp: block' rule"},
	[XFW_DROP_SYN_RATE_LIMITED]		= {"xfw_syn_rate_limited",
						   "Blocked by 'tcp_flags syn: "
						   "ratelimit' rule"},
	[XFW_DROP_RST_RATE_LIMITED]		= {"xfw_rst_rate_limited",
						   "Blocked by 'tcp_flags rst: "
						   "ratelimit' rule"},
	[XFW_DROP_ICMP_RATE_LIMITED]		= {"xfw_icmp_rate_limited",
						   "Blocked by 'icmp: ratelimit' rule"},
	[XFW_DROP_ICMP_DEFAULT_BLOCKED]		= {"xfw_icmp_default_blocked",
						   "Blocked by 'defaults/icmp: "
						   "block' rule"},
	[XFW_DROP_ICMP_DEFAULT_RATE_LIMITED]	= {"xfw_icmp_default_rate_limited",
						   "Blocked by 'defaults/icmp: "
						   "ratelimit' rule"},
	[XFW_DROP_DST_BLOCKED]			= {"xfw_dst_blocked",
						   "Blocked by 'dst: block' rule"},
	[XFW_DROP_DST_RATE_LIMITED]		= {"xfw_dst_rate_limited",
						   "Blocked by 'dst: ratelimit' rule"},
	[XFW_DROP_SRC_PORT_BLOCKED]		= {"xfw_src_port_blocked",
						   "Blocked by 'src_port: block' rule"},
	[XFW_DROP_SRC_PORT_RATE_LIMITED]	= {"xfw_src_port_rate_limited",
						   "Blocked by 'src_port: ratelimit' rule"},
	[XFW_DROP_SRC_PORT_DEFAULT_BLOCKED]	= {"xfw_src_port_default_blocked",
						   "Blocked by 'defaults/src_port: "
						   "block' rule"},
	[XFW_DROP_SRC_PORT_DEFAULT_RATE_LIMITED] = {"xfw_src_port_default_rate_limited",
						    "Blocked by 'defaults/src_port: "
						    "ratelimit' rule"},
	[XFW_DROP_SRC_IP_BLOCKED]		= {"xfw_src_ip_blocked",
						   "Blocked by 'src_ip: block' rule"},
	[XFW_DROP_SRC_IP_RATE_LIMITED]		= {"xfw_src_ip_rate_limited",
						   "Blocked by 'src_ip: ratelimit' rule"},
	[XFW_DROP_SRC_IP_DEFAULT_BLOCKED]	= {"xfw_src_ip_default_blocked",
						   "Blocked by 'defaults/src_ip: "
						   "block' rule"},
	[XFW_DROP_SRC_IP_DEFAULT_RATE_LIMITED]	= {"xfw_src_ip_default_rate_limited",
						   "Blocked by 'defaults/src_ip: "
						   "ratelimit' rule"},
	[XFW_DROP_TCP_ANOM_BAD_FLAGS]		= {"xfw_tcp_anom_bad_flags",
						   "Blocked by TCP anomaly: bad flags"},
	[XFW_DROP_TCP_ANOM_SYN_BAD_SEQ]		= {"xfw_tcp_anom_syn_bad_seq",
						   "Blocked by TCP anomaly: SYN bad seq"},
	[XFW_DROP_TCP_ANOM_SYN_NO_OPTIONS]	= {"xfw_tcp_anom_syn_no_options",
						   "Blocked by TCP anomaly: SYN "
						   "without options"},
	[XFW_DROP_TCP_ANOM_SYN_HAS_DATA]	= {"xfw_tcp_anom_syn_has_data",
						   "Blocked by TCP anomaly: SYN "
						   "with payload"},
	[XFW_DROP_TCP_ANOM_ZERO_PORT]		= {"xfw_tcp_anom_zero_port",
						   "Blocked by TCP anomaly: zero"
						   " port"},
	[XFW_DROP_UDP_ANOM_ZERO_PORT]		= {"xfw_udp_anom_zero_port",
						   "Blocked by UDP anomaly: zero"
						   " port"},
	[XFW_DROP_L2_UNKNOWN_INGRESS]		= {"xfw_l2_unknown_ingress",
						   "Blocked on parsing: unknown "
						   "EtherType"},
	[XFW_DROP_ETH_BADHDR_INGRESS]		= {"xfw_eth_badhdr_ingress",
						   "Blocked on parsing: bad "
						   "ethernet header"},
	[XFW_DROP_IP4_BADHDR_INGRESS]		= {"xfw_ip4_badhdr_ingress",
						   "Blocked on parsing: IPv4 bad"
						   " header"},
	[XFW_DROP_IP4_FRAGMENTED_INGRESS]	= {"xfw_ip4_fragmented_ingress",
						   "Blocked on parsing: IPv4 "
						   "fragmented packet"},
	[XFW_DROP_IP6_BADHDR_INGRESS]		= {"xfw_ip6_badhdr_ingress",
						   "Blocked on parsing: IPv6 bad"
						   " header"},
	[XFW_DROP_IP6_FRAGMENTED_INGRESS]	= {"xfw_ip6_fragmented_ingress",
						   "Blocked on parsing: IPv6 "
						   "fragmented packet"},
	[XFW_DROP_TCP_BADHDR_INGRESS]		= {"xfw_tcp_badhdr_ingress",
						   "Blocked on parsing: TCP bad "
						   "header"},
	[XFW_DROP_UDP_BADHDR_INGRESS]		= {"xfw_udp_badhdr_ingress",
						   "Blocked on parsing: UDP bad "
						   "header"},
	[XFW_DROP_ICMP_BADHDR_INGRESS]		= {"xfw_icmp_badhdr_ingress",
						   "Blocked on parsing: ICMP bad"
						   " header"},
	[XFW_DROP_L4_UNSUPPORTED_INGRESS]	= {"xfw_l4_unsupported_ingress",
						   "Blocked on parsing: unsupported"
						   " IP proto"},
	[XFW_DROP_TCP_AUTH_FAILED]		= {"xfw_tcp_auth_failed",
						   "Blocked by 'tcp_auth_filter': "
						   "unknown connection"},
	[XFW_DROP_TCP_AUTH_TIMEOUT]		= {"xfw_tcp_auth_timeout",
						   "Blocked by 'tcp_auth_filter': "
						   "outdated connection"},
	[XFW_DROP_SYNCOOKIE_FAILED]		= {"xfw_syncookie_failed",
						   "Blocked by 'tcp_syncookies' "
						   "rule: invalid syncookie"},
	[XFW_DROP_SYN_BLOCKED]			= {"xfw_syn_blocked",
						   "Blocked by 'tcp_syn_drop' "
						   "rule: SYN tuple is blocked"},
	[XFW_DROP_DNS_BADHDR_INGRESS]		= {"xfw_dns_badhdr_ingress",
						   "Blocked on parsing: DNS bad "
						   "header"},
	[XFW_DROP_DNS_QRY_RCODE_NOT_OK]		= {"xfw_dns_qry_rcode_not_ok",
						   "Blocked by DNS anomaly: "
						   "RCODE is not OK in query packet"},
	[XFW_DROP_DNS_BAD_QUESTION]		= {"xfw_dns_bad_question",
						   "Blocked on parsing: "
						   "bad question in DNS packet"},
	[XFW_DROP_DNS_MULTIPLE_QUESTIONS]	= {"xfw_dns_multiple_questions",
						   "Blocked by DNS anomaly: "
						   "More than 1 question in DNS packet "
						   "(query or response)"},
	[XFW_DROP_DNS_ANS_OR_AUTHS_IN_QUERY]	= {"xfw_dns_ans_or_auth_in_query",
						   "Blocked by DNS anomaly: "
						   "Answers or Authority sections "
						   "in DNS query"},
	[XFW_DROP_DNS_IXFR_ANOMALY]		= {"xfw_dns_ixfr_anomaly",
						   "Blocked by DNS anomaly: "
						   "Authority in DNS query"},
	[XFW_DROP_DNS_QRY_BAD_ARCOUNT]		= {"xfw_dns_qry_bad_arcount",
						   "Blocked by DNS anomaly: "
						   "More than 2 additional sections "
						   "in DNS query"},
	[XFW_DROP_DNS_NOT_ASKED_RESPONSE]	= {"xfw_dns_not_asked_response",
						   "Blocked by DNS anomaly: "
						   "Incoming response without "
						   "outcoming query before"},
	[XFW_DROP_DNS_LARGE_RESPONSE]		= {"xfw_dns_large_response",
						   "Blocked by DNS anomaly: "
						   "DNS UDP response packet size "
						   "is too large"},
	[XFW_DROP_DNS_RESP_ANS_OVERLIMIT]	= {"xfw_dns_resp_ans_overlimit",
						   "Blocked by DNS anomaly: "
						   "DNS response contains "
						   "too many answers"},
	[XFW_DROP_DNS_BAD_RR]			= {"xfw_dns_bad_dns_rr",
						   "Blocked on parsing: DNS bad "
						   "resource record"},
	[XFW_DROP_DNS_ANSWER_ANOMALY]		= {"xfw_dns_answer_anomaly",
						   "Blocked by DNS anomaly: "
						   "DNS answer has "
						   "anomaly ttl"}
};
XFW_STAT_ARRAY_ASSERT(xfw_drop_stats, XFW_DROP_STAT_MAX);

#if defined(__clang__)
#pragma clang diagnostic pop
#endif
