/*
 *	Tempesta Bpf drop/pass all statistic.
 *
 * SPDX-FileCopyrightText: © 2026 Tempesta Technologies, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#pragma once

#include "statistics_types.h"

enum XfwStatistic {
	XFW_METADATA_CREATION_FAILED,
	XFW_ICMP_BLOCKED,
	XFW_SYN_RATE_LIMITED,
	XFW_RST_RATE_LIMITED,
	XFW_ICMP_RATE_LIMITED,
	XFW_ICMP_DEFAULT_BLOCKED,
	XFW_ICMP_DEFAULT_RATE_LIMITED,
	XFW_DST_BLOCKED,
	XFW_DST_RATE_LIMITED,
	XFW_SRC_PORT_ALLOWED,
	XFW_SRC_PORT_BLOCKED,
	XFW_SRC_PORT_RATE_LIMITED,
	XFW_SRC_PORT_DEFAULT_BLOCKED,
	XFW_SRC_PORT_DEFAULT_RATE_LIMITED,
	XFW_SRC_IP_ALLOWED,
	XFW_SRC_IP_BLOCKED,
	XFW_SRC_IP_RATE_LIMITED,
	XFW_SRC_IP_DEFAULT_BLOCKED,
	XFW_SRC_IP_DEFAULT_RATE_LIMITED,
	XFW_TCP_ANOM_BAD_FLAGS,
	XFW_TCP_ANOM_SYN_BAD_SEQ,
	XFW_TCP_ANOM_SYN_NO_OPTIONS,
	XFW_TCP_ANOM_SYN_HAS_DATA,
	XFW_TCP_ANOM_ZERO_PORT,
	XFW_UDP_ANOM_ZERO_PORT,
	XFW_L2_UNKNOWN_INGRESS,
	XFW_ETH_BADHDR_INGRESS,
	XFW_IP4_BADHDR_INGRESS,
	XFW_IP4_FRAGMENTED_INGRESS,
	XFW_IP6_BADHDR_INGRESS,
	XFW_IP6_FRAGMENTED_INGRESS,
	XFW_TCP_BADHDR_INGRESS,
	XFW_UDP_BADHDR_INGRESS,
	XFW_ICMP_BADHDR_INGRESS,
	XFW_ARP_INGRESS,
	XFW_L4_UNSUPPORTED_INGRESS,
	XFW_TCP_AUTH_FAILED,
	XFW_TCP_AUTH_TIMEOUT,
	XFW_SYNCOOKIE_FAILED,
	XFW_SYNCOOKIE_GENERATED,
	XFW_PRELOAD_INGRESS,
	XFW_L2_UNKNOWN_EGRESS,
	XFW_ETH_BADHDR_EGRESS,
	XFW_L4_UNSUPPORTED_EGRESS,
	XFW_IP4_BADHDR_EGRESS,
	XFW_IP6_BADHDR_EGRESS,
	XFW_TCP_BADHDR_EGRESS,
	XFW_UDP_BADHDR_EGRESS,
	XFW_PRELOAD_EGRESS,
	XFW_DNS_BADHDR_INGRESS,
	XFW_DNS_QRY_RCODE_NOT_OK,
	XFW_DNS_BAD_QUESTION,
	XFW_DNS_MULTIPLE_QUESTIONS,
	XFW_DNS_ANS_OR_AUTHS_IN_QUERY,
	XFW_DNS_IXFR_ANOMALY,
	XFW_DNS_QRY_BAD_ARCOUNT,
	XFW_DNS_NOT_ASKED_RESPONSE,
	XFW_DNS_LARGE_RESPONSE,
	XFW_DNS_RESP_ANS_OVERLIMIT,
	XFW_DNS_BAD_RR,
	XFW_DNS_ANSWER_ANOMALY,
	XFW_GRE_INGRESS,

	XFW_DECISION_STAT_MAX
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
static const struct XfwStatInfo xfw_decision_stat[] = {
	[XFW_METADATA_CREATION_FAILED]		= {"xfw_metadata_creation_failed",
						   "Internal error: metadata creation failed"},
	[XFW_ICMP_BLOCKED]			= {"xfw_icmp_blocked",
						   "Blocked by 'icmp: block' rule"},
	[XFW_SYN_RATE_LIMITED]			= {"xfw_syn_rate_limited",
						   "Blocked by 'tcp_flags syn: "
						   "ratelimit' rule"},
	[XFW_RST_RATE_LIMITED]			= {"xfw_rst_rate_limited",
						   "Blocked by 'tcp_flags rst: "
						   "ratelimit' rule"},
	[XFW_ICMP_RATE_LIMITED]			= {"xfw_icmp_rate_limited",
						   "Blocked by 'icmp: ratelimit' rule"},
	[XFW_ICMP_DEFAULT_BLOCKED]		= {"xfw_icmp_default_blocked",
						   "Blocked by 'defaults/icmp: "
						   "block' rule"},
	[XFW_ICMP_DEFAULT_RATE_LIMITED]		= {"xfw_icmp_default_rate_limited",
						   "Blocked by 'defaults/icmp: "
						   "ratelimit' rule"},
	[XFW_DST_BLOCKED]			= {"xfw_dst_blocked",
						   "Blocked by 'dst: block' rule"},
	[XFW_DST_RATE_LIMITED]			= {"xfw_dst_rate_limited",
						   "Blocked by 'dst: ratelimit' rule"},
	[XFW_SRC_PORT_ALLOWED]			= {"xfw_src_port_allowed",
						   "Whitelisted by 'src_port: allow' rule"},
	[XFW_SRC_PORT_BLOCKED]			= {"xfw_src_port_blocked",
						   "Blocked by 'src_port: block' rule"},
	[XFW_SRC_PORT_RATE_LIMITED]		= {"xfw_src_port_rate_limited",
						   "Blocked by 'src_port: ratelimit' rule"},
	[XFW_SRC_PORT_DEFAULT_BLOCKED]		= {"xfw_src_port_default_blocked",
						   "Blocked by 'defaults/src_port: "
						   "block' rule"},
	[XFW_SRC_PORT_DEFAULT_RATE_LIMITED]	= {"xfw_src_port_default_rate_limited",
						   "Blocked by 'defaults/src_port: "
						   "ratelimit' rule"},
	[XFW_SRC_IP_ALLOWED]			= {"xfw_src_ip_allowed",
						   "Whitelisted by 'src_ip: allow' rule"},
	[XFW_SRC_IP_BLOCKED]			= {"xfw_src_ip_blocked",
						   "Blocked by 'src_ip: block' rule"},
	[XFW_SRC_IP_RATE_LIMITED]		= {"xfw_src_ip_rate_limited",
						   "Blocked by 'src_ip: ratelimit' rule"},
	[XFW_SRC_IP_DEFAULT_BLOCKED]		= {"xfw_src_ip_default_blocked",
						   "Blocked by 'defaults/src_ip: "
						   "block' rule"},
	[XFW_SRC_IP_DEFAULT_RATE_LIMITED]	= {"xfw_src_ip_default_rate_limited",
						   "Blocked by 'defaults/src_ip: "
						   "ratelimit' rule"},
	[XFW_TCP_ANOM_BAD_FLAGS]		= {"xfw_tcp_anom_bad_flags",
						   "Blocked by TCP anomaly: bad flags"},
	[XFW_TCP_ANOM_SYN_BAD_SEQ]		= {"xfw_tcp_anom_syn_bad_seq",
						   "Blocked by TCP anomaly: SYN bad seq"},
	[XFW_TCP_ANOM_SYN_NO_OPTIONS]		= {"xfw_tcp_anom_syn_no_options",
						   "Blocked by TCP anomaly: SYN "
						   "without options"},
	[XFW_TCP_ANOM_SYN_HAS_DATA]		= {"xfw_tcp_anom_syn_has_data",
						   "Blocked by TCP anomaly: SYN "
						   "with payload"},
	[XFW_TCP_ANOM_ZERO_PORT]		= {"xfw_tcp_anom_zero_port",
						   "Blocked by TCP anomaly: zero"
						   " port"},
	[XFW_UDP_ANOM_ZERO_PORT]		= {"xfw_udp_anom_zero_port",
						   "Blocked by UDP anomaly: zero"
						   " port"},
	[XFW_L2_UNKNOWN_INGRESS]		= {"xfw_l2_unknown_ingress",
						   "Blocked on parsing: unknown "
						   "EtherType"},
	[XFW_ETH_BADHDR_INGRESS]		= {"xfw_eth_badhdr_ingress",
						   "Blocked on parsing: bad "
						   "ethernet header"},
	[XFW_IP4_BADHDR_INGRESS]		= {"xfw_ip4_badhdr_ingress",
						   "Blocked on parsing: IPv4 bad"
						   " header"},
	[XFW_IP4_FRAGMENTED_INGRESS]		= {"xfw_ip4_fragmented_ingress",
						   "Blocked on parsing: IPv4 "
						   "fragmented packet"},
	[XFW_IP6_BADHDR_INGRESS]		= {"xfw_ip6_badhdr_ingress",
						   "Blocked on parsing: IPv6 bad"
						   " header"},
	[XFW_IP6_FRAGMENTED_INGRESS]		= {"xfw_ip6_fragmented_ingress",
						   "Blocked on parsing: IPv6 "
						   "fragmented packet"},
	[XFW_TCP_BADHDR_INGRESS]		= {"xfw_tcp_badhdr_ingress",
						   "Blocked on parsing: TCP bad "
						   "header"},
	[XFW_UDP_BADHDR_INGRESS]		= {"xfw_udp_badhdr_ingress",
						   "Blocked on parsing: UDP bad "
						   "header"},
	[XFW_ICMP_BADHDR_INGRESS]		= {"xfw_icmp_badhdr_ingress",
						   "Blocked on parsing: ICMP bad"
						   " header"},
	[XFW_ARP_INGRESS]			= { "xfw_arp_ingress",
						    "Allowed on parsing: ARP packet"},
	[XFW_L4_UNSUPPORTED_INGRESS]		= {"xfw_l4_unsupported_ingress",
						   "Blocked on parsing: unsupported"
						   " IP proto"},
	[XFW_TCP_AUTH_FAILED]			= {"xfw_tcp_auth_failed",
						   "Blocked by 'tcp_auth_filter': "
						   "unknown connection"},
	[XFW_TCP_AUTH_TIMEOUT]			= {"xfw_tcp_auth_timeout",
						   "Blocked by 'tcp_auth_filter': "
						   "outdated connection"},
	[XFW_SYNCOOKIE_FAILED]			= {"xfw_syncookie_failed",
						   "Blocked by 'tcp_syncookies' "
						   "rule: invalid syncookie"},
	[XFW_SYNCOOKIE_GENERATED]		= {"xfw_syncookie_generated",
						   "Transmit packet back to "
						   "client with syncookie"},
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
	[XFW_PRELOAD_EGRESS]			= {"xfw_preload_egress",
						   "Allowed: xFW rules are not loaded"},
	[XFW_DNS_BADHDR_INGRESS]		= {"xfw_dns_badhdr_ingress",
						   "Blocked on parsing: DNS bad "
						   "header"},
	[XFW_DNS_QRY_RCODE_NOT_OK]		= {"xfw_dns_qry_rcode_not_ok",
						   "Blocked by DNS anomaly: "
						   "RCODE is not OK in query packet"},
	[XFW_DNS_BAD_QUESTION]			= {"xfw_dns_bad_question",
						   "Blocked on parsing: "
						   "bad question in DNS packet"},
	[XFW_DNS_MULTIPLE_QUESTIONS]		= {"xfw_dns_multiple_questions",
						   "Blocked by DNS anomaly: "
						   "More than 1 question in DNS packet "
						   "(query or response)"},
	[XFW_DNS_ANS_OR_AUTHS_IN_QUERY]		= {"xfw_dns_ans_or_auth_in_query",
						   "Blocked by DNS anomaly: "
						   "Answers or Authority sections "
						   "in DNS query"},
	[XFW_DNS_IXFR_ANOMALY]			= {"xfw_dns_ixfr_anomaly",
						   "Blocked by DNS anomaly: "
						   "Authority in DNS query"},
	[XFW_DNS_QRY_BAD_ARCOUNT]		= {"xfw_dns_qry_bad_arcount",
						   "Blocked by DNS anomaly: "
						   "More than 2 additional sections "
						   "in DNS query"},
	[XFW_DNS_NOT_ASKED_RESPONSE]		= {"xfw_dns_not_asked_response",
						   "Blocked by DNS anomaly: "
						   "Incoming response without "
						   "outcoming query before"},
	[XFW_DNS_LARGE_RESPONSE]		= {"xfw_dns_large_response",
						   "Blocked by DNS anomaly: "
						   "DNS UDP response packet size "
						   "is too large"},
	[XFW_DNS_RESP_ANS_OVERLIMIT]		= {"xfw_dns_resp_ans_overlimit",
						   "Blocked by DNS anomaly: "
						   "DNS response contains "
						   "too many answers"},
	[XFW_DNS_BAD_RR]			= {"xfw_dns_bad_dns_rr",
						   "Blocked on parsing: DNS bad "
						   "resource record"},
	[XFW_DNS_ANSWER_ANOMALY]		= {"xfw_dns_answer_anomaly",
						   "Blocked by DNS anomaly: "
						   "DNS answer has "
						   "anomaly ttl"},
	[XFW_GRE_INGRESS]			= { "xfw_gre_ingress",
						    "Allowed on parsing: GRE packet"},
};

#if defined(__TARGET_ARCH_BPF__) || defined(__BPF__)
STATIC_ASSERT(
	sizeof(xfw_decision_stat) / sizeof(struct XfwStatInfo) == XFW_DECISION_STAT_MAX,
	"You forgot description for stat");
#endif

#if defined(__clang__)
#pragma clang diagnostic pop
#endif
