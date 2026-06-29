/**
 *	Tempesta xFW limiting constants
 *
 * These limits highly impact the system performance and behavior under DDoS.
 *
 * SPDX-FileCopyrightText: © 2026 Tempesta Technologies, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#pragma once

#define XFW_MAX_PORTS				65535
#define XFW_MAX_SRC_IP_RULES			3000000
#define XFW_MAX_SRC_RATE_LIMITER_BUCKETS	1000000 /* LRU */
#define XFW_MAX_DNS_QRS_TRACKER_BUCKETS		1000000 /* LRU */
/* ICMP types amount is x2 for IPv4 and IPv6. */
#define XFW_MAX_ICMP_RULES			(255 * 2)
#define XFW_MAX_DST_RULES			2000
#define XFW_MAX_NAMED_RATELIMITS		255
#define XFW_MAX_TCP_FLAG_RULES			2
#define XFW_MAX_DEFAULT_RULES			14

/*
 * x2 for IPv4 and IPv6 maps separately.
 *
 * TODO: 1M for concurrent TCP connections is probably too small.
 * Also theck the limits above.
 */
#define XFW_MAX_PROTECTED_NET_RULES		50
#define XFW_MAX_CONCURRENT_TCP_CONNECTIONS	1000000

#define XFW_MAX_RATE_LIMITER_BUCKETS		(XFW_MAX_ICMP_RULES * 2 \
						 + XFW_MAX_DST_RULES * 2 \
						 + XFW_MAX_TCP_FLAG_RULES * 2 \
						 + XFW_MAX_DEFAULT_RULES * 2)
