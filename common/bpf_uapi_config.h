/**
 *	Tempesta xFW configuration structures
 *
 * See the rules for shared struct declarations in bpf_uapi.h.
 *
 * SPDX-FileCopyrightText: © 2026 Tempesta Technologies, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#pragma once

#include "default_index.h"
#include "supported_protocols.h"
#include "tcp_control_bits.h"

#include "bpf_bitset.h"
#include "bpf_uapi_action_rules.h"

#include "limits.h"

DECLARE_BITSET64(XfwTcpControlBitset, XFW_BIT_CONTROL_MAX);

typedef struct XfwRulesCfgTcpAnomaly {
	bool			enabled;
	bool			syn_without_opt_enabled;
	bool			syn_with_payload_enabled;
	bool			syn_seqno_enabled;
	__be32			syn_seqno_value;
	XfwTcpControlBitset	bad_flags;
} XfwRulesCfgTcpAnomaly;

typedef struct XfwEvaluationMode {
	bool			enabled;
} XfwEvaluationMode;

typedef struct XfwRulesCfgTcpAuth {
	bool			enabled;
} XfwRulesCfgTcpAuth;

typedef struct XfwRulesCfgDns {
	bool			enabled;
} XfwRulesCfgDns;

enum XfwFlagsFilter : uint8_t {
	XFW_FLAGS_FILTER_SYN,
	XFW_FLAGS_FILTER_RST,
	XFW_FLAGS_FILTER_MAX
};

typedef struct XfwRulesCfgSyncookie {
	uint64_t		passive_timer_jiff; /* In jiffies */
	uint64_t		flood_timer_jiff; /* In jiffies */
	bool			enabled;
} XfwRulesCfgSyncookie;

DECLARE_BITSET64(XfwSupportedProtocolsBitset, XFW_SUPPORTED_PROTOCOL_MAX);

typedef struct XfwRulesCfgIpProto {
	XfwSupportedProtocolsBitset	protocols;
} XfwRulesCfgIpProto;

typedef struct XfwRulesCfg {
	XfwEvaluationMode	evaluation_mode;
	XfwRulesCfgIpProto	ip_proto;
	XfwRulesCfgSyncookie	syncookie;
	XfwRulesCfgTcpAnomaly	tcp_anomaly;
	XfwRulesCfgTcpAuth	tcp_auth;
	XfwRulesCfgDns		dns;
	XfwActionRule		tcp_flags[XFW_FLAGS_FILTER_MAX];
	XfwActionRule		defaults[XFW_DEFAULT_MAX];
} __attribute__((aligned(8))) XfwRulesCfg;

typedef struct XfwPacketRate {
	uint64_t	packets;
	uint64_t	bytes;

#ifdef __cplusplus
	XfwPacketRate() noexcept
		/*
		 * TODO #488: we have to use UINT64_MAX here, but can't due to
		 * xfw_is_within_rlimit implementation. Maybe will be fixed
		 * with #87.
		 */
		: packets(INT64_MAX)
		, bytes(INT64_MAX)
	{}
#endif
} XfwPacketRate;

/**
 * The main configuration handler.
 *
 * @amap_*	- active map id, MAP_PRIMARY_IDX or MAP_SECONDARY_IDX
 * @named_rates	- named rate limits configuration
 */
typedef struct XfwFilterCfg {
	XfwRulesCfg		rules;
	bool			rules_active;

	uint8_t			amap_src;
	uint8_t			amap_icmp;
	uint8_t			amap_dst;
	uint8_t			amap_prot_net;

	XfwPacketRate		named_rates[XFW_MAX_NAMED_RATELIMITS];
} XfwFilterCfg;
