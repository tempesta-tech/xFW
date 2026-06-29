/**
 *	Tempesta xFW eBPF maps manager interfaces
 *
 * SPDX-FileCopyrightText: © 2026 Tempesta Technologies, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#pragma once
#include <sys/mman.h>

#include <utility>
#include <deque>
#include <vector>

#include "../../lib/bpf/array_map.hh"
#include "../../lib/bpf/array_mmaped_map.hh"
#include "../../lib/bpf/shadow_hash_map.hh"
#include "../../lib/bpf/map.hh"
#include "../../lib/bpf/per_cpu_counter.hh"

#include "../../xfw/bpf_uapi_action_rules.h"
#include "../../xfw/bpf_uapi_config.h"
#include "../../xfw/bpf_uapi_proto_keys.h"
#include "../../xfw/map_names.h"

#include "configuration.hh"
#include "index_pool.hh"
#include "map_key_hash.hh"
#include "stats.hh"

/*
 * Central manager for BPF-based filtering subsystem.
 *
 * Owns and manages all BPF maps used by filters (src/icmp/dst/intranet,
 * rate limiting, statistics, and configuration).
 *
 * The class acts as the single integration point between userspace logic
 * and the BPF program. All interaction with the kernel happens exclusively
 * through BPF maps.
 *
 * The system uses a shadow-map switching strategy for critical filters
 * (e.g. src/icmp/dst). Updates are performed on a secondary map while
 * the active one remains in use. After validation, maps are swapped
 * atomically in the kernel.
 *
 * This design guarantees:
 *	- lock-free reads in BPF program
 *	- consistent view during updates
 *	- ability to roll back incomplete updates
 */
class BpfMapsManager
{
public:
	BpfMapsManager();
	BpfMapsManager(const BpfMapsManager &) = delete;
	BpfMapsManager(BpfMapsManager &&) = delete;
	
public:
	/*
	 * Update ip-proto/dns/evaluation-mode/syncookie filtering rules.
	 * Existing rules are fully replaced in bpf program.
	 */
	void
	set_simple_rules(const XfwConfig &config);

	/*
	 * Update src filtering rules.
	 * Existing rules are fully replaced in bpf program. The operation
	 * involve shadow-map switching to ensure consistent updates without
	 * affecting the currently active filter state.
	 */
	void
	set_src_rules(const XfwConfig::NetIps &rules,
		      const XfwConfig::Defaults& defaults);

	/*
	 * Update icmp filtering rules.
	 * Existing rules are fully replaced in bpf program. The operation
	 * involve shadow-map switching to ensure consistent updates without
	 * affecting the currently active filter state.
	 */
	void
	set_icmp_rules(const XfwConfig::IcmpRules &rules,
		       const XfwConfig::Defaults& defaults);

	/*
	 * Update dst filtering rules.
	 * Existing rules are fully replaced in bpf program. The operation
	 * involve shadow-map switching to ensure consistent updates without
	 * affecting the currently active filter state.
	 */
	void
	set_dst_rules(const XfwConfig::NetIps &rules,
		      const XfwConfig::Defaults& defaults);

	/*
	 * Update protected net filtering rules.
	 * Existing rules are fully replaced in bpf program. The operation
	 * involve shadow-map switching to ensure consistent updates without
	 * affecting the currently active filter state.
	 */
	void set_prot_net_settings(const XfwConfig::NetIps &rules);

	/*
	 * Update named rate limit configuration.
	 *
	 * Named rate limits are updated in place when possible. Previously used
	 * entries may be marked as inactive, but their reuse is deferred until
	 * the entire configuration update succeeds.
	 *
	 * This is required because other parts of the configuration updated in
	 * the same operation may still reference existing named rate limits.
	 * Allowing early reuse would break consistency between rule sets and
	 * rate limit state.
	 */
	void set_ratelimits(const XfwConfig::Ratelimits &ratelimits);

	/* Update TCP flag (SYN or RST) filtering rules. */
	void
	set_tcp_flag_rule(const std::optional<XfwConfig::TcpFlagFilter> &new_filter,
			  XfwFlagsFilter flag);

	/* Update TCP anomaly filtering rules. */
	void set_tcp_anomaly_rule(const XfwConfig::TcpAnomalyFilter &new_filter);

public:
	void turn_filtration_on();
	
private:
	struct SrcRules
	{
		using Ipv4ShadowMap = BpfShadowHashMap<XfwIpv4LpmKey, XfwSrcRule, XfwIpv4LpmKeyHash>;
		using Ipv6ShadowMap = BpfShadowHashMap<XfwIpv6LpmKey, XfwSrcRule, XfwIpv6LpmKeyHash>;
		using PortShadowMap = BpfShadowHashMap<XfwPort, XfwSrcRule>;

		Ipv4ShadowMap v4_udp, v4_tcp;
		Ipv6ShadowMap v6_udp, v6_tcp;
		PortShadowMap port_udp, port_tcp;
	};

	struct ProtectedNetRules
	{
		using Ipv4ShadowMap = BpfShadowHashMap<XfwIpv4LpmKey, int, XfwIpv4LpmKeyHash>;
		using Ipv6ShadowMap = BpfShadowHashMap<XfwIpv6LpmKey, int, XfwIpv6LpmKeyHash>;

		Ipv4ShadowMap v4;
		Ipv6ShadowMap v6;
	};

	using IcmpRules = BpfShadowHashMap<XfwIcmpKey, XfwActionRule, XfwIcmpKeyHash>;
	using DstRules = BpfShadowHashMap<XfwDstKey, XfwActionRule, XfwDstKeyHash>;

private:
	XfwFilterCfg get_config();

	/*
	 * Apply part of configuration to the BPF program and finalize update step.
	 *
	 * This is the final stage of every set_* operation, but it does not
	 * necessarily update the entire configuration. Only the parts affected
	 * by the current operation are applied.
	 *
	 * Until this function is called, no changes are visible in the BPF datapath.
	 *
	 * If shadow-map rules are involved (e.g. dst/icmp filters), this step performs
	 * an atomic switch of the corresponding active maps in the kernel. After the
	 * swap, the datapath starts using the newly activated rule set.
	 *
	 * Rate limit buckets are committed only if they were involved in the current
	 * subsystem update; unrelated buckets remain unchanged.
	 */
	void
	upload_config_changes(XfwFilterCfg &cfg, std::optional<std::reference_wrapper<IndexPoolTransaction>> tx);
	static constexpr auto no_ratelimit_buckets = std::nullopt;

	static const uint8_t
	get_maps_by_index(uint8_t map_idx)
	{
		switch (map_idx) {
		case MAP_PRIMARY_IDX:	return 0;
		case MAP_SECONDARY_IDX:	return 1;
		}
		throw std::runtime_error("Unexpected map index from bpf-core");
	}

	/*
	 * Return the active icmp ruleset.
	 *
	 * The returned reference is tied to the active configuration state and
	 * must not be modified. Updates must be performed through the configuration
	 * update pipeline only.
	 */
	const IcmpRules &get_active_icmp_rules(const XfwFilterCfg &cfg)
	{
		const auto active_map_idx = get_maps_by_index(cfg.amap_icmp);
		return icmp_rules_[active_map_idx];
	}

	/*
	 * Return the active dst ruleset.
	 *
	 * The returned reference is tied to the active configuration state and
	 * must not be modified. Updates must be performed through the configuration
	 * update pipeline only.
	 */
	const DstRules &get_active_dst_rules(const XfwFilterCfg &cfg)
	{
		const auto active_map_idx = get_maps_by_index(cfg.amap_dst);
		return dst_rules_[active_map_idx];
	}

	XfwPerCpuStats get_global_stats() { return global_stats_.load_global_stats(); }

private:
	void
	apply_defaults(const XfwConfig::Defaults &defaults,
		       std::span<const DefaultIndex> indices,
		       uint8_t default_action, std::span<XfwActionRule> to,
		       IndexPoolTransaction &tx);

private:
	using RLimitsMap = BpfMmapedArrayMap<XfwRLimitLeakyBckt,
						XFW_MAX_RATE_LIMITER_BUCKETS>;

	/*
	* Reset callback invoked when a previously used index is ready to be reused.
	*
	* BPF maps are zero-initialized, not logically reset, so stale runtime
	* state from previous usage may remain valid. This includes:
	*	- stale nrefill_jiff values
	*	- partially valid rate limit state
	*
	* The callback is responsible for explicitly clearing all such state
	* before the bucket is reassigned.
	*/
	static void
	reset_rlimit_bucket(
		RLimitsMap& map, IndexPool::Index bucket_idx) noexcept
	{
		(*map)[bucket_idx].reset();
	}

private:
	using FilterCfgMap = BpfSingleElementMap<XfwFilterCfg>;

	/*
	 * Kernel tick frequency (CONFIG_HZ).
	 * We use jiffies as the primary time unit for per-packet processing
	 * intervals because they align with the kernel's native 
	 * scheduling/timekeeping granularity.
	 * 
	 * Compared to nanosecond-based timestamps (e.g. ktime_get_ns()), jiffies:
	 * - avoid expensive high-resolution clock reads in the fast path
	 * - reduce arithmetic cost in per-packet hot code
	 * - provide sufficient resolution for coarse-grained rate limiting and timeouts
	 * 
	 * This constant is used to convert higher-level time units (seconds) into jiffies:
	 * 	jiffies = seconds * hz_
	 * 
	 * The goal is performance in the dataplane: minimizing per-packet overhead
	 * while staying consistent with kernel timing semantics.
	 */
	const uint64_t	hz_;

	FilterCfgMap	cfg_map_{MAP_CFG_STR};
	BpfStats	global_stats_;

	SrcRules	src_rules_[2]= {
		{ SrcRules::Ipv4ShadowMap(MAP_SRC_4_UDP_STR(MAP_PRIMARY_IDX)),
		  SrcRules::Ipv4ShadowMap(MAP_SRC_4_TCP_STR(MAP_PRIMARY_IDX)),
		  SrcRules::Ipv6ShadowMap(MAP_SRC_6_UDP_STR(MAP_PRIMARY_IDX)),
		  SrcRules::Ipv6ShadowMap(MAP_SRC_6_TCP_STR(MAP_PRIMARY_IDX)),
		  SrcRules::PortShadowMap(MAP_SRC_P_UDP_STR(MAP_PRIMARY_IDX)),
		  SrcRules::PortShadowMap(MAP_SRC_P_TCP_STR(MAP_PRIMARY_IDX)) },
		{ SrcRules::Ipv4ShadowMap(MAP_SRC_4_UDP_STR(MAP_SECONDARY_IDX)),
		  SrcRules::Ipv4ShadowMap(MAP_SRC_4_TCP_STR(MAP_SECONDARY_IDX)),
		  SrcRules::Ipv6ShadowMap(MAP_SRC_6_UDP_STR(MAP_SECONDARY_IDX)),
		  SrcRules::Ipv6ShadowMap(MAP_SRC_6_TCP_STR(MAP_SECONDARY_IDX)),
		  SrcRules::PortShadowMap(MAP_SRC_P_UDP_STR(MAP_SECONDARY_IDX)),
		  SrcRules::PortShadowMap(MAP_SRC_P_TCP_STR(MAP_SECONDARY_IDX)) }
	};

	IcmpRules	icmp_rules_[2] = {
		IcmpRules(MAP_ICMP_STR(MAP_PRIMARY_IDX)),
		IcmpRules(MAP_ICMP_STR(MAP_SECONDARY_IDX))
	};
	DstRules	dst_rules_[2] = {
		DstRules(MAP_DST_STR(MAP_PRIMARY_IDX)),
		DstRules(MAP_DST_STR(MAP_SECONDARY_IDX))
	};
	ProtectedNetRules	prot_net_rules_[2] = {
		{ ProtectedNetRules::Ipv4ShadowMap(MAP_NET_IP4_STR(MAP_PRIMARY_IDX)),
		  ProtectedNetRules::Ipv6ShadowMap(MAP_NET_IP6_STR(MAP_PRIMARY_IDX)) },
		{ ProtectedNetRules::Ipv4ShadowMap(MAP_NET_IP4_STR(MAP_SECONDARY_IDX)),
		  ProtectedNetRules::Ipv6ShadowMap(MAP_NET_IP6_STR(MAP_SECONDARY_IDX)) }
	};

	/*
	* Rate limiting infrastructure use two cooperating components:
	*   - RLimitsMap: bpf storage for per-bucket rate limit state;
	*   - IndexPool: index allocator for reusable rate limit buckets.
	*
	* Both components are designed to be used together. The index pool does not
	* own data; it only manages reusable indices into the BPF map.
	*
	* IMPORTANT:
	* The index pool is used in shadow-map update mode (dst-filter / icmp-filter),
	* where updates are staged and then committed atomically to the kernel.
	* This allows safe rollback of all allocated indices if the commit fails,
	* avoiding leaks and inconsistent state between maps and userspace.
	*/
	RLimitsMap	rlimits_map_{ MAP_RATELIMIT_STR };
	IndexPool	ratelimit_index_pool_{
		RLimitsMap::Size,
		[this](IndexPool::Index idx){
			reset_rlimit_bucket(rlimits_map_, idx);
		}
	};
};
