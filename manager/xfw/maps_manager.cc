/**
 *	Tempesta xFW eBPF maps manager
 *
 * SPDX-FileCopyrightText: © 2026 Tempesta Technologies, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include <chrono>
#include <fstream>
#include <sys/utsname.h>

#include "../../lib/log.hh"
#include "../../lib/error.hh"
#include "../../xfw/ip_helpers.h"

#include "../ip_formatter.hh"
#include "../xfw_update_error.hh"
#include "maps_manager.hh"
#include "xfw.hh"

/* Default IP protocol filter.
 * Represents the baseline allowed protocol set used when no ip_proto is
 * provided in configuration. GRE (47) is intentionally excluded by default.
 */
static auto
make_default_ip_proto()
{
	BitSet<XfwSupportedProtocols, XFW_SUPPORTED_PROTOCOL_MAX> bs;
	bs.set(XfwSupportedProtocols::TCP);
	bs.set(XfwSupportedProtocols::UDP);
	bs.set(XfwSupportedProtocols::ICMP);
	bs.set(XfwSupportedProtocols::ICMPV6);
	return bs;
}

/*
 * Get kernel release string via uname()
 */
static std::string
get_kernel_release()
{
	struct utsname u;
	if (uname(&u) != 0)
		throw Except("uname() failed");

	return std::string(u.release);
}

/*
 * Try to extract CONFIG_HZ from a config file.
 * Returns true if successful.
 */
static bool
parse_config_hz_file(const std::string &path, unsigned long &hz)
{
	std::ifstream f(path);
	if (!f.is_open())
		return false;

	std::string line;
	while (std::getline(f, line)) {
		if (line.rfind("CONFIG_HZ=", 0) == 0) {
			hz = std::stoul(line.substr(10));
			return true;
		}
	}

	TE_WRN("CONFIG_HZ is unavailable in file {}", path);
	return false;
}

/*
 * Fallback chain:
 * 1. /boot/config-$(uname -r)
 * 2. /lib/modules/$(uname -r)/build/.config
 * 3. throw exception (hard failure)
 */
unsigned long get_config_hz()
{
	unsigned long hz = 0;
	const std::string rel = get_kernel_release();

	// 1. Boot config (best userspace-available source)
	if (parse_config_hz_file("/boot/config-" + rel, hz))
		return hz;

	// 2. Kernel build config fallback
	if (parse_config_hz_file("/lib/modules/" + rel + "/build/.config", hz))
		return hz;

	// 3. Hard failure
	throw Except("Failed to determine CONFIG_HZ (no fallback available)");
}

/*
 * Reconcile rate limit bucket ownership between previous configuration state
 * and a new rule being constructed.
 *
 * This function operates on a pair of optional states:
 *   - cfg_rule: previously applied rule (may be absent)
 *   - new_rule: target rule being constructed (may be absent)
 *
 * The goal is not to perform a full state transition, but to ensure correct
 * ownership of rate limit buckets when rules are added, removed, or modified.
 *
 * Rate limit buckets are treated as external resources managed by a transaction
 * (IndexPoolTransaction). Depending on the transition, a bucket may be:
 *   - allocated for a newly introduced rate limit rule
 *   - released when a rule stops using rate limiting
 *   - reused when the named rate limit identity remains unchanged
 *   - replaced when the rule switches to a different named rate limit
 *
 * This function does NOT mutate cfg_rule and only updates new_rule when it
 * exists. All resource side effects are tracked via the transaction object.
 */
void
reconcile_ratelimit_bucket(XfwActionRule *new_rule,
			   const XfwActionRule *cfg_rule,
			   IndexPoolTransaction &tx)
{
	const bool new_rl = new_rule && new_rule->action == XFW_ACTION_RATE_LIMIT;
	const bool old_rl = cfg_rule && cfg_rule->action == XFW_ACTION_RATE_LIMIT;

	/* No rate limiting in either old or new state → nothing to reconcile. */
	if (!new_rl && !old_rl)
		return;

	/* Transition: no rate limit → rate limit.
	 * A fresh bucket must be allocated for the new rule.
	 */
	if (new_rl && !old_rl) {
		new_rule->rlimit.bucket_idx = tx.allocate();
		return;
	}

	/* Transition: rate limit → no rate limit.
	 * The previously allocated bucket is released back to the pool.
	 */
	if (!new_rl && old_rl) {
		tx.release(cfg_rule->rlimit.bucket_idx);
		return;
	}

	/* Transition: rate limit → rate limit with identical named index.
	 * The existing bucket can be safely reused without reallocation.
	 */
	if (new_rule->rlimit.named_idx == cfg_rule->rlimit.named_idx) {
		new_rule->rlimit.bucket_idx = cfg_rule->rlimit.bucket_idx;
		return;
	}
	
	/* Transition: rate limit → rate limit with different named index.
	 * Old bucket is no longer valid and must be replaced.
	 */
	new_rule->rlimit.bucket_idx = tx.allocate();
	tx.release(cfg_rule->rlimit.bucket_idx);
}

template<class Map, class Key>
const typename Map::mapped_type *
find_ptr(const Map &map, const Key &key)
{
	if (auto it = map.find(key); it != map.end())
		return std::addressof(it->second);

	return nullptr;
}

BpfMapsManager::BpfMapsManager(): hz_(get_config_hz())
{
	TE_DBG("Bpf maps are ready to use.");
}

void
BpfMapsManager::set_tcp_flag_rule(const std::optional<XfwConfig::TcpFlagFilter> &new_filter,
				  XfwFlagsFilter flag)
{
	auto cfg = get_config();
	static_assert(XFW_MAX_TCP_FLAG_RULES == XFW_FLAGS_FILTER_MAX,
		"If you added new TCP flag filter, "
		"please carefully update XFW_MAX_TCP_FLAG_RULES");
	XfwActionRule new_rule;
	if (new_filter.has_value()) {
		new_rule.action = XFW_ACTION_RATE_LIMIT;
		new_rule.rlimit.named_idx = new_filter.value().ratelimit_index_;
	}
	else
		new_rule.action = XFW_ACTION_ALLOW;

	IndexPoolTransaction tx{ ratelimit_index_pool_ };
	reconcile_ratelimit_bucket(&new_rule, &cfg.rules.tcp_flags[flag], tx);
	cfg.rules.tcp_flags[flag] = std::move(new_rule);

	upload_config_changes(cfg, tx);
}

void
BpfMapsManager::set_tcp_anomaly_rule(const XfwConfig::TcpAnomalyFilter &filter)
{
	auto cfg = get_config();

	cfg.rules.tcp_anomaly.enabled = filter.enabled_;
	cfg.rules.tcp_anomaly.syn_with_payload_enabled =
		filter.syn_with_payload_enabled_;
	cfg.rules.tcp_anomaly.syn_without_opt_enabled =
		filter.syn_without_opt_enabled_;
	cfg.rules.tcp_anomaly.syn_seqno_enabled =
		filter.syn_with_seqno_.has_value();
	cfg.rules.tcp_anomaly.syn_seqno_value =
		filter.syn_with_seqno_.value_or(0);

	using BitsetT = std::decay_t<decltype(filter.bad_flags_)>;
	static_assert(BitsetT::byte_size() == sizeof(cfg.rules.tcp_anomaly.bad_flags.data),
		      "Bitset size mismatch");
	std::memcpy(cfg.rules.tcp_anomaly.bad_flags.data,
		    filter.bad_flags_.raw().data(),
		    filter.bad_flags_.byte_size());

	upload_config_changes(cfg, no_ratelimit_buckets);

}

void
BpfMapsManager::apply_defaults(const XfwConfig::Defaults &defaults,
			       std::span<const DefaultIndex> indices,
			       uint8_t default_action,
			       std::span<XfwActionRule> to,
			       IndexPoolTransaction &tx)
{
	static_assert(XFW_MAX_DEFAULT_RULES == DefaultIndex::XFW_DEFAULT_MAX,
		"If you added new default rule, "
		"please carefully update XFW_MAX_DEFAULT_RULES");
	for (auto idx : indices) {
		auto &src = defaults[idx];
		XfwActionRule new_rule;
		if (src.has_value())
			new_rule = XfwActionRule{src->allow_, src->ratelimit_index_};
		else
			new_rule = XfwActionRule{default_action};

		reconcile_ratelimit_bucket(&new_rule, &to[idx], tx);
		to[idx] = std::move(new_rule);
	}
}

void
BpfMapsManager::set_simple_rules(const XfwConfig &config)
{
	auto cfg = get_config();

	using BitsetT = std::decay_t<decltype(config.ip_proto_filter_->protocols_)>;
	static_assert(
		BitsetT::byte_size() == sizeof(cfg.rules.ip_proto.protocols.data),
		"IpProto Bitset size mismatch"
	);

	static const BitsetT default_protocols = make_default_ip_proto();
	const BitsetT &s = config.ip_proto_filter_.has_value()
		? config.ip_proto_filter_->protocols_
		: default_protocols;

	std::memcpy(cfg.rules.ip_proto.protocols.data, s.raw().data(), s.byte_size());

	cfg.rules.evaluation_mode.enabled = config.evaluation_mode_.enabled_;
	cfg.rules.tcp_auth.enabled = config.auth_filter_.enabled_;
	cfg.rules.dns.enabled = config.dns_filter_.enabled_;

	cfg.rules.syncookie.enabled = config.syncookie_filter_.has_value();
	if (cfg.rules.syncookie.enabled) {
		const auto &data = config.syncookie_filter_.value();
		cfg.rules.syncookie.flood_timer_jiff = data.flood_timer_ * hz_;
		cfg.rules.syncookie.passive_timer_jiff = data.passive_timer_ * hz_;
	}

	upload_config_changes(cfg, no_ratelimit_buckets);
}

void
BpfMapsManager::set_src_rules(const XfwConfig::NetIps &rules,
	const XfwConfig::Defaults& defaults)
{
	SrcRules::Ipv4ShadowMap::Snapshot rules4_udp, rules4_tcp;
	SrcRules::Ipv6ShadowMap::Snapshot rules6_udp, rules6_tcp;
	SrcRules::PortShadowMap::Snapshot port_rules_udp, port_rules_tcp;

	// If an IP appears more than once in the user-defined collection,
	// it's a configuration error — duplicates in user rules are not allowed.
	//
	// However, if an IP from the geo-based rules also exists in the user-defined
	// rules, the user rule should override the geo rule.
	//
	// That's why we process user-defined IP rules first — geo rules are less
	// important and can be ignored if a conflict occurs.
	for (auto& it: rules) {
		XfwSrcRule r(it.second.flags_.isAllowed_, it.second.ratelimit_index_);
		for (auto &rule: it.second.net4s_) {
			XfwIpv4LpmKey key = {rule.prefixlen_, rule.addr_};
			SrcRules::Ipv4ShadowMap::Snapshot &map = it.second.flags_.isTcp_ ? rules4_tcp : rules4_udp;
			auto [ign, inserted] = map.try_emplace(key, r);
			if (!inserted)
				throw Except("Ip address {} already exist. ",
					     "Check the configuration.",
					     ipv4_to_string(key.addr));
		}
		for (auto &rule: it.second.net6s_) {
			XfwIpv6LpmKey key = {rule.prefixlen_, { rule.addr_[0],
				rule.addr_[1], rule.addr_[2], rule.addr_[3] }};
			SrcRules::Ipv6ShadowMap::Snapshot &map = it.second.flags_.isTcp_ ? rules6_tcp : rules6_udp;
			auto [ign, inserted] = map.try_emplace(key, r);
			if (!inserted)
				throw Except("Ip address {} already exist. ",
					     "Check the configuration.",
					     ipv6_to_string(key.addr));
		}
		for (auto &port: it.second.ports_) {
			SrcRules::PortShadowMap::Snapshot &map = it.second.flags_.isTcp_ ? port_rules_tcp : port_rules_udp;
			auto [ign, inserted] = map.try_emplace(port, r);
			if (!inserted)
				throw Except("Rule for port {} already exist. ",
					      "Check the configuration. ", port);
		}
	}

	for (auto& it: rules) {
		XfwSrcRule r(it.second.flags_.isAllowed_, it.second.ratelimit_index_);
		for (auto &net: it.second.nets_) {
			for (auto &rule: net.net4s_) {
				XfwIpv4LpmKey key = {rule.prefixlen_, rule.addr_};
				SrcRules::Ipv4ShadowMap::Snapshot &map = it.second.flags_.isTcp_ ? rules4_tcp : rules4_udp;
				auto [ign, inserted] = map.try_emplace(key, r);
				if (!inserted)
					TE_INF("Ip address {} already exist, skip"
					       " the one from the geo-database.",
					       ipv4_to_string(key.addr));
			}
			for (auto &rule: net.net6s_) {
				XfwIpv6LpmKey key = {rule.prefixlen_, { rule.addr_[0],
					rule.addr_[1], rule.addr_[2], rule.addr_[3] }};
				SrcRules::Ipv6ShadowMap::Snapshot &map
					= it.second.flags_.isTcp_
					  ? rules6_tcp
					  : rules6_udp;
				auto [ign, inserted] = map.try_emplace(key, r);
				if (!inserted)
					TE_INF("Ip address {} already exist, skip"
					       " the one from the geo-database.",
					       ipv6_to_string(key.addr));
			}
		}
	}

	if (rules4_udp.size() > XFW_MAX_SRC_IP_RULES)
		throw std::runtime_error("src-filter ip4.udp rule limit exceeded");

	if (rules4_tcp.size() > XFW_MAX_SRC_IP_RULES)
		throw std::runtime_error("src-filter ip4.tcp rule limit exceeded");

	if (rules6_udp.size() > XFW_MAX_SRC_IP_RULES)
		throw std::runtime_error("src-filter ip6.udp rule limit exceeded");

	if (rules6_tcp.size() > XFW_MAX_SRC_IP_RULES)
		throw std::runtime_error("src-filter ip6.tcp rule limit exceeded");

	if (port_rules_udp.size() > XFW_MAX_PORTS)
		throw std::runtime_error("src-filter udp-port rule limit exceeded");
	if (port_rules_tcp.size() > XFW_MAX_PORTS)
		throw std::runtime_error("src-filter tcp-port rule limit exceeded");

	auto cfg = get_config();
	const uint8_t inactive_map_idx = next_map_idx(cfg.amap_src);

	auto &inactive_src_maps = src_rules_[get_maps_by_index(inactive_map_idx)];

	verify(inactive_src_maps.v4_udp.replace(std::move(rules4_udp)), "Unable to "
		"update src-ip4-udp rules in the BPF core");
	verify(inactive_src_maps.v4_tcp.replace(std::move(rules4_tcp)), "Unable to "
		"update src-ip4-tcp rules in the BPF core");
	verify(inactive_src_maps.v6_udp.replace(std::move(rules6_udp)), "Unable to "
		"update src-ip6-udp rules in the BPF core");
	verify(inactive_src_maps.v6_tcp.replace(std::move(rules6_tcp)), "Unable to "
		"update src-ip6-tcp rules in the BPF core");
	verify(inactive_src_maps.port_udp.replace(std::move(port_rules_udp)),
		"Unable to update port-udp rules in the BPF core");
	verify(inactive_src_maps.port_tcp.replace(std::move(port_rules_tcp)),
		"Unable to to update port-tcp rules in the BPF core");

	cfg.amap_src = inactive_map_idx;

	IndexPoolTransaction tx{ ratelimit_index_pool_ };
	// Array of indices we want to initialize in default array
	constexpr DefaultIndex src_indices[] = {
		DefaultIndex::XFW_DEFAULT_SRC_IP_TCP_IP4,
		DefaultIndex::XFW_DEFAULT_SRC_IP_UDP_IP4,
		DefaultIndex::XFW_DEFAULT_SRC_IP_TCP_IP6,
		DefaultIndex::XFW_DEFAULT_SRC_IP_UDP_IP6,

		DefaultIndex::XFW_DEFAULT_SRC_PORT_TCP_IP4,
		DefaultIndex::XFW_DEFAULT_SRC_PORT_UDP_IP4,
		DefaultIndex::XFW_DEFAULT_SRC_PORT_TCP_IP6,
		DefaultIndex::XFW_DEFAULT_SRC_PORT_UDP_IP6
	};
	apply_defaults(
		defaults, src_indices, XFW_ACTION_ALLOW, cfg.rules.defaults, tx);

	upload_config_changes(cfg, tx);
}

void
BpfMapsManager::set_icmp_rules(const XfwConfig::IcmpRules &rules,
	const XfwConfig::Defaults& defaults)
{
	auto cfg = get_config();
	auto &active_map = get_active_icmp_rules(cfg).snapshot();

	IndexPoolTransaction tx{ ratelimit_index_pool_ };
	IcmpRules::Snapshot new_rules;
	for (auto& it: rules) {
		const auto &rule = it.second;
		XfwActionRule r(rule.isAllowed_, rule.ratelimit_index_);
		XfwIcmpKey key;
		key.proto = rule.isIpv6_ ? XFW_L4_PROTO_ICMPV6
					 : XFW_L4_PROTO_ICMP;
		for (auto type: rule.types_) {
			key.type = type;
			reconcile_ratelimit_bucket(&r, find_ptr(active_map, key), tx);
			auto [ign, inserted] = new_rules.try_emplace(key, r);
			if (!inserted) {
				throw Except("Icmp-rule with type {} already exist."
					     " Check the configuration. ", type);
			}
		}
	}

	if (new_rules.size() > XFW_MAX_ICMP_RULES)
		throw std::runtime_error("icmp-filter rule limit exceeded");
	
	// Return buckets from removed rules to the pool.
	for (const auto &[key, rule] : active_map) {
		if (new_rules.find(key) == new_rules.end())
			reconcile_ratelimit_bucket(nullptr, &rule, tx);
	}

	const uint8_t inactive_map_idx = next_map_idx(cfg.amap_icmp);
	auto &inactive_map = icmp_rules_[get_maps_by_index(inactive_map_idx)];
	verify(inactive_map.replace(std::move(new_rules)),
	       "Unable to update icmp rules in the BPF core");

	cfg.amap_icmp = inactive_map_idx;

	// Array of indices we want to initialize in default array
	constexpr DefaultIndex icmp_indices[] = {
		DefaultIndex::XFW_DEFAULT_ICMP_IP4,
		DefaultIndex::XFW_DEFAULT_ICMP_IP6
	};
	apply_defaults(
		defaults, icmp_indices, XFW_ACTION_ALLOW, cfg.rules.defaults, tx);

	upload_config_changes(cfg, tx);
}

void
BpfMapsManager::set_dst_rules(const XfwConfig::NetIps &rules,
	const XfwConfig::Defaults& defaults)
{
	auto cfg = get_config();
	auto &active_map = get_active_dst_rules(cfg).snapshot();

	//Build new snapshot
	IndexPoolTransaction tx{ ratelimit_index_pool_ };
	DstRules::Snapshot new_rules;
	for (auto& it: rules) {
		XfwDstKey key;
		key.ipver = it.second.flags_.isIpv6_
			       ? static_cast<unsigned int>(XFW_IP_VER_6)
			       : static_cast<unsigned int>(XFW_IP_VER_4);
		key.proto = it.second.flags_.isTcp_
			    ? static_cast<unsigned char>(XFW_L4_PROTO_TCP)
			    : static_cast<unsigned char>(XFW_L4_PROTO_UDP);

		XfwActionRule r(it.second.flags_.isAllowed_,
				it.second.ratelimit_index_);
		assert(it.second.nets_.empty());
		for (auto &rule: it.second.net4s_) {
			xfw_ipv4_to_ipv6_mapped(rule.addr_, key.addr.addr32);
			key.port = rule.port_;
			reconcile_ratelimit_bucket(&r, find_ptr(active_map, key), tx);
			auto [ign, inserted] = new_rules.try_emplace(key, r);
			if (!inserted)
				throw Except("Ip address {} already exist."
					     " Check the aconfiguration.",
					     ipv4_to_string(rule.addr_));
		}
		for (auto &rule: it.second.net6s_) {
			std::memcpy(key.addr.addr32, rule.addr_, sizeof(key.addr.addr32));
			key.port = rule.port_;
			reconcile_ratelimit_bucket(&r, find_ptr(active_map, key), tx);
			auto [ign, inserted] = new_rules.try_emplace(key, r);
			if (!inserted)
				throw Except("Ip address {} already exist."
					     " Check the configuration. ",
					     ipv6_to_string(rule.addr_));
		}
	}

	if (new_rules.size() > XFW_MAX_DST_RULES)
		throw std::runtime_error("dst-filter rule limit exceeded");

	// Return buckets from removed rules to the pool.
	for (const auto &[key, rule] : active_map) {
		if (new_rules.find(key) == new_rules.end())
			reconcile_ratelimit_bucket(nullptr, &rule, tx);
	}

	const uint8_t inactive_map_idx = next_map_idx(cfg.amap_dst);
	auto &inactive_map = dst_rules_[get_maps_by_index(inactive_map_idx)];
	verify(inactive_map.replace(std::move(new_rules)),
	       "Unable to update dst rules in the BPF core");

	cfg.amap_dst = inactive_map_idx;

	// Array of indices we want to initialize in default array
	constexpr DefaultIndex dst_indices[] = {
		DefaultIndex::XFW_DEFAULT_DST_TCP_IP4,
		DefaultIndex::XFW_DEFAULT_DST_TCP_IP6,
		DefaultIndex::XFW_DEFAULT_DST_UDP_IP4,
		DefaultIndex::XFW_DEFAULT_DST_UDP_IP6
	};
	auto default_rule = rules.empty() ? XFW_ACTION_ALLOW : XFW_ACTION_BLOCK;
	apply_defaults(
		defaults, dst_indices, default_rule, cfg.rules.defaults, tx);

	upload_config_changes(cfg, tx);
}

void
BpfMapsManager::set_prot_net_settings(const XfwConfig::NetIps &rules)
{
	ProtectedNetRules::Ipv4ShadowMap::Snapshot	prot_net4;
	ProtectedNetRules::Ipv6ShadowMap::Snapshot	prot_net6;

	const int xfw_dummy_value = 1;
	for (auto& it: rules) {
		for (auto &rule: it.second.net4s_) {
			XfwIpv4LpmKey key = {rule.prefixlen_, rule.addr_};
			auto [ign, inserted] = prot_net4.try_emplace(key, xfw_dummy_value);
			if (!inserted)
				throw Except("Protected net ip address {} already exist. ",
					     "Check the configuration.",
					     ipv4_to_string(key.addr));
		}
		for (auto &rule: it.second.net6s_) {
			XfwIpv6LpmKey key = {rule.prefixlen_, { rule.addr_[0],
				rule.addr_[1], rule.addr_[2], rule.addr_[3] }};
			auto [ign, inserted] = prot_net6.try_emplace(key, xfw_dummy_value);
			if (!inserted)
				throw Except("Protected net ip address {} already exist. ",
					     "Check the configuration.",
					     ipv6_to_string(key.addr));
		}
	}

	if (prot_net4.size() > XFW_MAX_PROTECTED_NET_RULES)
		throw std::runtime_error("Too many 'protected net' 'ip4' rules");

	if (prot_net6.size() > XFW_MAX_PROTECTED_NET_RULES)
		throw std::runtime_error("Too many 'protected net' 'ip6' rules");

	auto cfg = get_config();
	const uint8_t inactive_map_idx = next_map_idx(cfg.amap_prot_net);
	auto &inactive_prot_net_map = prot_net_rules_[get_maps_by_index(inactive_map_idx)];

	verify(inactive_prot_net_map.v4.replace(std::move(prot_net4)), "Unable to "
		"update lan-ip4 rules in the BPF core");
	verify(inactive_prot_net_map.v6.replace(std::move(prot_net6)), "Unable to "
		"update lan-ip6 rules in the BPF core");

	cfg.amap_prot_net = inactive_map_idx;
	upload_config_changes(cfg, no_ratelimit_buckets);
}

void
BpfMapsManager::turn_filtration_on()
{
	auto cfg = get_config();
	cfg.rules_active = true;
	upload_config_changes(cfg, no_ratelimit_buckets);
}

XfwFilterCfg
BpfMapsManager::get_config()
{
	XfwFilterCfg cfg;
	if (cfg_map_.get(cfg) == 0) [[likely]]
		return cfg;
		
	throw Except("XfwFilterCfg load failed, map fd: {}", MAP_CFG_STR);
}

void
BpfMapsManager::upload_config_changes(
	XfwFilterCfg &cfg,
	std::optional<std::reference_wrapper<IndexPoolTransaction>> tx
)
{
	verify(cfg_map_.set(cfg) == 0, "Unable to update configuration "
	       "in the BPF core");

	if (tx)
		tx->get().commit();
}

void
BpfMapsManager::set_ratelimits(const XfwConfig::Ratelimits &ratelimits)
{
	auto cfg = get_config();
	const auto& src = ratelimits.get_all();
	for (size_t i = 0; i < src.size(); ++i) {
		if (src[i].state_ == XfwConfig::Ratelimit::State::Active) {
			cfg.named_rates[i].packets = src[i].pps_;
			cfg.named_rates[i].bytes = src[i].bps_;
		}
	}
	upload_config_changes(cfg, no_ratelimit_buckets);
}
