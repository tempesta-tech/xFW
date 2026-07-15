/**
 *	Tempesta Xfw configuration updater
 *
 * SPDX-FileCopyrightText: © 2026 Tempesta Technologies, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <numeric>

#include "../bpf_uapi/tcp_anomaly_features.h"
#include "../lib/proto/bitset_helper.hh"
#include "../lib/bitset.hh"

#include "xfw/tcp_anomaly_flags.hh"

#include "proto_wrappers.hh"
#include "xfw_config_updater.hh"
#include "ip_formatter.hh"
#include "xfw_update_error.hh"

template <typename Map>
typename Map::mapped_type&
get_rule(Map &map, std::string_view alias)
{
	auto it = map.find(alias);
	if (it != map.end())
		return it->second;

	throw UpdateError("Can't perform operation for rule '{}': not found.",
			  alias);
}

template <typename Map>
void
delete_rule(std::string_view alias, Map &from)
{
	auto it = from.find(alias);
	if (it != from.end()) {
		from.erase(it);
		return;
	}

	throw UpdateError("Can't delete rule '{}': not found.", alias);
}

template <typename Map>
typename Map::mapped_type&
upsert_rule(std::string_view key, Map &map)
{
	using KeyType = typename Map::key_type;
	using MappedType = typename Map::mapped_type;

	auto [it, inserted] = map.insert_or_assign(KeyType(key), MappedType{});
   	return it->second;
}

/**
 * Class which incapsulated the work with protobuf messages with a type
 * TempestaRPC::ReqRecType_RRT_XFW_CFG.
 */
class XfwConfigUpdater
{
public:
	friend void
	update_xfw_config(const TempestaRPC::XFWCfg &cfg, Xfw &xfw);

private:
	XfwConfigUpdater(const Xfw &xfw, const TempestaRPC::XFWCfg &msg):
		xfw_(xfw), msg_(msg)
	{
		verify(msg.flags(), "Null 'XFWCfg::flags' field is not"
			" allowed in proto data.");
		verify(bitset_deserialize(*msg.flags(), msg_flags_),
		       "Unexpected bytes count at XFWCfg::flags");

		const auto &config = xfw.get_config();
		if (!config.has_value())
			return;

		if (msg_flags_.test(TempestaRPC::XFWOpt_XFW_CONFIG_PATCH)) {
			// We are going to patch the old config if possible.
			// So let's copy the old one to apply the diff.
			config_ = config.value();
		}
		else {
			// We don't need the old config anymore, except ratelimits data.
			// We can't remove rate limits immediately because updates
			// in bpf-core are not instantaneous. In case of
			// a bpf error, we will still need the old ratelimits available.
			// So let's mark all active rate limits as inactive.
			// We will be able to remove unused ones if the configuration
			// update succeeds (see XfwConfigUpdater::commit_update).
			config_.ratelimits_ = config.value().ratelimits_;
			config_.ratelimits_.inactivate_all();
		}
	}

	/**
	 * Get information from proto TempestaRPC::XFWCfg to create updated XfwConfig.
	 */
	void prepare_update();

	/**
	 * Update xfw config with the prepared information.
	 */
	void commit_update(Xfw &xfw);

protected:
	void prepare_protocols();
	void prepare_defaults();

	void prepare_evaluation_mode();
	void prepare_tcp_anomaly_filter();
	void prepare_dns_filter();
	void prepare_icmp_rules();

	void prepare_net_rules();
	void prepare_ratelimits();

	void prepare_tcp_auth_filter();
	void prepare_syncookie_filter();

	void prepare_tcp_flags_filter();

private:
	/**
	 * Populate the target rule with attributes from the protocol.
	 */
	template<typename ProtoType, typename TargetType>
	void
	set_attributes_to(const ProtoType &proto, TargetType &rule);

	/**
	 * Populate the target rule with matchers from the protocol.
	 */
	template<typename ProtoType, typename TargetType>
	void
	add_matchers_to(const ProtoType &proto, TargetType &rule);

	/**
	 * Remove matchers from the target rule based on the protocol.
	 */
	template<typename ProtoType, typename TargetType>
	static void
	delete_matchers_from(const ProtoType &proto, TargetType &rule);

	/**
	 * Apply protocol-defined differences to the provided map/set.
	 */
	template<typename ProtoType, typename MapType>
	void
	apply_edit_action(const ProtoWrapper<ProtoType> &proto, MapType &set);

private:
	/**
	 * Returns the index of a rate limit by name, or std::nullopt if the
	 * pointer is null. Throw if the string is empty.
	 */
	std::optional<XfwConfig::RatelimitIndex>
	get_ratelimit_idx(const flatbuffers::String *name);

private:
	const Xfw						&xfw_;
	const TempestaRPC::XFWCfg				&msg_;
	BitSet<TempestaRPC::XFWOpt, TempestaRPC::XFWOpt_MAX>	msg_flags_;

private:
	XfwConfig						config_;
};

void
update_xfw_config(const TempestaRPC::XFWCfg &cfg, Xfw &xfw)
{
	XfwConfigUpdater r(xfw, cfg);
	r.prepare_update();
	r.commit_update(xfw);
}

/*
 * ------------------------------------------------------------------------
 *	XfwConfigUpdater
 * ------------------------------------------------------------------------
 */
void
XfwConfigUpdater::prepare_update()
{
	using namespace TempestaRPC;

	prepare_protocols();
	prepare_ratelimits();
	prepare_defaults();
	prepare_net_rules();
	prepare_tcp_anomaly_filter();
	prepare_tcp_auth_filter();
	prepare_dns_filter();

	prepare_evaluation_mode();
	prepare_syncookie_filter();

	// Syncookies modify the workflow by creating a cookie in response and
	// sending data back to the user (see syn_filter).
	// Therefore, this filter cannot be used in evaluation mode.
	verify(!config_.evaluation_mode_.enabled_ ||
	       !config_.syncookie_filter_.has_value(), "Syncookies are not allowed"
	       " in evaluation mode");

	prepare_tcp_flags_filter();
	prepare_icmp_rules();

	return;
}

void
XfwConfigUpdater::commit_update(Xfw &xfw)
{
	xfw.set_config(std::move(config_));
}

void
XfwConfigUpdater::prepare_defaults()
{
	using namespace TempestaRPC;

	if (!msg_.defaults())
		return;

	//Section has only replace semantic for now. So cleanup all
	for (auto &rule : config_.defaults_)
		rule.reset();

	for (std::size_t i = 0; i < msg_.defaults()->size(); ++i) {
		auto* rule = msg_.defaults()->Get(i);
		verify(!!rule, "Null 'DefaultAction' is not allowed");
		verify(rule->flags(), "Null 'DefaultAction::flags' field is not"
			" allowed in proto data.");

		auto ratelimit_idx = get_ratelimit_idx(rule->ratelimit());
		
		BitSet<DefaultIndex, XFW_DEFAULT_MAX> flags;
		verify(bitset_deserialize(*rule->flags(), flags),
		       "Unexpected bytes count at DefaultAction::flags");

		for (size_t i = 0; i < static_cast<size_t>(DefaultIndex::XFW_DEFAULT_MAX); ++i) {
			DefaultIndex idx = static_cast<DefaultIndex>(i);
			if (!flags.test(idx))
				continue;
			if (config_.defaults_[idx].has_value())
				throw UpdateError("Two identical default "
						  "rule are not allowed");
			config_.defaults_[idx].emplace(rule->allow(), ratelimit_idx);
		}
	}
}

void
XfwConfigUpdater::prepare_evaluation_mode()
{
	using namespace TempestaRPC;

	if (msg_flags_.test(XFWOpt::XFWOpt_EVALUATION_MODE_OFF))
		config_.evaluation_mode_.enabled_ = false;
	else if (msg_flags_.test(XFWOpt::XFWOpt_EVALUATION_MODE_ON))
		config_.evaluation_mode_.enabled_ = true;

	// Otherwise there is no information about this in config.
}

void
XfwConfigUpdater::prepare_protocols()
{
	using namespace TempestaRPC;
	
	if (msg_flags_.test(XFWOpt::XFWOpt_IP_PROTO_FILTER_OFF)) {
		config_.ip_proto_filter_.reset();
		return;
	}

	// There is no information about this filter in config.
	if (!msg_.ip_proto())
		return;
	
	verify(!!msg_.ip_proto()->protocols(), "Null 'Protocols' field is not allowed");

	XfwConfig::IpProtoFilter filter;
	verify(bitset_deserialize(*msg_.ip_proto()->protocols(), filter.protocols_),
	       "Unexpected bytes count at IpProto::Protocols");

	config_.ip_proto_filter_ = std::move(filter);
}

void
XfwConfigUpdater::prepare_tcp_anomaly_filter()
{
	using namespace TempestaRPC;

	if (msg_flags_.test(XFWOpt::XFWOpt_TCP_ANOMALY_FILTER_OFF)) {
		config_.anomaly_filter_.enabled_= false;
		return;
	}
	
	// There is no information about this filter in config.
	if (!msg_.tcp_anomaly())
		return;
	
	verify(!!msg_.tcp_anomaly()->features(), "Null 'Features' field is not allowed");
	BitSet<TcpAnomalyFeature, XFW_TCP_ANOMALY_FEATURE_MAX> features;
	verify(bitset_deserialize(*msg_.tcp_anomaly()->features(), features),
	       "Unexpected bytes count at TcpAnomaly::Features");

	if (features.test(TcpAnomalyFeature::XFW_SYN_WIHOUT_OPTIONS))
		config_.anomaly_filter_.syn_without_opt_enabled_ = true;
	
	if (features.test(TcpAnomalyFeature::XFW_SYN_WITH_PAYLOAD))
		config_.anomaly_filter_.syn_with_payload_enabled_ = true;

	if (features.test(TcpAnomalyFeature::XFW_SYN_WITH_SEQ_NO))
		config_.anomaly_filter_.syn_with_seqno_ =
			htonl(msg_.tcp_anomaly()->seqno_value());

	config_.anomaly_filter_.bad_flags_ = xfw_prohibited_rules;
	if (features.test(TcpAnomalyFeature::XFW_BAD_FLAGS)) {
		if (!msg_.tcp_anomaly()->bad_tcp_flags()) {
			//user hasn't specified flags: bad_flags();
			config_.anomaly_filter_.bad_flags_ |= xfw_suspicious_rules;
		}
		else {
			BitSet<TcpControlBits, XFW_BIT_CONTROL_MAX> user_defined_rules;
			verify(bitset_deserialize(*msg_.tcp_anomaly()->bad_tcp_flags(),
						  user_defined_rules),
			       "Unexpected bytes count at TcpAnomaly::bad_flags");

			config_.anomaly_filter_.bad_flags_ |= user_defined_rules;
		}
	}

	config_.anomaly_filter_.enabled_ = true;
}

void
XfwConfigUpdater::prepare_dns_filter()
{
	using namespace TempestaRPC;

	if (msg_flags_.test(XFWOpt::XFWOpt_DNS_FILTER_OFF))
		config_.dns_filter_.enabled_= false;
	else if (msg_flags_.test(XFWOpt::XFWOpt_DNS_FILTER_ON))
		config_.dns_filter_.enabled_ = true;

	// Otherwise there is no information about this filter in config.
}

void
XfwConfigUpdater::prepare_icmp_rules()
{
	using namespace TempestaRPC;

	if (!msg_.icmp_rules())
		return;

	for (size_t i = 0; i < msg_.icmp_rules()->size(); ++i) {
		ProtoIcmpRule rule(msg_.icmp_rules()->Get(i));
		apply_edit_action(rule, config_.icmp_rules_);
	}
}

/**
 * We received some commands that need to be applied to the existing config.
 * This function adds, deletes, or replaces existing rules with new ones.
 */
void
XfwConfigUpdater::prepare_net_rules()
{
	using namespace TempestaRPC;

	if (!msg_.net_rules())
		return;

	for (size_t i = 0; i < msg_.net_rules()->size(); ++i) {
		ProtoNetRule rule(msg_.net_rules()->Get(i));
		const auto &flags = rule.flags();
		if (flags.test(NetRuleOpt::NetRuleOpt_SRC))
			apply_edit_action(rule, config_.src_rules_);
		else if (flags.test(NetRuleOpt::NetRuleOpt_PROTECTED_NET))
			apply_edit_action(rule, config_.prot_net_);
		else
			apply_edit_action(rule, config_.dst_rules_);
	}
}

template<typename ProtoType, typename MapType>
void
XfwConfigUpdater::apply_edit_action(const ProtoWrapper<ProtoType> &proto, MapType &set)
{
	switch(proto.action()) {
	case EditAction::REPLACE:
		// If there are some IPs to replace – replace the whole rule.
		// Otherwise, update rule's attributes.
		if (proto.has_matchers()) {
			auto &net = upsert_rule(proto.alias(), set);
			set_attributes_to(proto, net);
			add_matchers_to(proto, net);
		}
		else {
			auto &net = get_rule(set, proto.alias());
			set_attributes_to(proto, net);
		}
		break;
	case EditAction::DELETE:
		//If there are some IPs to delete – delete only them.
		// Otherwise, delete everything.
		if (proto.has_matchers()) [[likely]] {
			auto &net = get_rule(set, proto.alias());
			delete_matchers_from(proto, net);
			// There is a possible situation where the IP list
			// becomes empty. But we can't remove the entire
			// rule without an explicit command, because the
			// default behavior can be modified. For example,
			// for 'dst' we have a default rule of 'block' if
			// there is at least one 'dst' section. However,
			// when there are no 'dst' sections, we must allow
			// all traffic.
		}
		else {
			delete_rule(proto.alias(), set);
		}
		break;
	case EditAction::ADD:
		auto &net = get_rule(set, proto.alias());
		add_matchers_to(proto, net);
		break;
	}
}

void
XfwConfigUpdater::prepare_ratelimits()
{
	using namespace TempestaRPC;

	if (!msg_.ratelimits())
		return;

	for (size_t i = 0; i < msg_.ratelimits()->size(); ++i) {
		const auto rule = msg_.ratelimits()->Get(i);
		verify(!!rule, "Null 'Ratelimit' field is not allowed in "
			"proto data.");
		verify(!!rule->alias(), "Null 'Ratelimit::alias' field is "
			"not allowed in proto data.");
		verify(rule->alias()->size(), "Empty 'Ratelimit::alias' field is "
			"not allowed in proto data.");
		verify(!!rule->flags(), "Null 'Ratelimit::flags' field is "
			"not allowed in proto data.");

		BitSet<RatelimitOpt, RatelimitOpt::RatelimitOpt_MAX> flags;
		verify(bitset_deserialize(*rule->flags(), flags),
		       "Unexpected bytes count at RatelimitOpt");

		if (flags.test(RatelimitOpt_DELETE)) {
			config_.ratelimits_.inactivate(rule->alias()->string_view());
		}
		else {
			config_.ratelimits_.upsert(
				rule->alias()->string_view(), rule->pps(), rule->bps());
		}
	}
}

void
XfwConfigUpdater::prepare_tcp_auth_filter()
{
	using namespace TempestaRPC;

	if (msg_flags_.test(XFWOpt::XFWOpt_TCP_AUTH_FILTER_OFF))
		config_.auth_filter_.enabled_= false;
	else if (msg_flags_.test(XFWOpt::XFWOpt_TCP_AUTH_FILTER_ON))
		config_.auth_filter_.enabled_ = true;

	// Otherwise there is no information about this filter in config.
}

void
XfwConfigUpdater::prepare_syncookie_filter()
{
	using namespace TempestaRPC;

	if (!msg_.syncookie())
		return;

	if (msg_flags_.test(XFWOpt::XFWOpt_TCP_SYNCOOKIE_FILTER_OFF)) {
		config_.syncookie_filter_.reset();
		return;
	}

	config_.syncookie_filter_.emplace(msg_.syncookie()->passive_timer(),
		msg_.syncookie()->flood_timer());
}

void
XfwConfigUpdater::prepare_tcp_flags_filter()
{
	using namespace TempestaRPC;

	// Delete what we should be deleted.
	if (msg_flags_.test(XFWOpt::XFWOpt_TCP_SYN_FLAGS_FILTER_OFF))
		config_.tcp_syn_flag_filter_.reset();

	if (msg_flags_.test(XFWOpt::XFWOpt_TCP_RST_FLAGS_FILTER_OFF))
		config_.tcp_rst_flag_filter_.reset();

	if (!msg_.tcp_flags())
		return;

	// Add/replace rules.
	for (size_t i = 0; i < msg_.tcp_flags()->size(); ++i) {
		const auto rule = msg_.tcp_flags()->Get(i);
		verify(!!rule, "Null 'TcpFlagsFilter' field is not allowed in "
			"proto data.");
		verify(!!rule->ratelimit(), "Null 'TcpFlagsFilter::ratelimit' "
			"field is not allowed in proto data.");
		verify(rule->ratelimit()->size(), "Empty 'TcpFlagsFilter::ratelimit' "
			"field is not allowed in proto data.");

		std::string_view name = rule->ratelimit()->string_view();
		XfwConfig::RatelimitIndex ratelimit_idx = 
			config_.ratelimits_.get_active_index(name);

		switch (rule->flag()) {
		case TcpFlagType_ALL:
			config_.tcp_syn_flag_filter_.emplace(ratelimit_idx);
			config_.tcp_rst_flag_filter_.emplace(ratelimit_idx);
			break;
		case TcpFlagType_SYN:
			config_.tcp_syn_flag_filter_.emplace(ratelimit_idx);
			break;
		case TcpFlagType_RST:
			config_.tcp_rst_flag_filter_.emplace(ratelimit_idx);
			break;
		default:
			throw UpdateError("Unknown TcpFlagType {}.",
					  static_cast<uint8_t>(rule->flag()));
		}
	}
}

/**
 * We have to check some restrictions during parsing protected net information from proto.
 */
XfwConfig::Net4Key
get_net4key_prot_net(const TempestaRPC::Net4 *data, const XfwConfig::Flags &flags)
{
	verify(!data->port(), "'port' is prohibited in protected net section");
	return { { data->prefix() },
		*reinterpret_cast<const decltype(XfwConfig::Net4Key::addr_)*>(
			data->addr()->data()) };
}

/**
 * We have to check some restrictions during parsing src information from proto.
 */
XfwConfig::Net4Key
get_net4key_src(const TempestaRPC::Net4 *data, const XfwConfig::Flags &flags)
{
	verify(!flags.isAllowed_ || !data->port(), "'port' is prohibited in "
		"'allow' section");
	verify(bool(data->addr()) != bool(data->port()), "'port' is prohibited "
		"with ip address");
	return { { data->prefix() },
		*reinterpret_cast<const decltype(XfwConfig::Net4Key::addr_)*>(
			data->addr()->data()) };
}

/**
 * We have to check some restrictions during parsing dst information from proto.
 */
XfwConfig::Net4Key
get_net4key_dst(const TempestaRPC::Net4 *data, const XfwConfig::Flags &flags)
{
	verify(data->port(), "'port' must be provided for every 'dst' rule");
	verify(not std::all_of(data->addr()->begin(), data->addr()->end(),
			[](char c) { return c == 0; }),
		"all-zero address is not allowed in 'dst' rule");
	return { { htons(data->port()) },
		*reinterpret_cast<const decltype(XfwConfig::Net4Key::addr_)*>(
			data->addr()->data()) };
}

XfwConfig::Net4Key
get_net4key(const TempestaRPC::Net4 *data, const XfwConfig::Flags &flags)
{
	static const std::size_t Ipv4AddressSize = 4;
	verify(!!data, "Null 'Net4' field is not allowed in proto data.");
	verify(!!data->addr(),
		"Null 'Net4::addr' field is not allowed in proto data.");
	verify(data->addr()->size() == Ipv4AddressSize,
	       "Incorrect size of 'Net4::addr' field.");

	if (flags.isProcNet_)
		return get_net4key_prot_net(data, flags);
	else if (flags.isSrc_)
		return get_net4key_src(data, flags);
	else
		return get_net4key_dst(data, flags);
}

/**
 * We have to check some restrictions during parsing protected net information from proto.
 */
XfwConfig::Net6Key
get_net6key_prot_net(const TempestaRPC::Net6 *data, const XfwConfig::Flags &flags)
{
	verify(!data->port(), "'port' is prohibited in protected net section");
	XfwConfig::Net6Key key;
	key.prefixlen_ = data->prefix();
	std::memcpy(key.addr_, data->addr()->data(), sizeof(key.addr_));
	return key;
}

/**
 * We have to check some restrictions during parsing src information from proto.
 */
XfwConfig::Net6Key
get_net6key_src(const TempestaRPC::Net6 *data, const XfwConfig::Flags &flags)
{
	verify(!flags.isAllowed_ || !data->port(), "'port' is prohibited in "
		"'allow' section");
	verify(bool(data->addr()) != bool(data->port()), "'port' is prohibited "
		"with ip address");

	XfwConfig::Net6Key key;
	key.prefixlen_ = data->prefix();
	std::memcpy(key.addr_, data->addr()->data(), sizeof(key.addr_));
	return key;
}

/**
 * We have to check some restrictions during parsing dst information from proto.
 */
XfwConfig::Net6Key
get_net6key_dst(const TempestaRPC::Net6 *data, const XfwConfig::Flags &flags)
{
	verify(data->port(), "'port' must be provided for every 'dst' rule");
	verify(not std::all_of(data->addr()->begin(), data->addr()->end(),
			[](char c) { return c == 0; }),
		"'addr' = '::' is not allowed in 'dst' rule");
	XfwConfig::Net6Key key;
	key.port_ = htons(data->port());
	std::memcpy(key.addr_, data->addr()->data(), sizeof(key.addr_));
	return key;
}

XfwConfig::Net6Key
get_net6key(const TempestaRPC::Net6 *data, const XfwConfig::Flags &flags)
{
	static const std::size_t Ipv6AddressSize = 16;
	verify(!!data, "Null 'Net6' field is not allowed in proto data.");
	verify(!!data->addr(),
		"Null 'Net6::addr' field is not allowed in proto data.");
	verify(data->addr()->size() == Ipv6AddressSize,
	       "Incorrect size of 'Net6::addr' field.");

	if (flags.isProcNet_)
		return get_net6key_prot_net(data, flags);
	else if (flags.isSrc_)
		return get_net6key_src(data, flags);
	else
		return get_net6key_dst(data, flags);
}

static std::vector<uint16_t>
ports_from_range(uint16_t port, uint16_t port_end)
{
	std::vector<uint16_t> ports;
	if (port_end == 0) {
		ports.push_back(port);
	}
	else {
		if (port >= port_end)
			throw UpdateError("Error on forming range: start {} "
					  "must be < end {}", port, port_end);
		ports.resize(port_end - port + 1);
		std::iota(ports.begin(), ports.end(), port);
	}
	return ports;
}

template<>
void
XfwConfigUpdater::add_matchers_to<ProtoNetRule, XfwConfig::NetIp>(
	const ProtoNetRule &nr_proto, XfwConfig::NetIp &to)
{
	const auto &proto = nr_proto.rule();
	if (proto.net6s()) {
		for (size_t j = 0; j < proto.net6s()->size(); ++j) {
			auto key = get_net6key(proto.net6s()->Get(j), to.flags_);
			if (xfw_is_ipv4_embedded_ipv6(key.addr_))
				throw Except("Unexpected IPv4-compatible prefix "
					     "in IPv6 address");
			auto [it, inserted] = to.net6s_.insert(key);
			if (!inserted) {
				throw UpdateError("Error on add: Net6 "
					"address {}/{} already exist at server's "
					"configuration", ipv6_to_string(key.addr_),
					key.prefixlen_);
			}
		}
	}

	if (proto.net4s()) {
		for (size_t j = 0; j < proto.net4s()->size(); ++j) {
			auto key = get_net4key(proto.net4s()->Get(j), to.flags_);
			auto [it, inserted] = to.net4s_.insert(key);
			if (!inserted) {
				throw UpdateError("Error on add: Net4 "
					"address {}/{} already exist at server's "
					"configuration", ipv4_to_string(key.addr_),
					key.prefixlen_);
			}
		}
	}

	// dst section can't have port-rules for now.
	if (proto.ports()) {
		verify(to.flags_.isSrc_, "A port can be used as an address only"
		       " in the src section.");
		to.ports_.reserve(proto.ports()->size());
		for (size_t j = 0; j < proto.ports()->size(); ++j) {
			const uint16_t port = proto.ports()->Get(j)->port();
			const uint16_t port_end = proto.ports()->Get(j)->port_end();
			const auto &ports = ports_from_range(port, port_end);
			for (const auto &_p: ports) {
				XfwPort p = htons(_p);
				auto it = std::find(to.ports_.begin(), to.ports_.end(), p);
				if (it != to.ports_.end()) {
					throw UpdateError("Error on add: "
						"NetPort {} already exist at "
						"server's configuration", p);
				}
				to.ports_.push_back(p);
			}
		}
	}

	// dst section can't have geo-rules for now.
	if (proto.nets()) {
		verify(to.flags_.isSrc_, "A geo-name can be used as an address"
		       " only in the src section.");
		// Basically, MaxMind has many CIDR blocks for each country.
		// We don't take the US into account here, but this is enough
		// for medium-sized countries like Germany, Japan, etc.
		to.nets_.reserve(10000);
		for (size_t j = 0; j < proto.nets()->size(); ++j) {
			const auto data = proto.nets()->Get(j);
			verify(!!data, "Null 'Nets' field is not allowed in proto data.");
			verify(!data->port(), "'port' is prohibited in 'geo' section");
			XfwConfig::NetGeo geo(data->code());
			xfw_.load_geo_entry(geo, !to.flags_.isIpv6_, to.flags_.isIpv6_);
			to.nets_.push_back(std::move(geo));
		}

	}
}

template<>
void
XfwConfigUpdater::delete_matchers_from<ProtoNetRule, XfwConfig::NetIp>(
	const ProtoNetRule &nr_proto, XfwConfig::NetIp &from)
{
	const auto &proto = nr_proto.rule();
	if (proto.net6s()) {
		for (size_t j = 0; j < proto.net6s()->size(); ++j) {
			auto key = get_net6key(proto.net6s()->Get(j), from.flags_);
			auto it = from.net6s_.find(key);
			if (it == from.net6s_.end()) {
				throw UpdateError("Error on delete: Net6 "
					"address {}/{} wasn't found at server's "
					"configuration", ipv6_to_string(key.addr_),
					key.prefixlen_);
			}
			from.net6s_.erase(it);
		}
	}

	if (proto.net4s()) {
		for (size_t j = 0; j < proto.net4s()->size(); ++j) {
			auto key = get_net4key(proto.net4s()->Get(j), from.flags_);
			auto it = from.net4s_.find(key);
			if (it == from.net4s_.end()) {
				throw UpdateError("Error on delete: Net4 "
					"address {}/{} wasn't found at server's "
					"configuration", ipv4_to_string(key.addr_),
					key.prefixlen_);
			}
			from.net4s_.erase(it);
		}
	}

	if (proto.ports()) {
		verify(from.flags_.isSrc_, "A port can be used as an address only"
			" in the src section.");
		for (size_t j = 0; j < proto.ports()->size(); ++j) {
			const uint16_t port = proto.ports()->Get(j)->port();
			const uint16_t port_end = proto.ports()->Get(j)->port_end();
			const auto &ports = ports_from_range(port, port_end);
			for (const auto &_p: ports) {
				XfwPort p = htons(_p);
				auto it = std::find(from.ports_.begin(), from.ports_.end(), p);
				if (it == from.ports_.end()) {
					throw UpdateError("Error on delete: "
						"NetPort {} wasn't found at "
						"server's configuration", p);
				}
				from.ports_.erase(it);
			}
		}
	}

	if (proto.nets()) {
		verify(from.flags_.isSrc_, "A geo-name can be used as an address"
		       " only in the src section.");
		for (size_t j = 0; j < proto.nets()->size(); ++j) {
			const auto data = proto.nets()->Get(j);
			verify(!!data, "Null 'Nets' field is not allowed in "
				"proto data.");

			size_t count = std::erase_if(from.nets_,
				[&](const XfwConfig::NetGeo &r) {
					return r.code_ == data->code();
				});
			if (!count) {
				throw UpdateError("Error on delete: Net "
					"address '{}' wasn't found at server's "
					"configuration", data->code());
			}
		}
	}
}

template<>
void
XfwConfigUpdater::set_attributes_to<ProtoNetRule, XfwConfig::NetIp>(
	const ProtoNetRule &nr_proto, XfwConfig::NetIp &rule)
{
	using namespace TempestaRPC;

	const auto &proto = nr_proto.rule();
	rule.ratelimit_index_ = get_ratelimit_idx(proto.ratelimit());

	const auto &flags = nr_proto.flags();
	rule.flags_ = {
		.isProcNet_ = flags.test(NetRuleOpt::NetRuleOpt_PROTECTED_NET),
		.isSrc_ = flags.test(NetRuleOpt::NetRuleOpt_SRC),
		.isAllowed_ = flags.test(NetRuleOpt::NetRuleOpt_ALLOW),
		.isTcp_ = flags.test(NetRuleOpt::NetRuleOpt_TCP),
		.isIpv6_ = flags.test(NetRuleOpt::NetRuleOpt_IPV6)
	};
}

template<>
void
XfwConfigUpdater::add_matchers_to<ProtoIcmpRule, XfwConfig::IcmpRule>(
	const ProtoIcmpRule &icmp_proto, XfwConfig::IcmpRule &out)
{
	const auto &proto = icmp_proto.rule();
	if (proto.types()) {
		out.types_.reserve(out.types_.size() + proto.types()->size());
		for (size_t i = 0; i < proto.types()->size(); ++i) {
			uint8_t type = proto.types()->Get(i);
			auto it = std::find(out.types_.begin(), out.types_.end(), type);
			if (it != out.types_.end()) {
				throw UpdateError("Error on add: Icmp type "
					"{} already exist at server's configuration",
					type);
			}
			out.types_.push_back(type);
		}
	}
}

template<>
void
XfwConfigUpdater::delete_matchers_from<ProtoIcmpRule, XfwConfig::IcmpRule>(
	const ProtoIcmpRule &icmp_proto, XfwConfig::IcmpRule &from)
{
	const auto &proto = icmp_proto.rule();
	assert(!!proto.types());
	for (size_t i = 0; i < proto.types()->size(); ++i) {
		uint8_t type = proto.types()->Get(i);
		auto it = std::find(from.types_.begin(), from.types_.end(), type);
		if (it == from.types_.end()) {
			throw UpdateError("Error on delete: Icmp type {} "
				     "wasn't found at server's configuration", type);
		}
		from.types_.erase(it);
	}
}

template<>
void
XfwConfigUpdater::set_attributes_to<ProtoIcmpRule, XfwConfig::IcmpRule>(
	const ProtoIcmpRule &icmp_proto, XfwConfig::IcmpRule &rule)
{
	using namespace TempestaRPC;

	const auto &proto = icmp_proto.rule();
	rule.ratelimit_index_ = get_ratelimit_idx(proto.ratelimit());

	const auto &flags = icmp_proto.flags();
	rule.isAllowed_ = flags.test(IcmpRuleOpt::IcmpRuleOpt_ALLOW);
	rule.isIpv6_ = flags.test(IcmpRuleOpt::IcmpRuleOpt_IPV6);
}

std::optional<XfwConfig::RatelimitIndex>
XfwConfigUpdater::get_ratelimit_idx(const flatbuffers::String *ratelimit)
{
	if (!ratelimit)
		return std::nullopt;

	verify(ratelimit->size(), "Empty ratelimit name is not allowed");
	std::string_view name = ratelimit->string_view();
	return config_.ratelimits_.get_active_index(name);
}
