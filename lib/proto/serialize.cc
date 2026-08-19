/**
 *	FlatBuffers-based serialization for gRPC communication
 *
 * SPDX-FileCopyrightText: © 2026 Tempesta Technologies, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "../cli/tcl_private.hh"

#include "generated/proto_generated.hh"

#include "bitset_helper.hh"
#include "serialize.hh"

TempestaRPC::TcpFlagType TcpFlagToProtoFlag(TcpFlags::FlagType type)
{
	switch (type) {
	case TcpFlags::FlagType::ALL:
		return TempestaRPC::TcpFlagType_ALL;
	case TcpFlags::FlagType::SYN:
		return TempestaRPC::TcpFlagType_SYN;
	case TcpFlags::FlagType::RST:
		return TempestaRPC::TcpFlagType_RST;
	}
	assert(false && "Unreachable");
	std::unreachable();
}

flatbuffers::Offset<TempestaRPC::XFWCfg>
serialize(flatbuffers::grpc::MessageBuilder &builder, const XfwConf &xfw)
{
	using namespace TempestaRPC;

	// Create Syncookie.
	flatbuffers::Offset<TempestaRPC::Syncookie> syncookie;
	if (xfw.syncookie_.has_value()) {
		syncookie = CreateSyncookie(builder,
					    xfw.syncookie_.value().passive_timer_sec_,
					    xfw.syncookie_.value().flood_timer_sec_);
	}

	flatbuffers::Offset<TempestaRPC::TcpSynDrop> tcp_syn_drop;
	if (xfw.tcp_syn_drop_.has_value()) {
		tcp_syn_drop = CreateTcpSynDrop(
			builder,
			xfw.tcp_syn_drop_.value().hash_salt_,
			xfw.tcp_syn_drop_.value().time_min_ms_,
			xfw.tcp_syn_drop_.value().max_delay_ms_,
			xfw.tcp_syn_drop_.value().block_timeout_ms_,
			xfw.tcp_syn_drop_.value().retry_count_
		);
	}

	// Create TcpFlags.
	std::vector<flatbuffers::Offset<TempestaRPC::TcpFlagsFilter>> tcp_flags;
	if (!xfw.tcp_flags_.empty()) {
		tcp_flags.reserve(xfw.tcp_flags_.size());
		for (auto &rule: xfw.tcp_flags_) {
			tcp_flags.push_back(CreateTcpFlagsFilter(builder,
				TcpFlagToProtoFlag(rule.flag_),
				builder.CreateString(rule.ratelimit_)));
		}
	}

	// Create Ratelimits.
	std::vector<flatbuffers::Offset<TempestaRPC::Ratelimit>> ratelimits;
	if (!xfw.ratelimits_.empty()) {
		ratelimits.reserve(!xfw.ratelimits_.size());
		for (auto &rule: xfw.ratelimits_) {
			ratelimits.push_back(CreateRatelimit(builder,
				builder.CreateString(rule.alias_),
				bitset_serialize(builder, rule.flags_),
				rule.pps_.has_value()? rule.pps_.value(): 0,
				rule.bps_.has_value()? rule.bps_.value(): 0
			));
		}
	}

	// Serialize NetRules.
	std::vector<flatbuffers::Offset<TempestaRPC::NetRule>> net_rules;
	net_rules.reserve(xfw.net_rules_.size());
	for (auto &net_rule: xfw.net_rules_) {
		//net6
		std::vector<flatbuffers::Offset<TempestaRPC::Net6>> net6s;
		net6s.reserve(net_rule.net6s_.size());
		for (auto &net: net_rule.net6s_) {
			auto addr = builder.CreateVector(net.addr_,
				sizeof(net.addr_) / sizeof(uint8_t));
			auto ip = CreateNet6(builder, addr, net.port_, net.prefix_);
			net6s.push_back(ip);
		}

		//net4
		std::vector<flatbuffers::Offset<TempestaRPC::Net4>> net4s;
		net4s.reserve(net_rule.net4s_.size());
		for (auto &net: net_rule.net4s_) {
			auto addr = builder.CreateVector(net.addr_,
				sizeof(net.addr_) / sizeof(uint8_t));
			auto ip = CreateNet4(builder, addr, net.port_, net.prefix_);
			net4s.push_back(ip);
		}

		//nets
		std::vector<flatbuffers::Offset<TempestaRPC::NetCode>> nets;
		nets.reserve(net_rule.nets_.size());
		for (auto &net: net_rule.nets_) {
			auto ip = CreateNetCode(builder, net.port_, net.code_);
			nets.push_back(ip);
		}

		std::vector<flatbuffers::Offset<TempestaRPC::PortPair>> ports;
		if (not net_rule.ports_.empty()) {
			ports.reserve(net_rule.ports_.size());
			for (const auto& p : net_rule.ports_) {
				auto port_offset = TempestaRPC::CreatePortPair(builder,
					p.first, p.second.value_or(0));
				ports.push_back(port_offset);
			}
		}
		auto rule = CreateNetRule(builder,
			builder.CreateString(net_rule.alias_),
			bitset_serialize(builder, net_rule.flags_),
			net_rule.net6s_.empty()? 0 : builder.CreateVector(net6s),
			net_rule.net4s_.empty()? 0 : builder.CreateVector(net4s),
			net_rule.nets_.empty()? 0 : builder.CreateVector(nets),
			net_rule.ports_.empty()? 0 : builder.CreateVector(ports),
			net_rule.ratelimit_.empty()? 0:
				builder.CreateString(net_rule.ratelimit_));
		net_rules.push_back(rule);
	}

	std::vector<flatbuffers::Offset<TempestaRPC::IcmpRule>> icmp_rules;
	icmp_rules.reserve(xfw.icmp_rules_.size());
	for (auto &icmp_rule: xfw.icmp_rules_) {
		// We don't have empty alias now. At least we have "ip4" or "ip6" as alias.
		auto proto_rule = CreateIcmpRule(builder,
			builder.CreateString(icmp_rule.alias_),
			bitset_serialize(builder, icmp_rule.flags_),
			builder.CreateVector(icmp_rule.types_),
			icmp_rule.ratelimit_.empty()? 0:builder.CreateString(icmp_rule.ratelimit_)
		);
		icmp_rules.push_back(proto_rule);
	}

	std::vector<flatbuffers::Offset<TempestaRPC::DefaultAction>> defaults;
	defaults.reserve(xfw.defaults_.size());
	for (size_t i = 0; i < xfw.defaults_.size(); ++i) {
		const auto &rule = xfw.defaults_[i];
		auto proto_rule = CreateDefaultAction(builder,
			bitset_serialize(builder, rule.flags_),
			rule.allow_,
			rule.ratelimit_.empty()? 0: builder.CreateString(rule.ratelimit_));
		defaults.push_back(proto_rule);
	}

	// Create TcpAnomaly.
	flatbuffers::Offset<TempestaRPC::TcpAnomaly> tcp_anomaly;
	if (xfw.tcp_anomaly_.has_value()) {
		const auto &anomaly = xfw.tcp_anomaly_.value();
		const auto &flags = anomaly.bad_tcp_flags_;
		tcp_anomaly = CreateTcpAnomaly(builder,
			bitset_serialize(builder, anomaly.features_),
			flags.has_value() ? bitset_serialize(builder, flags.value()) : 0,
			anomaly.seqno_value_);
	}

	// Create IpProto.
	flatbuffers::Offset<TempestaRPC::IpProto> ip_proto;
	if (xfw.ip_proto_.has_value()) {
		ip_proto = CreateIpProto(builder,
			    bitset_serialize(builder,  xfw.ip_proto_->protocols_));
	}

	return CreateXFWCfg(builder,
			    bitset_serialize(builder, xfw.flags_),
			    xfw.ip_proto_.has_value() ? ip_proto : 0,
			    xfw.syncookie_.has_value() ? syncookie : 0,
			    xfw.tcp_syn_drop_.has_value() ? tcp_syn_drop : 0,
			    xfw.tcp_flags_.empty() ? 0 : builder.CreateVector(tcp_flags),
			    xfw.net_rules_.empty() ? 0 : builder.CreateVector(net_rules),
			    xfw.icmp_rules_.empty() ? 0 : builder.CreateVector(icmp_rules),
			    xfw.ratelimits_.empty() ? 0 : builder.CreateVector(ratelimits),
			    xfw.defaults_.empty() ? 0 : builder.CreateVector(defaults),
			    xfw.tcp_anomaly_.has_value() ? tcp_anomaly : 0);
}

flatbuffers::grpc::Message<TempestaRPC::Request>
build_set_config_request(const TlProgConf &conf)
{
	using namespace TempestaRPC;

	flatbuffers::grpc::MessageBuilder builder;
	std::vector<flatbuffers::Offset<ReqRecord>> records;
	records.reserve(ReqRecordBody_MAX);

	//Build TlConf
	if (conf.tl_prog_txt_len) {
		auto tl_text = builder.CreateVector(
			reinterpret_cast<const uint8_t*>(conf.tl_prog_txt),
			conf.tl_prog_txt_len);
		auto tl_prog = CreateTLProg(builder, tl_text);
		auto tl_request = CreateReqRecord(builder,
						  ReqRecType_RRT_TL_OBJ,
						  ReqRecordBody_tl_prog,
						  flatbuffers::Offset<void>(tl_prog.o));
		records.push_back(tl_request);
	}

	//Build TFWConf
	if (conf.tfw_conf_len) {
		auto tfw_text = builder.CreateVector(
			reinterpret_cast<const uint8_t*>(conf.tfw_conf),
			conf.tfw_conf_len);
		auto tfw_conf = CreateTLProg(builder, tfw_text);
		auto tfw_request = CreateReqRecord(builder,
						   ReqRecType_RRT_TFW_CFG,
						   ReqRecordBody_tfw_cfg,
						   flatbuffers::Offset<void>(tfw_conf.o));
		records.push_back(tfw_request);
	}

	//Build XfwConf
	if (conf.prvt->xfw_conf.has_value()) {
		auto xfw_conf = serialize(builder, conf.prvt->xfw_conf.value());
		auto xfw_request = CreateReqRecord(builder,
						ReqRecType_RRT_XFW_CFG,
						ReqRecordBody_xfw_cfg,
						flatbuffers::Offset<void>(xfw_conf.o));
		records.push_back(xfw_request);
	}

	if (records.empty()) {
		throw Except("There is nothing to pass to server. "
			     "Check your configuration");
	}

	auto request = CreateRequest(builder,
				     ProtoVersion,
				     builder.CreateVector(records));

	builder.Finish(request);
	return builder.ReleaseMessage<TempestaRPC::Request>();
}

flatbuffers::grpc::Message<TempestaRPC::Request>
build_reload_request()
{
	using namespace TempestaRPC;

	flatbuffers::grpc::MessageBuilder builder;
	auto record = CreateReqRecord(builder, ReqRecType_RRT_TFW_CFG_RLD);
	auto request = CreateRequest(builder,
				     ProtoVersion,
				     builder.CreateVector({record}));

	builder.Finish(request);
	return builder.ReleaseMessage<TempestaRPC::Request>();
}
