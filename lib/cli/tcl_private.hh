/**
 *	Tempesta Client library private definitions
 *
 * SPDX-FileCopyrightText: © 2026 Tempesta Technologies, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#pragma once
#include <arpa/inet.h>
#include <linux/types.h>

#include <optional>
#include <ostream>
#include <vector>

#include "../../bpf_uapi/default_index.h"
#include "../../bpf_uapi/tcp_control_bits.h"
#include "../../bpf_uapi/tcp_anomaly_features.h"
#include "../../bpf_uapi/supported_protocols.h"

#include "../bitset.hh"
#include "../enum_array.hh"
#include "../error.hh"

struct Syncookie {
	int	passive_timer_ = 0;
	int	flood_timer_ = 0;
};

struct TcpAnomalyRule {
	BitSet<TcpAnomalyFeature, XFW_TCP_ANOMALY_FEATURE_MAX>		features_;
	std::optional<BitSet<TcpControlBits, XFW_BIT_CONTROL_MAX>>	bad_tcp_flags_;
	uint32_t							seqno_value_{0};
};

struct IpProtoRule {
	BitSet<XfwSupportedProtocols, XFW_SUPPORTED_PROTOCOL_MAX> protocols_;
};

struct Ratelimit
{
	enum class Attr : uint8_t {
		DELETE		= 0, // action for data.
		_MAX_BIT
	};

	Ratelimit() = default;

	Ratelimit(Ratelimit &&o): alias_(std::move(o.alias_)),
		flags_(std::move(o.flags_)), pps_(o.pps_), bps_ (o.bps_)
	{}

	Ratelimit& operator=(Ratelimit &&o)
	{
		if (this == &o)
			return *this;

		alias_ = std::move(o.alias_);
		flags_ = std::move(o.flags_);
		pps_ = o.pps_;
		bps_ = o.bps_;
		return *this;
	}

	std::string			alias_;
	BitSet<Attr, Attr::_MAX_BIT>	flags_;
	std::optional<uint64_t>		pps_;
	std::optional<uint64_t>		bps_;
};

struct DefaultAction
{
	std::string				ratelimit_;
	bool					allow_ = false;
	BitSet<DefaultIndex, XFW_DEFAULT_MAX>	flags_;
};

struct TcpFlags
{
	enum class FlagType : uint8_t {
		ALL		= 0,
		SYN		= 1, // for packets with SYN
		RST		= 2, // for packets with RST
	};
	FlagType	flag_ = FlagType::ALL;
	std::string	ratelimit_;
};

struct Net4 {
	uint8_t		addr_[4];
	uint16_t	port_ = 0;
	uint8_t		prefix_ = 32;
};

struct Net6 {
	uint8_t		addr_[16];
	uint16_t	port_ = 0;
	uint8_t		prefix_ = 128;
};

struct NetCode {
	uint16_t		port_ = 0;
	union {
		uint16_t	code_;
		char		code_str_[2]; // Two symbols
	};
};

using NetPort = uint16_t;

class NetRule {
public:
	enum class Attr : uint8_t {
		IPV6		= 0, // otherwise IPv4
		TCP		= 1, // otherwise UDP
		SRC		= 2, // otherwise DST
		ALLOW		= 3, // otherwise BLOCK (for SRC)
		REPLACE		= 4, // action for data. Overwrite all section.
				     // If it is not set, see action in flag 5.
		DELETE		= 5, // action for data. Otherwise ADD.
		PROTECTED_NET	= 6,
		_MAX_BIT
	};

	std::string			alias_;
	BitSet<Attr, Attr::_MAX_BIT>	flags_;
	// We want to keep serialization/deserialization simple, without
	// polimorthism. In case of polimorthism we can't use struct without extra
	// copy of the data on deserialization with flatbuffers. But we want to avoid
	// extra coping. So let's split all kind of Nets by separate vectors.
	std::vector<Net6>	net6s_;
	std::vector<Net4>	net4s_;
	std::vector<NetCode>	nets_;
	std::vector<std::pair<NetPort,std::optional<NetPort>>>	ports_;
	std::string		ratelimit_;

public:
	explicit NetRule(std::optional<Attr> flag = std::nullopt)
	{
		if (flag)
			flags_.set(flag.value());
	}

	NetRule(NetRule &&o)
		: alias_(std::move(o.alias_)), flags_(std::move(o.flags_)),
		  net6s_(std::move(o.net6s_)), net4s_(std::move(o.net4s_)),
		  nets_(std::move(o.nets_)), ports_(std::move(o.ports_)),
		  ratelimit_(std::move(o.ratelimit_))
	{}

	NetRule& operator=(NetRule &&o)
	{
		if (this == &o)
			return *this;

		alias_ = std::move(o.alias_);
		flags_ = std::move(o.flags_);
		net6s_ = std::move(o.net6s_);
		net4s_ = std::move(o.net4s_);
		nets_ = std::move(o.nets_);
		ports_ = std::move(o.ports_);
		ratelimit_ = std::move(o.ratelimit_);

		return *this;
	}

	void
	set_action(std::string_view action)
	{
		using namespace std::literals;

		// We don't need to set flag for replace.
		// It was already set by default.
		if (action == "/del"sv) {
			flags_.unset(Attr::REPLACE);
			flags_.set(Attr::DELETE);
		}
		else if (action == "/add"sv) {
			flags_.unset(Attr::REPLACE);
		}
	}

	void
	set_proto(std::string_view proto)
	{
		using namespace std::literals;

		if (proto == "ip4.tcp"sv) {
			flags_.set(Attr::TCP);
		}
		else if (proto == "ip6.tcp"sv) {
			flags_.set(Attr::IPV6);
			flags_.set(Attr::TCP);
		}
		else if (proto == "ip4.udp"sv) {
		}
		else if (proto == "ip6.udp"sv) {
			flags_.set(Attr::IPV6);
		}
		else {
			throw Except("bad proto {}", proto);
		}
	}

public:
	friend std::ostream& operator<<(std::ostream &os, const NetRule &obj) noexcept;
};
static_assert(std::is_move_constructible<NetRule>::value,
			  "NetRule has to be move constructable!");
static_assert(std::is_move_assignable<NetRule>::value,
			  "NetRule has to be move assignable!");


//TODO #31: has to be removed after
class IcmpRule {
public:
	enum class Attr : uint8_t {
		IPV6		= 0, // otherwise IPv4
		ALLOW		= 1, // otherwise BLOCK
		REPLACE		= 2, // action for data. Overwrite all section.
				     // If it is not set, see action in flag DELETE.
		DELETE		= 3, // action for data. Otherwise ADD.
		_MAX_BIT
	};

	std::string			alias_;
	BitSet<Attr, Attr::_MAX_BIT>	flags_;
	std::vector<uint8_t>		types_;
	std::string			ratelimit_;

public:
	explicit IcmpRule(std::optional<Attr> flag = std::nullopt)
	{
		if (flag)
			flags_.set(flag.value());
	}

	IcmpRule(IcmpRule &&o)
		: alias_(std::move(o.alias_)), flags_(std::move(o.flags_)),
		 types_(std::move(o.types_)), ratelimit_(o.ratelimit_)
	{}

	IcmpRule& operator=(IcmpRule &&o)
	{
		if (this == &o)
			return *this;

		alias_ = std::move(o.alias_);
		flags_ = std::move(o.flags_);
		types_ = std::move(o.types_);
		ratelimit_ = std::move(o.ratelimit_);

		return *this;
	}

	void
	set_proto(std::string_view proto)
	{
		using namespace std::literals;

		if (proto == "ip6"sv) {
			flags_.set(Attr::IPV6);
		}
		else if (proto == "ip4"sv) {
		}
		else {
			throw Except("bad proto {}", proto);
		}
	}

public:
	friend std::ostream& operator<<(std::ostream &os, const IcmpRule &obj) noexcept;
};
static_assert(std::is_move_constructible<IcmpRule>::value,
	      "IcmpRule has to be move constructable!");
static_assert(std::is_move_assignable<IcmpRule>::value,
	      "IcmpRule has to be move assignable!");

/**
 * XFW module configuration.
 * Serializable to gRPC/flatbuffers.
 */
class XfwConf {
public:
	static const size_t FLAGS_BITS = 8;

	enum class Opt : uint8_t {
		XFW_CONFIG_PATCH		= 0, // Replace otherwise.
		TCP_ANOMALY_FILTER_OFF		= 1,
		TCP_AUTH_FILTER_ON		= 2,
		TCP_AUTH_FILTER_OFF		= 3,
		EVALUATION_MODE_ON		= 4,
		EVALUATION_MODE_OFF		= 5,
		TCP_SYNCOOKIE_FILTER_OFF	= 6,
		//If the TCP_RST_FLAGS_FILTER_OFF/TCP_SYN_FLAGS_FILTER_OFF flag is
		//set, the filter must be disabled. Otherwise, the data may be
		//present in a std::vector<TcpFlags>. In that case, the existing
		//values should be overwritten. If the data is not present, the
		//server'sbehavior has already been defined and should not be changed.
		TCP_SYN_FLAGS_FILTER_OFF	= 7,
		TCP_RST_FLAGS_FILTER_OFF	= 8,
		DNS_FILTER_ON			= 9,
		DNS_FILTER_OFF			= 10,
		IP_PROTO_FILTER_OFF		= 11,
		_MAX_BIT
	};

	BitSet<Opt, Opt::_MAX_BIT>	flags_;
	std::optional<IpProtoRule>	ip_proto_;
	std::optional<Syncookie>	syncookie_;
	std::vector<NetRule>		net_rules_;
	std::vector<TcpFlags>		tcp_flags_;
	std::vector<Ratelimit>		ratelimits_;
	std::vector<IcmpRule>		icmp_rules_;
	std::vector<DefaultAction>	defaults_;
	std::optional<TcpAnomalyRule>	tcp_anomaly_;

public:
	XfwConf()
	{}

	void
	add_netrule(NetRule &&nr)
	{
		for (auto& rule: net_rules_) {
			if (rule.flags_.test(NetRule::Attr::SRC)
			    != nr.flags_.test(NetRule::Attr::SRC))
				continue;
			if (rule.flags_.test(NetRule::Attr::PROTECTED_NET)
			    != nr.flags_.test(NetRule::Attr::PROTECTED_NET))
				continue;
			if (rule.alias_ != nr.alias_)
				continue;

			// Here we can merge section if it is possible.
			// But now we prohibit to have two section with the same name.
			throw Except("There is a conflict with another section"
				" with the same alias \'{}\'. Now it is prohibited"
				" to have two src/dst section with the same alias.",
				nr.alias_);
		}

		// It is a new rule, we can't merge it with another rule.
		// Just add it to the list.
		net_rules_.emplace_back(std::move(nr));
	}

	template<typename Type>
	void
	add_rule(Type &&r, std::vector<Type>& to)
	{
		for (auto& rule: to) {
			if (rule.alias_ != r.alias_)
				continue;

			// Here we can merge section if it is possible.
			// But now we prohibit to have two section with the same name.
			throw Except("There is a conflict with another section"
				" with the same alias \'{}\'. Now it is prohibited"
				" to have two section of the same type with the"
				" same alias.", r.alias_);
		}

		// It is a new rule, we can't merge it with another rule.
		// Just add it to the list.
		to.emplace_back(std::move(r));
	}

public:
	friend std::ostream& operator<<(std::ostream &os, const XfwConf &obj) noexcept;
};
static_assert(std::is_move_constructible<XfwConf>::value,
			  "XfwConf has to be move constructable!");
static_assert(std::is_move_assignable<XfwConf>::value,
			  "XfwConf has to be move assignable!");

/**
 * @tl_prog	- TL program byte string.
 * @xfw_conf	- XFW configuration.
 */
struct TlProgPrvt {
	std::string			tl_prog;
	std::optional<XfwConf>		xfw_conf;
};

namespace tcl {

void dump_except(Exception &e);

void dump_unknown_except();

}; // tcl
