/**
 *	Implementation for section with name "Defaults"
 *
 * SPDX-FileCopyrightText: © 2026 Tempesta Technologies, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include <utility>

#include "defaults_section.hh"

constexpr std::string_view
to_string_view(DefaultIndex f)
{
	using namespace std::literals;
	switch (f) {
	case DefaultIndex::XFW_DEFAULT_SRC_IP_TCP_IP4: return "src_ip ip4.tcp"sv;
	case DefaultIndex::XFW_DEFAULT_SRC_IP_TCP_IP6: return "src_ip ip6.tcp"sv;
	case DefaultIndex::XFW_DEFAULT_SRC_IP_UDP_IP4: return "src_ip ip4.udp"sv;
	case DefaultIndex::XFW_DEFAULT_SRC_IP_UDP_IP6: return "src_ip ip6.udp"sv;
	case DefaultIndex::XFW_DEFAULT_SRC_PORT_TCP_IP4: return "src_port ip4.tcp"sv;
	case DefaultIndex::XFW_DEFAULT_SRC_PORT_TCP_IP6: return "src_port ip6.tcp"sv;
	case DefaultIndex::XFW_DEFAULT_SRC_PORT_UDP_IP4: return "src_port ip4.udp"sv;
	case DefaultIndex::XFW_DEFAULT_SRC_PORT_UDP_IP6: return "src_port ip6.udp"sv;
	case DefaultIndex::XFW_DEFAULT_DST_TCP_IP4: return "dst ip4.tcp"sv;
	case DefaultIndex::XFW_DEFAULT_DST_TCP_IP6: return "dst ip6.tcp"sv;
	case DefaultIndex::XFW_DEFAULT_DST_UDP_IP4: return "dst ip4.udp"sv;
	case DefaultIndex::XFW_DEFAULT_DST_UDP_IP6: return "dst ip6.udp"sv;
	case DefaultIndex::XFW_DEFAULT_ICMP_IP4: return "icmp ip4"sv;
	case DefaultIndex::XFW_DEFAULT_ICMP_IP6: return "icmp ip6"sv;
	case DefaultIndex::XFW_DEFAULT_MAX: return ""sv;
	}
	assert(false && "Undefined default type used");
	std::unreachable();
}

/*
 * ------------------------------------------------------------------------
 *	XFW::DefaultsSection section parsing
 * ------------------------------------------------------------------------
 */
DefaultsSection::DefaultsSection(XfwConf &conf)
	: Section("defaults")
	, xfw_conf_(conf)
{
	defaults_.reserve(DefaultIndex::XFW_DEFAULT_MAX);
}

const char*
DefaultsSection::type_to_name(DefaultsSection::DataType type)
{
	switch(type){
	case DataType::SRC_IP:
		return "src_ip";
	case DataType::SRC_PORT:
		return "src_port";
	case DataType::DST:
		return "dst";
	case DataType::ICMP:
		return "icmp";
	}
	assert(false && "Undefined type used");
	std::unreachable();
}

void
DefaultsSection::commit()
{
	if (!xfw_conf_.defaults_.empty())
		throw Except("Two 'defaults' sections are not allowed");

	xfw_conf_.defaults_.swap(defaults_);
}

std::string
DefaultsSection::get_path() const
{
	return "xfw/defaults";
}

std::pair<bool, std::shared_ptr<LineConsumer>>
DefaultsSection::process_body()
{
	using namespace std::literals;
	using dt = DataType;

	auto name = peek_until(parsing_helpers::delimeters + ':');
	if (name == "src_ip"sv)
		return {true, std::make_shared<TcpIpDefaultSection>(dt::SRC_IP, *this)};
	else if (name == "src_port"sv)
		return {true, std::make_shared<TcpIpDefaultSection>(dt::SRC_PORT, *this)};
	else if (name == "dst"sv)
		return {true, std::make_shared<TcpIpDefaultSection>(dt::DST, *this)};
	else if (name == "icmp"sv)
		return {true, std::make_shared<IpProtoDefaultSection>(dt::ICMP, *this)};

	return {false, nullptr};
}

void
DefaultsSection::set_presence_or_throw(DefaultIndex flag)
{
	if (presence_flags_.test(flag))
		throw Except("Flag {} has already set", to_string_view(flag));

	presence_flags_.set(flag);
}
 /*
 * ------------------------------------------------------------------------
 *	XFW::DefaultsSection::TcpIpDefaultSection section parsing
 * ------------------------------------------------------------------------
 */
DefaultsSection::TcpIpDefaultSection::TcpIpDefaultSection(DataType type,
	DefaultsSection &parent)
	: Section(type_to_name(type), std::make_unique<ActionProcessor>())
	, ip4_tcp_(get_index(type, TransportProtocol::TCP, IPVersion::IP4))
	, ip6_tcp_(get_index(type, TransportProtocol::TCP, IPVersion::IP6))
	, ip4_udp_(get_index(type, TransportProtocol::UDP, IPVersion::IP4))
	, ip6_udp_(get_index(type, TransportProtocol::UDP, IPVersion::IP6))
	, parent_(parent)
{}

void
DefaultsSection::TcpIpDefaultSection::commit()
{
	assert(!!action_processor_);
	auto action = action_processor_->get_result();
	if (!action.has_value())
		throw Except("Action is required.");

	//The situation "src_ip : block;"
	if (!flags_.test(ip4_tcp_) && !flags_.test(ip6_tcp_)
	  && !flags_.test(ip4_udp_) && !flags_.test(ip6_udp_)) {
		set_flag(ip4_tcp_);
		set_flag(ip6_tcp_);
		set_flag(ip4_udp_);
		set_flag(ip6_udp_);
	}

	parent_.defaults_.emplace_back(std::move(action->ratelimit_), action->allow_,
				       std::move(flags_));
}

std::string
DefaultsSection::TcpIpDefaultSection::get_path() const
{
	return "xfw/defaults/" + name_;
}

bool
DefaultsSection::TcpIpDefaultSection::process_attributes()
{
	using namespace std::literals;

	auto name = peek_until(parsing_helpers::delimeters + ":.");
	if (name == "ip4"sv) {
		consume(name.size());
		if (peek() == '.') {
			consume(1);
			name = consume_until(parsing_helpers::delimeters + ":");
			if (name == "tcp")
				set_flag(ip4_tcp_);
			else if (name == "udp")
				set_flag(ip4_udp_);
			else
				throw Except("Unknown attribute {}.", name);
			return true;
		}
		set_flag(ip4_tcp_);
		set_flag(ip4_udp_);
		return true;
	}
	else if (name == "ip6"sv) {
		consume(name.size());
		if (peek() == '.') {
			consume(1);
			name = consume_until(parsing_helpers::delimeters + ":");
			if (name == "tcp")
				set_flag(ip6_tcp_);
			else if (name == "udp")
				set_flag(ip6_udp_);
			else
				throw Except("Unknown attribute {}.", name);
			return true;
		}
		set_flag(ip6_tcp_);
		set_flag(ip6_udp_);
		return true;
	}
	return false;
}

void
DefaultsSection::TcpIpDefaultSection::set_flag(DefaultIndex flag)
{
	parent_.set_presence_or_throw(flag);
	flags_.set(flag);
}

/*
 * ------------------------------------------------------------------------
 *	XFW::DefaultsSection section parsing
 * ------------------------------------------------------------------------
 */
DefaultsSection::IpProtoDefaultSection::IpProtoDefaultSection(DataType type,
	DefaultsSection &parent)
	: Section(type_to_name(type), std::make_unique<ActionProcessor>())
	, ip4_(get_index(type, TransportProtocol::NONE, IPVersion::IP4))
	, ip6_(get_index(type, TransportProtocol::NONE, IPVersion::IP6))
	, parent_(parent)
{}

void
DefaultsSection::IpProtoDefaultSection::commit()
{
	assert(!!action_processor_);

	auto action = action_processor_->get_result();
	if (!action.has_value())
		throw Except("Action is required.");

	//The situation "icmp : block;"
	if (!flags_.test(ip4_) && !flags_.test(ip6_)) {
		set_flag(ip4_);
		set_flag(ip6_);
	}

	parent_.defaults_.emplace_back(std::move(action->ratelimit_), action->allow_,
			       std::move(flags_));
}

std::string
DefaultsSection::IpProtoDefaultSection::get_path() const
{
	return "xfw/defaults/" + name_;
}

bool
DefaultsSection::IpProtoDefaultSection::process_attributes()
{
	using namespace std::literals;

	auto name = peek_until(parsing_helpers::delimeters + ":");
	if (name == "ip4"sv) {
		consume(name.size());
		set_flag(ip4_);
		return true;
	}
	else if (name == "ip6"sv) {
		consume(name.size());
		set_flag(ip6_);
		return true;
	}
	return false;
}

void
DefaultsSection::IpProtoDefaultSection::set_flag(DefaultIndex flag)
{
	parent_.set_presence_or_throw(flag);
	flags_.set(flag);
}

/*
 * ------------------------------------------------------------------------
 *	static asserts to be sure that get_index is working well
 * ------------------------------------------------------------------------
 */

/**
 * IndexTests is a helper struct used to verify at compile-time that the mapping
 * from DataType, IPVersion, and TransportProtocol to DefaultIndex is correct.
 * It leverages static_assert to catch mismatches during compilation, ensuring the
 * index calculation formula remains consistent.
 */
struct StaticGetIndexTests
{
	using ds = DefaultsSection;

	//checks for SRC_IP
	static_assert(ds::get_index(ds::DataType::SRC_IP, ds::TransportProtocol::TCP,
		ds::IPVersion::IP4) == DefaultIndex::XFW_DEFAULT_SRC_IP_TCP_IP4);
	static_assert(ds::get_index(ds::DataType::SRC_IP, ds::TransportProtocol::TCP,
		ds::IPVersion::IP6) == DefaultIndex::XFW_DEFAULT_SRC_IP_TCP_IP6);
	static_assert(ds::get_index(ds::DataType::SRC_IP, ds::TransportProtocol::UDP,
		ds::IPVersion::IP4) == DefaultIndex::XFW_DEFAULT_SRC_IP_UDP_IP4);
	static_assert(ds::get_index(ds::DataType::SRC_IP, ds::TransportProtocol::UDP,
		ds::IPVersion::IP6) == DefaultIndex::XFW_DEFAULT_SRC_IP_UDP_IP6);

	//checks for SRC_PORT
	static_assert(ds::get_index(ds::DataType::SRC_PORT, ds::TransportProtocol::TCP,
		ds::IPVersion::IP4) == DefaultIndex::XFW_DEFAULT_SRC_PORT_TCP_IP4);
	static_assert(ds::get_index(ds::DataType::SRC_PORT, ds::TransportProtocol::TCP,
		ds::IPVersion::IP6) == DefaultIndex::XFW_DEFAULT_SRC_PORT_TCP_IP6);
	static_assert(ds::get_index(ds::DataType::SRC_PORT, ds::TransportProtocol::UDP,
		ds::IPVersion::IP4) == DefaultIndex::XFW_DEFAULT_SRC_PORT_UDP_IP4);
	static_assert(ds::get_index(ds::DataType::SRC_PORT, ds::TransportProtocol::UDP,
		ds::IPVersion::IP6) == DefaultIndex::XFW_DEFAULT_SRC_PORT_UDP_IP6);

	//checks for DST
	static_assert(ds::get_index(ds::DataType::DST, ds::TransportProtocol::TCP,
		ds::IPVersion::IP4) == DefaultIndex::XFW_DEFAULT_DST_TCP_IP4);
	static_assert(ds::get_index(ds::DataType::DST, ds::TransportProtocol::TCP,
		ds::IPVersion::IP6) == DefaultIndex::XFW_DEFAULT_DST_TCP_IP6);
	static_assert(ds::get_index(ds::DataType::DST, ds::TransportProtocol::UDP,
		ds::IPVersion::IP4) == DefaultIndex::XFW_DEFAULT_DST_UDP_IP4);
	static_assert(ds::get_index(ds::DataType::DST, ds::TransportProtocol::UDP,
		ds::IPVersion::IP6) == DefaultIndex::XFW_DEFAULT_DST_UDP_IP6);

	//checks for ICMP
	static_assert(ds::get_index(ds::DataType::ICMP, ds::TransportProtocol::NONE,
		ds::IPVersion::IP4) == DefaultIndex::XFW_DEFAULT_ICMP_IP4);
	static_assert(ds::get_index(ds::DataType::ICMP, ds::TransportProtocol::NONE,
		ds::IPVersion::IP6) == DefaultIndex::XFW_DEFAULT_ICMP_IP6);

	//if we have more members, we have to expand checks above.
	static_assert(DefaultIndex::XFW_DEFAULT_ICMP_IP6 + 1 == DefaultIndex::XFW_DEFAULT_MAX);
};
