/**
 *	Tempesta parser for configuration text
 *
 * SPDX-FileCopyrightText: © 2026 Tempesta Technologies, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include <stdlib.h>

#include <algorithm>
#include <optional>
#include <ranges>
#include <stack>
#include <utility>
#include <vector>

#include <boost/asio/ip/address.hpp>

#include "defaults_section.hh"
#include "ip_proto_section.hh"
#include "tempesta_client.hh" // for extern "C" API
#include "tcl_private.hh"
#include "tcp_anomaly_section.hh"
#include "line_consumer.hh"
#include "log.hh"
#include "section.hh"

static constexpr const uint16_t MAX_PORTS = 65535;

//TODO #208: split this file for separated classes during moving to StateProcessor

/**
 * Class for reading any section without internal's parsing. Attributes are
 * skipped, so if you have to prohibit attributes, you have to inherit from this
 * class and override 'process_attributes' function. All '\n' and spaces from the
 * input are removed. The result line will be saved to @data.
 */
class GenericSection : public Section {
public:
	GenericSection(const char *name, char *&data, size_t &len)
		: Section(name),
		  data_(data), data_len_(len)
	{}

	virtual ~GenericSection() override {}

private:
	/**
	 * Skip the whole body of the section, save it to tmp_acc_.
	 */
	virtual std::pair<bool, std::shared_ptr<LineConsumer>> process_body() override;

	/**
	 * Save all section to @data_ and set @data_len_
	 */
	virtual void commit() override;

private:
	// appropriate TlProgConf pointer
	char		*&data_;
	// length of appropriate TlProgConf data
	size_t		&data_len_;
	// '{' and '}' brace counter
	int		bcnt_ = 0;
};

// There is no need to minimize TL programs as they're
// compiled right away. We need to preserve the lines
// structure to report any issues with the code from the
// compiler to a user.
struct TlSection final: public GenericSection {
	TlSection(TlProgConf &conf)
		: GenericSection("tl", conf.tl_prog_txt, conf.tl_prog_txt_len)
	{
		accumulate_enabled_ = true;
		accumulate_spaces_ = true;
		accumulate_comments_ = true;
	}

	virtual ~TlSection() override {}
};

class XfwSection final: public Section {
protected:
	class NetRuleSection: public Section {
	public:
		NetRuleSection(const char *name, XfwConf &conf, NetRule::Attr type)
			: Section(name, std::make_unique<ActionProcessor>(),
				  std::make_unique<EditProcessor>())
			, xfw_conf_(conf), nr_(type)
		{
		}

		NetRuleSection(const char *name, XfwConf &conf)
			: Section(name, std::make_unique<ActionProcessor>(),
				  std::make_unique<EditProcessor>())
			, xfw_conf_(conf)
		{
		}

		virtual ~NetRuleSection() override {}

	private:
		virtual std::pair<bool, std::shared_ptr<LineConsumer>> process_body() override;

		virtual std::string
		get_path() const override
		{
			const std::string path = "xfw/" + Section::get_path();
			return path;
		}

		virtual void commit() override;

	private:
		XfwConf &xfw_conf_;

	protected:
		NetRule nr_;
		bool has_protocol_ = false;
	};

	class DstSection final: public NetRuleSection {
	public:
		DstSection(XfwConf &conf)
			: NetRuleSection("dst", conf)
		{}

		virtual ~DstSection() override {}

	private:
		virtual bool process_attributes() override;
	};

	class SrcSection final: public NetRuleSection {
	public:
		SrcSection(XfwConf &conf)
			: NetRuleSection("src", conf, NetRule::Attr::SRC)
		{}

		virtual ~SrcSection() override {}

	private:
		virtual bool process_attributes() override;
	};

	class ProtectedNetSection final: public NetRuleSection
	{
	public:
		ProtectedNetSection(XfwConf &conf)
			: NetRuleSection("net", conf, NetRule::Attr::PROTECTED_NET)
		{}

		virtual ~ProtectedNetSection() override {}

	private:
		virtual bool process_attributes() override;
	};

	struct IcmpSection final: public Section {
	public:
		IcmpSection(XfwConf &conf)
			: Section("icmp", std::make_unique<ActionProcessor>(),
				  std::make_unique<EditProcessor>())
			, xfw_conf_(conf)
		{}

		virtual ~IcmpSection() override {}

	private:
		virtual bool process_attributes() override;

		virtual void commit() override;

	protected:
		virtual std::pair<bool, std::shared_ptr<LineConsumer>> process_body() override;

		virtual std::string
		get_path() const override
		{
			return "xfw/icmp";
		}
	private:
		XfwConf&	xfw_conf_;
		IcmpRule	icmp_rule_;
	};

	struct TcpFlagSection final: public Section {
	public:
		TcpFlagSection(XfwConf &conf)
			: Section("tcp_flags", std::make_unique<ActionProcessor>(),
				  std::make_unique<EditProcessor>())
			, xfw_conf_(conf)
		{}

		virtual ~TcpFlagSection() override {}

	private:
		virtual bool process_attributes() override;

		virtual void commit() override;

	protected:
		virtual std::string
		get_path() const override
		{
			return "xfw/tcp_flags";
		}
	private:
		XfwConf			&xfw_conf_;
		TcpFlags::FlagType	flag_ = TcpFlags::FlagType::ALL;
	};

	struct DnsFilterSection final: public Section {
	public:
		DnsFilterSection(XfwConf &conf)
			: Section("dns_filter", std::unique_ptr<ActionProcessor>(),
				 std::make_unique<EditProcessor>())
			, xfw_conf_(conf)
		{}

		virtual ~DnsFilterSection() override {}

	private:
		virtual void commit() override;

	private:
		XfwConf			&xfw_conf_;
	};

	struct EvaluationModeSection final: public Section {
	public:
		EvaluationModeSection(XfwConf &conf)
			: Section("evaluation_mode", std::unique_ptr<ActionProcessor>(),
				  std::make_unique<EditProcessor>())
			, xfw_conf_(conf)
		{}

		virtual ~EvaluationModeSection() override {}

	private:
		virtual void commit() override;

	private:
		XfwConf		&xfw_conf_;
	};

	struct TcpAuthSection final: public Section {
	public:
		TcpAuthSection(XfwConf &conf)
			: Section("tcp_auth_filter", std::unique_ptr<ActionProcessor>(),
				  std::make_unique<EditProcessor>())
			, xfw_conf_(conf)
		{}

		virtual ~TcpAuthSection() override {}

	private:
		virtual void commit() override;

	private:
		XfwConf			&xfw_conf_;
	};

	struct TcpSyncookieSection final: public Section {
	public:
		TcpSyncookieSection(XfwConf &conf)
			: Section("tcp_syncookies", std::unique_ptr<ActionProcessor>(),
				  std::make_unique<EditProcessor>())
			, xfw_conf_(conf)
		{}

		virtual ~TcpSyncookieSection() override {}

	private:
		virtual bool process_attributes() override;

		virtual void commit() override;

	private:
		XfwConf				&xfw_conf_;
		std::optional<uint32_t>		f_timer_;
		std::optional<uint32_t>		p_timer_;
	};

	class RatelimitSection final: public Section
	{
	public:
		RatelimitSection(XfwConf &conf)
			: Section("ratelimit", std::make_unique<ActionProcessor>(),
				  std::make_unique<EditProcessor>())
			, xfw_conf_(conf)
		{}

		virtual ~RatelimitSection() override {}

	private:
		virtual bool process_attributes() override;

		virtual void commit() override;

	private:
		XfwConf			&xfw_conf_;
		Ratelimit		ratelimit_;
	};

public:
	XfwSection(TlProgConf &conf)
		: Section("xfw"), conf_(conf)
	{}

	virtual ~XfwSection() override {}

protected:
	virtual std::pair<bool, std::shared_ptr<LineConsumer>> process_body() override;

	virtual void commit() override
	{
		conf_.prvt->xfw_conf = std::move(xfw_conf_);
	}

private:
	TlProgConf	&conf_;
	XfwConf		xfw_conf_;
};

struct TfwSection : public GenericSection {
	TfwSection(TlProgConf &conf)
		: GenericSection("tfw", conf.tfw_conf, conf.tfw_conf_len)
	{
		accumulate_enabled_ = true;
	}

	virtual ~TfwSection() override {}
};

struct RootSection final: public LineConsumer {
	RootSection(TlProgConf &conf)
		: LineConsumer(), conf_(conf)
	{
	}

	virtual ~RootSection() override {}

	std::shared_ptr<LineConsumer> consume_line() override;

	virtual std::string
	get_path() const override
	{
		return "/";
	}

private:
	TlProgConf &conf_;
};

/**
 * The class manages the stack of parsers.
 */
class ParserManager {
public:
	ParserManager(std::shared_ptr<LineConsumer> root): root_(root)
	{}

	void
	push_parser(std::shared_ptr<LineConsumer>&& newParser)
	{
		history_.push(newParser);
	}

	void
	pop_parser()
	{
		assert(!history_.empty());
		history_.pop();
	}

	LineConsumer*
	get_current_parser() const
	{
		return !history_.empty()? history_.top().get(): root_.get();
	}

private:
	std::shared_ptr<LineConsumer> root_;
	std::stack<std::shared_ptr<LineConsumer>> history_; //history for undo
};

/*
 * ------------------------------------------------------------------------
 *	GenericSection class implementation
 * ------------------------------------------------------------------------
 */
/**
 * Tracks the balance of opening and closing brackets. Returns control after
 * each newly found closing bracket or at the end of line. It consumes all '}'
 * except the situation when balance has violated by extra '}'
 */
std::pair<bool, std::shared_ptr<LineConsumer>>
GenericSection::process_body()
{
	using namespace std::literals;

	assert(state_ == State::ProcessingBody);

	while (!empty()){
		switch (peek()) {
		case '{':
			++bcnt_;
			break;
		case '}':
			--bcnt_;
			if (bcnt_ == -1)
				return {false, nullptr};
			break;
		default:
			break;
		}
		consume(1);
	}
	return {true, shared_from_this()};
};

void
GenericSection::commit()
{
	if (accumulated_.empty())
		return;

	data_len_ = accumulated_.size();
	data_ = new char[data_len_];
	memcpy(data_, accumulated_.c_str(), data_len_);
}

/*
 * ------------------------------------------------------------------------
 *	XFW section parsing
 * ------------------------------------------------------------------------
 */
std::pair<bool, std::shared_ptr<LineConsumer>>
XfwSection::process_body()
{
	using namespace std::literals;

	auto name = peek_until(parsing_helpers::delimeters + "/");
	if (name == "src"sv)
		return {true, std::make_shared<SrcSection>(xfw_conf_)};
	else if (name == "dst"sv)
		return {true, std::make_shared<DstSection>(xfw_conf_)};
	else if (name == "ratelimit"sv)
		return {true, std::make_shared<RatelimitSection>(xfw_conf_)};
	else if (name == "tcp_flags"sv)
		return {true, std::make_shared<TcpFlagSection>(xfw_conf_)};
	else if (name == "evaluation_mode"sv)
		return {true, std::make_shared<EvaluationModeSection>(xfw_conf_)};
	else if (name == "tcp_anomaly_filter"sv)
		return {true, std::make_shared<TcpAnomalySection>(xfw_conf_)};
	else if (name == "dns_filter"sv)
		return {true, std::make_shared<DnsFilterSection>(xfw_conf_)};
	else if (name == "tcp_auth_filter"sv)
		return {true, std::make_shared<TcpAuthSection>(xfw_conf_)};
	else if (name == "tcp_syncookies"sv)
		return {true, std::make_shared<TcpSyncookieSection>(xfw_conf_)};
	else if (name == "net"sv)
		return {true, std::make_shared<ProtectedNetSection>(xfw_conf_)};
	else if (name == "icmp"sv)
		return {true, std::make_shared<IcmpSection>(xfw_conf_)};
	else if (name == "defaults"sv)
		return {true, std::make_shared<DefaultsSection>(xfw_conf_)};
	else if (name == "ip_proto"sv)
		return {true, std::make_shared<IpProtoSection>(xfw_conf_)};
	
	return {false, nullptr};
}

/*
 * ------------------------------------------------------------------------
 *	XFW::NetRuleSection section parsing
 * ------------------------------------------------------------------------
 */

NetCode
get_netcode(std::string_view code, std::optional<uint16_t> port)
{
	NetCode net;
	if (port.has_value())
		net.port_ = *port;

	assert(code.size() == 2);
	net.code_str_[0] = code[0];
	net.code_str_[1] = code[1];
	return net;
}

Net4
get_net4(const boost::asio::ip::address &ip, const std::optional<uint8_t> &mask,
	 const std::optional<uint16_t> &port)
{
	Net4 net;
	if (port.has_value())
		net.port_ = *port;
	if (mask.has_value())
		net.prefix_ = *mask;

	if (port.has_value() && mask.has_value())
		throw Except {"Mask and port cannot be set at one time "
				"for one rule"};

	/* to_bytes() returns address in network byte order */
	std::copy_n(ip.to_v4().to_bytes().begin(), sizeof(net.addr_), net.addr_);
	return net;
}

Net6
get_net6(const boost::asio::ip::address &ip, const std::optional<uint8_t> &mask,
	 const std::optional<uint16_t> &port)
{
	Net6 net;
	if (port.has_value())
		net.port_ = *port;
	if (mask.has_value())
		net.prefix_ = *mask;

	if (port.has_value() && mask.has_value())
		throw Except {"Mask and port cannot be set at one time "
				"for one rule"};

	/* to_bytes() returns address in network byte order */
	std::copy_n(ip.to_v6().to_bytes().begin(), sizeof(net.addr_), net.addr_);
	return net;
}

boost::asio::ip::address
convert_ip(std::string_view ip)
{
	try {
		auto ipb = boost::asio::ip::address::from_string(std::string(ip));
		return ipb;
	}
	catch(const boost::system::system_error &e)
	{
		throw Except("Bad ip {}: {}.", ip,  e.what());
	}
}

std::optional<uint8_t>
read_mask(std::string_view lv, size_t slash_pos,
				      size_t colon_pos, uint32_t limit)
{
	if (slash_pos == std::string_view::npos)
		return std::nullopt;

	size_t end = (colon_pos != std::string_view::npos)? colon_pos: lv.size();
	std::string mask(lv.substr(slash_pos + 1, end - slash_pos - 1));

	try {
		uint32_t mask_val = std::stoul(mask);
		if (mask_val > limit)
			throw Except("Incorrect mask found {}.", mask_val);
		return mask_val;
	}
	catch (const std::invalid_argument &e) {
		throw Except("Invalid argument in mask {}: {}.", mask, e.what());
	}
	catch (const std::out_of_range &e) {
		throw Except("Mask {} is out of range: {}.", mask, e.what());
	}
}

std::optional<uint8_t>
read_mask4(std::string_view lv, size_t slash_pos, size_t colon_pos)
{
	return read_mask(lv, slash_pos, colon_pos, 32);
}

std::optional<uint8_t>
read_mask6(std::string_view lv, size_t slash_pos, size_t colon_pos)
{
	return read_mask(lv, slash_pos, colon_pos, 128);
}


std::pair<NetPort,std::optional<NetPort>>
read_ports(std::string_view interval_begin, std::string_view interval_end)
{
	using namespace parsing_helpers;

	uint32_t port = parse_as<uint32_t>(interval_begin);
	if (port > MAX_PORTS || port == 0)
		throw Except("'port' must be 0 < {} <= {}", port, MAX_PORTS);

	if (interval_end.empty())
		return {static_cast<uint16_t>(port), std::nullopt};

	uint32_t port_end = parse_as<uint32_t>(interval_end);
	if (port_end > MAX_PORTS)
		throw Except("'port_end' must be <= {}", MAX_PORTS);
	if (port >= port_end)
		throw Except("start port of range must be less than end");

	return {static_cast<uint16_t>(port), {static_cast<uint16_t>(port_end)}};
}

uint16_t
read_port(std::string_view lv)
{
	uint32_t port = parsing_helpers::parse_as<uint32_t>(lv);

	if (port > MAX_PORTS || port == 0)
		throw Except("Port must be 0 < {} <= {}", port, MAX_PORTS);

	return port;
}

std::optional<uint16_t>
read_port(std::string_view lv, size_t colon_pos)
{
	if (colon_pos == std::string_view::npos)
		return std::nullopt;

	return read_port(lv.substr(colon_pos + 1));
}

/**
 * We do not perform matching with the table of two-letter ISO codes, because
 * it is enought to check ip's length and verify that maximum one ':' presented.
 * However, if such a need arises, we will add the check here.
 */
bool
is_iso_country_code(std::string_view lv)
{
	assert(!lv.empty());
	size_t colon_pos_l = lv.find_last_of(':');
	std::string_view ip = lv.substr(0, colon_pos_l);

	if (ip.size() != 2)
		return false;

	// We have to exclude short version of ipv6 as "::1". If there is another
	// colon then it has to be a regular ipv6 address.
	size_t colon_pos_f = lv.find_first_of(':');
	if (colon_pos_f != colon_pos_l)
		return false;

	return true;
}

bool
is_port(std::string_view lv)
{
	if (lv[0] != ':')
		return false;

	if (lv.size() == 1)
		throw Except("Bad ip6 or port format");

	// It still could be ip6
	if (lv[1] == ':')
		return false;

	// Now it looks like a port, parse it in that way.
	return true;
}

/**
 * Parses a string containing an ISO code address and extracts the IP address and
 * port if it is available.
 */
std::tuple<std::string_view, std::optional<uint16_t>>
read_iso_code_address(std::string_view lv)
{
	assert(!lv.empty());
	size_t colon_pos = lv.find_last_of(':');

	std::string_view ip = lv.substr(0, colon_pos);
	auto port = read_port(lv, colon_pos);

	return {ip, port};
}

/**
 * Parses a string containing an ipv6 address and extracts the IP address,
 * port and mask - if they are available.
 */
std::tuple<std::string_view, std::optional<uint8_t>, std::optional<uint16_t>>
read_ip6_address(std::string_view lv)
{
	assert(!lv.empty());

	std::string_view ip;
	size_t slash_pos = lv.find_first_of('/');
	size_t port_colon_pos = lv.find_last_of(':');

	/* Parse ip address */
	if (lv[0] == '[') {
		size_t close_brace_pos = lv.find_first_of(']');
		if (close_brace_pos == std::string_view::npos)
			throw Except("'[' must be followed by ']', but it has "
				     "been missed.");
		ip = lv.substr(1, close_brace_pos - 1);
		if (slash_pos != std::string_view::npos)
			throw Except("IPv6 address in square brackets [] "
				     "must be followed by port. "
				     "Port and mask cannot be specified "
				     "at the same time");
		if (port_colon_pos < close_brace_pos)
			port_colon_pos = std::string_view::npos;
	}
	else {
		if (slash_pos == std::string_view::npos)
			return {lv, std::nullopt, std::nullopt};
		ip = lv.substr(0, slash_pos);

		if (port_colon_pos != std::string_view::npos &&
		    port_colon_pos < slash_pos)
			port_colon_pos = std::string_view::npos;
	}

	/* Parse mask if exists */
	auto mask = read_mask6(lv, slash_pos, port_colon_pos);
	auto port = read_port(lv, port_colon_pos);

	return {ip, mask, port};
}

/**
 * Parses a string containing an ipv4 address and extracts the IP address,
 * port and mask - if they are available.
 */
std::tuple<std::string_view, std::optional<uint8_t>, std::optional<uint16_t>>
read_ip4_address(std::string_view lv)
{
	assert(!lv.empty());

	std::string_view ip;
	size_t slash_pos = lv.find_first_of('/');
	size_t colon_pos = lv.find_first_of(':');

	size_t first_delim = std::min(slash_pos, colon_pos);
	ip = lv.substr(0, first_delim);

	auto mask = read_mask4(lv, slash_pos, colon_pos);
	auto port = read_port(lv, colon_pos);

	return {ip, mask, port};
}

std::pair<bool, std::shared_ptr<LineConsumer>>
XfwSection::NetRuleSection::process_body()
{
	using namespace boost::asio;
	using namespace std::literals;

	auto ipv = consume_until(parsing_helpers::delimeters + "-");
	if (ipv.empty())
		return {false, nullptr};

	if (is_iso_country_code(ipv)) {
		auto[ip, port] = read_iso_code_address(ipv);
		NetCode net = get_netcode(ip, port);
		nr_.nets_.emplace_back(std::move(net));
	}
	else if (is_port(ipv)) {
		string_view interval_begin = ipv.substr(1);
		string_view interval_end;

		skip_spaces();
		if (peek() == '-') {
			consume(1);
			skip_spaces();
			interval_end = consume_until_delimeters();
		}

		nr_.ports_.push_back(read_ports(interval_begin, interval_end));
	}
	else {
		bool is_ipv6 = nr_.flags_.test(NetRule::Attr::IPV6);
		if (is_ipv6) {
			auto[ip, mask, port] = read_ip6_address(ipv);
			Net6 net = get_net6(convert_ip(ip), mask, port);
			nr_.net6s_.emplace_back(std::move(net));
		}
		else {
			auto[ip, mask, port] = read_ip4_address(ipv);
			Net4 net = get_net4(convert_ip(ip), mask, port);
			nr_.net4s_.emplace_back(std::move(net));
		}
	}

	if (peek() == ',')
		consume(1);

	return {true, shared_from_this()};
}

void
XfwSection::NetRuleSection::commit()
{
	assert(!!action_processor_);
	auto action = action_processor_->get_result();
	if (action.has_value()) {
		if (action.value().allow_)
			nr_.flags_.set(NetRule::Attr::ALLOW);
		nr_.ratelimit_ = action.value().ratelimit_;
	}

	if (!has_protocol_ &&
	    !(nr_.nets_.empty() && nr_.net4s_.empty() && nr_.net6s_.empty())) {
		throw Except("You need to point out a proto type tcp/udp for ips");
	}

	if (section_alias_.empty())
		throw Except("Empty section name is not allowed for this rule");

	assert(!!edit_processor_);
	auto edit_action = edit_processor_->get_result();
	switch (edit_action.value_or(EditProcessor::EditType::REPLACE)) {
	case EditProcessor::EditType::ADD:
		if (action.has_value())
			throw Except("You should not specify action value "
				     "for /add edit");
		break;
	case EditProcessor::EditType::DELETE:
		if (action.has_value())
			throw Except("You should not specify action value "
				     "for /del edit");
		nr_.flags_.set(NetRule::Attr::DELETE);
		break;
	case EditProcessor::EditType::REPLACE:
		nr_.flags_.set(NetRule::Attr::REPLACE);
		break;
	assert(false && "Undefined edit type used");
	std::unreachable();
	}

	nr_.alias_ = std::move(section_alias_);
	xfw_conf_.add_netrule(std::move(nr_));
}

/*
 * ------------------------------------------------------------------------
 *	XFW::SrcSection section parsing
 * ------------------------------------------------------------------------
 */
bool
XfwSection::SrcSection::process_attributes()
{
	using namespace std::literals;

	auto name = peek_until(parsing_helpers::delimeters + ':');
	if (name.starts_with("ip")) {
		nr_.set_proto(name);
		if (section_alias_.empty())
			section_alias_ = name;
		has_protocol_ = true;
		consume(name.size());
		return true;
	}
	return false;
}

/*
 * ------------------------------------------------------------------------
 *	XFW::DstSection section parsing
 * ------------------------------------------------------------------------
 */
bool
XfwSection::DstSection::process_attributes()
{
	using namespace std::literals;

	auto name = peek_until(parsing_helpers::delimeters + ':');
	if (name.starts_with("ip")) {
		nr_.set_proto(name);
		if (section_alias_.empty())
			section_alias_ = name;
		has_protocol_ = true;
		consume(name.size());
		return true;
	}
	return false;
}

/*
 * ------------------------------------------------------------------------
 *	XFW::ProtectedNetSection section parsing
 * ------------------------------------------------------------------------
 */
bool
XfwSection::ProtectedNetSection::process_attributes()
{
	using namespace std::literals;

	//All sections must have unique names, so let's setup default names for
	//"lan ip6" and "lan ip4"
	auto name = peek_until_delimeters();
	if (name == "ip6") {
		if (section_alias_.empty())
			section_alias_ = name;
		nr_.flags_.set(NetRule::Attr::IPV6);
		has_protocol_ = true;
		consume(name.size());
		return true;
	}
	if (name == "ip4") {
		if (section_alias_.empty())
			section_alias_ = name;
		has_protocol_ = true;
		consume(name.size());
		return true;
	}
	return false;
}

/*
 * ------------------------------------------------------------------------
 *	XFW::IcmpSection section parsing
 * ------------------------------------------------------------------------
 */
bool
XfwSection::IcmpSection::process_attributes()
{
	using namespace std::literals;

	auto name = peek_until(parsing_helpers::delimeters + ':');
	if (name.empty())
		return false;

	if (name.starts_with("ip")) {
		icmp_rule_.set_proto(name);
		if (section_alias_.empty())
			section_alias_ = name;
		consume(name.size());
		return true;
	}
	return false;
}

std::pair<bool, std::shared_ptr<LineConsumer>>
XfwSection::IcmpSection::process_body()
{
	using namespace std::literals;

	auto nv = consume_until_delimeters();
	if (nv.empty())
		return {false, nullptr};
	uint32_t num = parsing_helpers::parse_as<uint32_t>(nv);
	icmp_rule_.types_.push_back(num);
	if (peek() == ',')
		consume(1);
	return {true, shared_from_this()};
}

void
XfwSection::IcmpSection::commit()
{
	assert(!!action_processor_);
	auto action = action_processor_->get_result();
	if (action.has_value()) {
		if (action.value().allow_)
			icmp_rule_.flags_.set(IcmpRule::Attr::ALLOW);
		icmp_rule_.ratelimit_ = action.value().ratelimit_;
	}

	if (section_alias_.empty())
		throw Except("Empty name is not allowed for this rule");

	assert(!!edit_processor_);
	auto edit_action = edit_processor_->get_result();
	if (edit_action.has_value()) {
		switch (edit_action.value()) {
		case EditProcessor::EditType::ADD:
			break;
		case EditProcessor::EditType::DELETE:
			icmp_rule_.flags_.set(IcmpRule::Attr::DELETE);
			break;
		case EditProcessor::EditType::REPLACE:
			icmp_rule_.flags_.set(IcmpRule::Attr::REPLACE);
			break;
		assert(false && "Undefined edit type used");
		std::unreachable();
		}
	}
	else {
		icmp_rule_.flags_.set(IcmpRule::Attr::REPLACE);
	}
	icmp_rule_.alias_ = std::move(section_alias_);
	xfw_conf_.add_rule(std::move(icmp_rule_), xfw_conf_.icmp_rules_);
}

/*
 * ------------------------------------------------------------------------
 *	XFW:TcpFlagSection section parsing
 * ------------------------------------------------------------------------
 */
bool
XfwSection::TcpFlagSection::process_attributes()
{
	using namespace std::literals;

	auto name = peek_until(parsing_helpers::delimeters + ':');
	if (name == "syn"sv) {
		if (flag_ != TcpFlags::FlagType::ALL)
			throw Except("Several tcp flags are not alowed in one rule");
		flag_ = TcpFlags::FlagType::SYN;
		consume(name.size());
		return true;
	}
	else if (name == "rst"sv) {
		if (flag_ != TcpFlags::FlagType::ALL)
			throw Except("Several tcp flags are not alowed in one rule");
		flag_ = TcpFlags::FlagType::RST;
		consume(name.size());
		return true;
	}
	return false;
}

std::string_view
FlagTypeName(TcpFlags::FlagType type) noexcept
{
	switch (type) {
	case TcpFlags::FlagType::SYN:
		return "syn";
	case TcpFlags::FlagType::RST:
		return "rst";
	case TcpFlags::FlagType::ALL:
		return "syn and rst";
	default:
		return "unknown";
	}
}

void
XfwSection::TcpFlagSection::commit()
{
	bool has_removed = false;
	assert(!!edit_processor_);
	auto edit_action = edit_processor_->get_result();
	if (edit_action.has_value()) {
		if (*edit_action != EditProcessor::EditType::DELETE)
			throw Except("Operation '{}' is not allowed in tcp_flag filter",
				     EditProcessor::to_string(edit_action.value()));
		has_removed = true;
	}

	assert(!!action_processor_);
	auto action = action_processor_->get_result();
	if (has_removed) {
		if (action.has_value())
			throw Except("'/del' can't be used with an action");

		switch(flag_) {
		case TcpFlags::FlagType::SYN:
			xfw_conf_.flags_.set(XfwConf::Opt::TCP_SYN_FLAGS_FILTER_OFF);
			break;
		case TcpFlags::FlagType::RST:
			xfw_conf_.flags_.set(XfwConf::Opt::TCP_RST_FLAGS_FILTER_OFF);
			break;
		case TcpFlags::FlagType::ALL:
			xfw_conf_.flags_.set(XfwConf::Opt::TCP_SYN_FLAGS_FILTER_OFF);
			xfw_conf_.flags_.set(XfwConf::Opt::TCP_RST_FLAGS_FILTER_OFF);
			break;
		}
		return;
	}

	if (!action.has_value() || action->ratelimit_.empty())
		throw Except("'ratelimit' is required field.");

	auto &tcp_flags = xfw_conf_.tcp_flags_;

	bool ruleExist = (flag_ == TcpFlags::FlagType::ALL && !tcp_flags.empty());
	if (!ruleExist) {
		auto it = std::find_if(tcp_flags.begin(), tcp_flags.end(),
			[&](const TcpFlags& rule) {
				return rule.flag_ == flag_ ||
				       rule.flag_ == TcpFlags::FlagType::ALL;
			});

		ruleExist = (it != tcp_flags.end());
	}

	if (ruleExist)
		throw Except("Rule with type {} conflict with another one.",
			      FlagTypeName(flag_));

	tcp_flags.emplace_back(flag_, std::move(action->ratelimit_));
}

/*
 * ------------------------------------------------------------------------
 *	XfwSection::DnsFilterSection section parsing
 * ------------------------------------------------------------------------
 */
void
XfwSection::DnsFilterSection::commit()
{
	assert(!!edit_processor_);
	auto edit_action = edit_processor_->get_result();
	if (edit_action.has_value()) {
		if (*edit_action != EditProcessor::EditType::DELETE)
			throw Except("Operation '{}' is not allowed in {}",
				     EditProcessor::to_string(edit_action.value()),
				     name_);
		xfw_conf_.flags_.set(XfwConf::Opt::DNS_FILTER_OFF);
		return;
	}

	xfw_conf_.flags_.set(XfwConf::Opt::DNS_FILTER_ON);
}

/*
 * ------------------------------------------------------------------------
 *	XfwSection::EvaluationModeSection section parsing
 * ------------------------------------------------------------------------
 */
void
XfwSection::EvaluationModeSection::commit()
{
	assert(!!edit_processor_);
	auto edit_action = edit_processor_->get_result();
	if (edit_action.has_value()) {
		if (*edit_action != EditProcessor::EditType::DELETE)
			throw Except("Operation '{}' is not allowed in evaluation_mode",
				     EditProcessor::to_string(edit_action.value()));
		xfw_conf_.flags_.set(XfwConf::Opt::EVALUATION_MODE_OFF);
		return;
	}

	xfw_conf_.flags_.set(XfwConf::Opt::EVALUATION_MODE_ON);
}

/*
 * ------------------------------------------------------------------------
 *	XfwSection::TcpAuthSection section parsing
 * ------------------------------------------------------------------------
 */
void
XfwSection::TcpAuthSection::commit()
{
	assert(!!edit_processor_);
	auto edit_action = edit_processor_->get_result();
	if (edit_action.has_value()) {
		if (*edit_action != EditProcessor::EditType::DELETE)
			throw Except("Operation '{}' is not allowed with tcp_auth_filter",
				     EditProcessor::to_string(edit_action.value()));
		xfw_conf_.flags_.set(XfwConf::Opt::TCP_AUTH_FILTER_OFF);
		return;
	}

	xfw_conf_.flags_.set(XfwConf::Opt::TCP_AUTH_FILTER_ON);
}

/*
 * ------------------------------------------------------------------------
 *	XfwSection::TcpSyncookieSection section parsing
 * ------------------------------------------------------------------------
 */
bool
XfwSection::TcpSyncookieSection::process_attributes()
{
	using namespace std::literals;

	auto name = peek_until_delimeters();
	if (name == "passive_timer") {
		p_timer_ = consume_typed_assignment<uint32_t>(name);
		return true;
	}
	else if (name == "flood_timer") {
		f_timer_ = consume_typed_assignment<uint32_t>(name);
		return true;
	}

	return false;
}

void
XfwSection::TcpSyncookieSection::commit()
{
	assert(!!edit_processor_);
	auto edit_action = edit_processor_->get_result();
	if (edit_action.has_value()) {
		if (*edit_action != EditProcessor::EditType::DELETE)
			throw Except("Operation '{}' is not allowed with tcp_syncookies",
				     EditProcessor::to_string(edit_action.value()));
		xfw_conf_.flags_.set(XfwConf::Opt::TCP_SYNCOOKIE_FILTER_OFF);
		return;
	}

	if (!f_timer_.has_value() && !p_timer_.has_value()) {
		throw Except("Section must contain at least one "
			     "of 'passive_timer' or 'flood_timer'.");
	}
	xfw_conf_.syncookie_.emplace(p_timer_.value_or(1),
		f_timer_.value_or(1));
}

/*
 * ------------------------------------------------------------------------
 *	XfwSection::RatelimitSection section parsing
 * ------------------------------------------------------------------------
 */
bool
XfwSection::RatelimitSection::process_attributes()
{
	using namespace std::literals;

	auto name = peek_until_delimeters();
	if (name == "bps") {
		ratelimit_.bps_ = consume_typed_assignment<uint64_t>(name);
		return true;
	}
	else if (name == "pps") {
		ratelimit_.pps_ = consume_typed_assignment<uint64_t>(name);
		return true;
	}

	return false;
}

void
XfwSection::RatelimitSection::commit()
{
	assert(!!edit_processor_);
	auto edit_action = edit_processor_->get_result();
	if (edit_action.has_value()) {
		if (*edit_action != EditProcessor::EditType::DELETE)
			throw Except("Operation '{}' is not allowed with ratelimit",
				     EditProcessor::to_string(edit_action.value()));
		ratelimit_.flags_.set(Ratelimit::Attr::DELETE);
	}

	if (section_alias_.empty())
		throw Except("Ratelimit must have a name");
	if (!ratelimit_.bps_.has_value() && !ratelimit_.pps_.has_value())
		if (!ratelimit_.flags_.test(Ratelimit::Attr::DELETE)) {
			throw Except("Section must contain at least one "
			    	     "of 'pps' or 'bps'.");
		}

	ratelimit_.alias_ = std::move(section_alias_);
	xfw_conf_.add_rule(std::move(ratelimit_), xfw_conf_.ratelimits_);
}

/*
 * ------------------------------------------------------------------------
 *	RootSection section parsing
 * ------------------------------------------------------------------------
 */
std::shared_ptr<LineConsumer>
RootSection::consume_line()
{
	using namespace std::literals;

	skip_spaces();
	if (empty() || peek() == '#') {
		consume_all();
		return shared_from_this();
	}

	auto name = peek_until_delimeters();
	if (name == "tfw"sv) {
		if (conf_.tfw_conf_len != 0)
			throw Except("It is not allowed to have 2 tfw sections at config.");
		return std::make_shared<TfwSection>(conf_);
	}
	else if (name == "xfw"sv) {
		if (conf_.prvt->xfw_conf.has_value())
			throw Except("It is not allowed to have 2 xfw sections at config.");
		return std::make_shared<XfwSection>(conf_);
	}
	else if (name == "tl"sv) {
		if (conf_.tl_prog_txt_len != 0)
			throw Except("It is not allowed to have 2 tl sections at config.");

		return std::make_shared<TlSection>(conf_);
	}

	throw Except("Unknown section found in config: name = {}, line = {}",
				 name, line_num_);
}
/*
 * ------------------------------------------------------------------------
 *	Main config parsing
 * ------------------------------------------------------------------------
 */
TlProgConf::TlProgConf()
{
	tcl_prog_conf_init(this);
}

TlProgConf::~TlProgConf()
{
	delete [] tfw_conf;
	delete [] tl_prog_txt;

	delete prvt;
}

/**
 * A high-level parser to:
 * 1. split Tempesta FW, Templesta xFW and Templesta Language (TL) sections into
 *    separate configuration strings to pass them to per-system parsers.
 * 2. remove unnecessary spaces and comments to simplify per-system parsers
 *    and make content smaller for network transmission. This simplification
 *    produces the same output for file and command line arguments based
 *    configuration.
 * 3. Tempesta xFW configuration for the XDP module is fully parsed by the code.
 *
 * The parser has following limitations, which probably should be fixed:
 * 1. comment lines can start only at the begining of a line. So you can't use
 *    comments for the command line arguments
 * 2. we don't expect huge configuration files or their number, so we don't care
 *    too much about the parser performance, but probably, with increased
 *    complexity, it still should be reworked to remove extra copies.
 */
void
parse_config(const char *text, size_t len, TlProgConf &conf)
{
	std::string_view conf_view(text, len);
	int line_num = 0;

	auto root = std::make_shared<RootSection>(conf);
	ParserManager manager(root);

	//TODO: replace ugly saving '\n' with std::split_after from c++26
	auto lines = std::views::split(conf_view, '\n');
	for (auto it = lines.begin(); it != lines.end(); ++it) {
		line_num++;

		//TODO: replace ugly saving '\n' with std::split_after from c++26
		uint extra_room = std::next(it) == lines.end()? 0: 1;
		std::string_view lv((*it).begin(), std::ranges::distance(*it) + extra_room);

		//We have to circle here if we have a long string with lots of sections.
		while (!lv.empty()) {
			auto current_parser = manager.get_current_parser();
			std::shared_ptr<LineConsumer> new_parser;
			// Return a tail for processing with different section parser.
			// The current parser can only consume his own parts but he can
			// delegate work to his subsystems. Nullptr as return means
			// that current parser finished his work.
			std::tie(lv, new_parser) =
				current_parser->consume_line(lv, line_num);
			if (!new_parser) {
				//section has ended
				manager.pop_parser();
			}
			else if (new_parser.get() != current_parser) {
				//next section is going to start
				manager.push_parser(std::move(new_parser));
			}
		}
	}

	if (manager.get_current_parser() != root.get())
		throw Except("Config is incomplete");
	return;
}

void
dbg_print_conf(const TlProgConf* conf)
{
	if (!conf)
		return;

	tcl::dbg << "tfw_conf (" << conf->tfw_conf_len << " bytes):\n"
		 << std::string(conf->tfw_conf, conf->tfw_conf_len) << "\n\n"
		 << "tl_prog_txt (" << conf->tl_prog_txt_len << " bytes):\n"
		 << std::string(conf->tl_prog_txt, conf->tl_prog_txt_len) << "\n\n";
	if (conf->prvt->xfw_conf.has_value())
		tcl::dbg << "xfw_conf:\n" << conf->prvt->xfw_conf.value() << "\n";

	tcl::dbg << std::endl;
}

/*
 * ------------------------------------------------------------------------
 *	Public API
 * ------------------------------------------------------------------------
 */
TlProgConf*
tcl_parse_conf(const char *text, size_t len, bool is_patch)
try {
	std::unique_ptr<TlProgConf> conf = std::make_unique<TlProgConf>();
	tcl::dbg << "Config text to parse:\n" << text << std::endl;

	parse_config(text, len, *conf);
	if (conf->prvt->xfw_conf.has_value() && is_patch)
		conf->prvt->xfw_conf->flags_.set(XfwConf::Opt::XFW_CONFIG_PATCH);
	dbg_print_conf(conf.get());

	return conf.release();
}
catch (Exception &e) {
	tcl::dump_except(e);
	return nullptr;
}
catch (...) {
	tcl::dump_unknown_except();
	return nullptr;
}

TlProgConf*
tcl_parse_full_conf(const char *text, size_t len)
{
	return tcl_parse_conf(text, len, false);
}


TlProgConf *
tcl_parse_patch_conf(const char *text, size_t len)
{
	return tcl_parse_conf(text, len, true);
}

TlProgConf*
tcl_parse_tl(const char *text, size_t len)
try {
	tcl::dbg << "TL program to parse:\n" << text << std::endl;

	std::string tl_sec(text, len);
	tl_sec = std::string("tl {\n") + tl_sec + "\n}";

	std::unique_ptr<TlProgConf> conf = std::make_unique<TlProgConf>();
	parse_config(tl_sec.c_str(), tl_sec.length(), *conf);
	dbg_print_conf(conf.get());

	return conf.release();
}
catch (Exception &e) {
	tcl::dump_except(e);
	return nullptr;
}
catch (...) {
	tcl::dump_unknown_except();
	return nullptr;
}
