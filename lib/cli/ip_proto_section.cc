/**
 *	Implementation for section with name "ip_proto"
 *
 * SPDX-FileCopyrightText: © 2026 Tempesta Technologies, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "ip_proto_section.hh"

IpProtoSection::IpProtoSection(XfwConf &conf)
	: Section("ip_proto", std::unique_ptr<ActionProcessor>()
	, std::make_unique<EditProcessor>()), conf_(conf)
{
}

void
IpProtoSection::IpProtoSection::commit()
{
	assert(!!edit_processor_);
	auto edit_action = edit_processor_->get_result();
	if (edit_action.has_value()) {
		if (*edit_action != EditProcessor::EditType::DELETE)
			throw Except("Operation '{}' is not allowed in {}",
				     EditProcessor::to_string(edit_action.value()),
				     name_);
		conf_.flags_.set(XfwConf::Opt::IP_PROTO_FILTER_OFF);
		return;
	}

	conf_.ip_proto_ = std::move(ip_proto_);
}

std::string
IpProtoSection::IpProtoSection::get_path() const
{
	return "xfw/ip_proto";
}

std::pair<bool, std::shared_ptr<LineConsumer>>
IpProtoSection::IpProtoSection::process_body()
{
	using namespace std::literals;

	auto nv = consume_until_delimeters();
	if (nv.empty())
		return {false, nullptr};

	const auto num = parsing_helpers::parse_as<uint32_t>(nv);
	if (num > XFW_SUPPORTED_PROTOCOL_MAX)
		throw Except("Unknown protocol {} in ip_proto section", num);
	const auto e = static_cast<XfwSupportedProtocols>(num);
	if (!ip_proto_)
		ip_proto_.emplace();

	ip_proto_->protocols_.set(e);

	skip_spaces();
	if (peek() == ',')
		consume(1);
		
	return {true, shared_from_this()};
}
