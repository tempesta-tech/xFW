/**
 *	Implementation for section with name "tcp_anomaly_filter"
 *
 * SPDX-FileCopyrightText: © 2026 Tempesta Technologies, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "tcp_anomaly_section.hh"

TcpControlBits
tcp_flag_to_bit(std::string_view tcp_flag)
{
	using namespace std::literals;

	if (tcp_flag == "0"sv)
		return TcpControlBits::XFW_BIT_NONE;
	if (tcp_flag == "ACK"sv)
		return TcpControlBits::XFW_BIT_ACK;
	if (tcp_flag == "CWR"sv)
		return TcpControlBits::XFW_BIT_CWR;
	if (tcp_flag == "ECE"sv)
		return TcpControlBits::XFW_BIT_ECE;
	if (tcp_flag == "FIN"sv)
		return TcpControlBits::XFW_BIT_FIN;
	if (tcp_flag == "PSH"sv)
		return TcpControlBits::XFW_BIT_PSH;
	if (tcp_flag == "RST"sv)
		return TcpControlBits::XFW_BIT_RST;
	if (tcp_flag == "SYN"sv)
		return TcpControlBits::XFW_BIT_SYN;
	if (tcp_flag == "URG"sv)
		return TcpControlBits::XFW_BIT_URG;

	throw Except("Unexpected 'bad_flag' value '{}'", tcp_flag);
}

inline TcpControlBits
operator|(TcpControlBits a, TcpControlBits b)
{
	return static_cast<TcpControlBits>(static_cast<int>(a) |
					   static_cast<int>(b));
}

bool
TcpAnomalySection::process_attributes()
{
	using namespace std::literals;

	auto name = peek_until(parsing_helpers::delimeters + "()");
	if (name == "syn_without_opt") {
		anomaly_.features_.set(TcpAnomalyFeature::XFW_SYN_WIHOUT_OPTIONS);
		consume(name.size());
		return true;
	}
	else if (name == "syn_with_payload") {
		anomaly_.features_.set(TcpAnomalyFeature::XFW_SYN_WITH_PAYLOAD);
		consume(name.size());
		return true;
	}
	else if (name == "syn_with_seqno") {
		anomaly_.features_.set(TcpAnomalyFeature::XFW_SYN_WITH_SEQ_NO);
		anomaly_.seqno_value_ = consume_typed_assignment<uint32_t>(name);
		return true;
	}
	else if (name == "bad_flags") {
		anomaly_.features_.set(TcpAnomalyFeature::XFW_BAD_FLAGS);
		consume(name.size());
		skip_spaces();
		if (peek() == '(')
			consume_tcp_flags();
		return true;
	}

	return false;
}

void
TcpAnomalySection::commit()
{
	assert(!!edit_processor_);
	auto edit_action = edit_processor_->get_result();
	if (edit_action.has_value()) {
		if (*edit_action != EditProcessor::EditType::DELETE)
			throw Except("Operation '{}' is not allowed in {}",
				     EditProcessor::to_string(edit_action.value()),
				     name_);
		xfw_conf_.flags_.set(XfwConf::Opt::TCP_ANOMALY_FILTER_OFF);
		return;
	}

	xfw_conf_.tcp_anomaly_.emplace(std::move(anomaly_));
}

/**
 * For now we don't allow to split bad_flags for several lines
 */
void
TcpAnomalySection::consume_tcp_flags()
{
	std::optional<TcpControlBits> tcp_combination;
	consume(1); // eat '('
	while (!empty()) {
		skip_spaces();
		if (peek() == ')') {
			if (tcp_combination.has_value())
				save_tcp_flags_combination(tcp_combination.value());
			consume(1); // eat ')'
			return;
		}

		const auto tcp_flag = consume_until(parsing_helpers::spaces + "+,)");
		const auto tcp_flag_e = tcp_flag_to_bit(tcp_flag);
		tcp_combination = tcp_flag_e | 
				  tcp_combination.value_or(TcpControlBits::XFW_BIT_NONE);

		skip_spaces();
		if (peek() == '+') {
			consume(1); // eat '+'
			continue;
		}

		if (peek() == ',') {
			if (!tcp_combination.has_value()) {
				throw Except("Illegal ',' in bad_flags: should be "
					     "only after tcp flag's combination");
			}

			save_tcp_flags_combination(tcp_combination.value());
			tcp_combination.reset();
			consume(1); // eat ','
			continue;
		}
	}

	throw Except("bad_flags: expected ')' after the tcp flag combinations");
}

void
TcpAnomalySection::save_tcp_flags_combination(TcpControlBits c)
{
	auto& flags = anomaly_.bad_tcp_flags_;
	if (!flags.has_value())
		flags.emplace();
	flags->set(c);
}
