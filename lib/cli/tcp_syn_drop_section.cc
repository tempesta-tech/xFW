/**
 *	Implementation for section with name "tcp_syn_drop_filter"
 *
 * SPDX-FileCopyrightText: © 2026 Tempesta Technologies, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "tcp_syn_drop_section.hh"

#include "config_defaults.hh"

bool
TcpSynDropSection::process_attributes()
{
	using namespace std::literals;

	auto name = peek_until_delimeters();
	if (name == "hash_salt") {
		hash_salt_ = consume_typed_assignment<uint64_t>(name);
		return true;
	}
	else if (name == "time_min") {
		time_min_ms_ = consume_typed_assignment<uint64_t>(name);
		return true;
	}
	else if (name == "max_delay") {
		max_delay_ms_ = consume_typed_assignment<uint64_t>(name);
		return true;
	}
	else if (name == "retry_count") {
		retry_count_ = consume_typed_assignment<uint32_t>(name);
		return true;
	}
	else if (name == "block_timeout") {
		block_timeout_ms_ = consume_typed_assignment<uint64_t>(name);
		return true;
	}

	return false;
}

void
TcpSynDropSection::commit()
{
	assert(!!edit_processor_);
	auto edit_action = edit_processor_->get_result();
	if (edit_action.has_value()) {
		if (*edit_action != EditProcessor::EditType::DELETE)
			throw Except("Operation '{}' is not allowed with tcp_syn_drop",
				     EditProcessor::to_string(edit_action.value()));
		xfw_conf_.flags_.set(XfwConf::Opt::TCP_SYN_DROP_FILTER_OFF);
		return;
	}

	/*
	 * The salt cannot safely have a generic default because it is part of
	 * the protection against predictable hash collisions.
	 */
	if (!hash_salt_.has_value()) {
		throw Except("tcp_syn_drop requires the 'hash_salt' "
			     "parameter.");
	}

	/*
	 * The design does not specify a default retry count, so it must be
	 * explicitly configured.
	 */
	if (!retry_count_.has_value()) {
		throw Except("tcp_syn_drop requires the 'retry_count' "
			     "parameter.");
	}

	if (!retry_count_.value()) {
		throw Except("tcp_syn_drop: 'retry_count' must be greater "
			     "than zero.");
	}

	const uint64_t time_min_ms =
		time_min_ms_.value_or(TCP_SYN_DROP_DEFAULT_MIN_DELAY_MS);

	const uint64_t max_delay_ms =
		max_delay_ms_.value_or(TCP_SYN_DROP_DEFAULT_MAX_DELAY_MS);

	const uint64_t block_timeout_ms =
		block_timeout_ms_.value_or(TCP_SYN_DROP_DEFAULT_BLOCK_TIMEOUT_MS);

	if (!max_delay_ms) {
		throw Except("tcp_syn_drop: 'max_delay' must be greater "
			     "than zero.");
	}

	/*
	 * The valid retransmission window is defined as:
	 *
	 *     stored_time + time_min <= now <= stored_time + max_delay
	 *
	 * Therefore, time_min must not exceed max_delay, otherwise no
	 * retransmission could ever satisfy the condition.
	 */
	if (time_min_ms > max_delay_ms) {
		throw Except("tcp_syn_drop: 'time_min' ({}) must not exceed "
			     "'max_delay' ({}).", time_min_ms, max_delay_ms);
	}

	xfw_conf_.tcp_syn_drop_.emplace(hash_salt_.value(),
					time_min_ms, max_delay_ms,
					block_timeout_ms,
					retry_count_.value());
}
