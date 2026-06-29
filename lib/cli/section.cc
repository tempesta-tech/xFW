/**
 *	Section API implementation
 *
 * SPDX-FileCopyrightText: © 2026 Tempesta Technologies, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include <utility>

#include "section.hh"

/*
 * Except is defined as a template class and user defined deduction guide is
 * required to instantiate it using template argeuments pack followed by a
 * function argument with default value. Use a simple C macro to avoid all the
 * templates headache just for one method forwarding arguments to Except.
 */
#define ERR(...)	err(std::source_location::current(), __VA_ARGS__)

std::string
Section::get_path() const
{
	if (section_alias_.empty())
		return name_;
	return name_ + "=" + section_alias_;
}

std::shared_ptr<LineConsumer>
Section::consume_line()
try {
	using namespace std::literals;

	assert(state_ != State::End);
	skip_spaces();
	if (empty())
		return shared_from_this();

	if (peek() == '#') {
		process_comment();
		return shared_from_this();
	}

	switch(state_) {
	case State::Start: {
		process_name();
		if (peek() == '/' && edit_processor_)
			state_ = State::ProcessEditAction;
		else
			state_ = State::ReadingAttributes;
		return shared_from_this();
	}
	case State::ProcessEditAction: {
		assert(!!edit_processor_);
		if (edit_processor_->process(this))
			return shared_from_this();
		state_ = State::ReadingAttributes;
		return shared_from_this();
	}
	case State::ReadingAttributes: {
		char s = peek();
		if (s == ';') {
			state_ = State::End;
			consume(1);
			commit();
			return nullptr;
		}
		else if (s == '{') {
			state_ = State::ProcessingBody;
			consume(1);
			return shared_from_this();
		}
		else if (s == ':' && action_processor_) {
			state_ = State::ProcessingAction;
			consume(1);
			return shared_from_this();
		}
		// It has to be called in the beginning of case block, but we don't
		// have AttributesProcessor yet, so we can't call process_attributes
		// in every class: some of them don't have implementation for this function.
		if (process_attributes())
			return shared_from_this();
		throw Except("Unknown symbols: {}", peek_until(" \t\r\n"));
	}
	case State::ProcessingAction: {
		assert(!!action_processor_);
		if (action_processor_->process(this))
			return shared_from_this();
		if (peek() == ';') {
			state_ = State::End;
			consume(1);
			commit();
			return nullptr;
		}
		else if (peek() == '{') {
			state_ = State::ProcessingBody;
			consume(1);
			return shared_from_this();
		}
		throw Except("Unknown symbols: {}", peek_until(" \t\r\n"));
	}
	case State::ProcessingBody: {
		auto [succeeded, parser] = process_body();
		if (succeeded)
			return parser;
		if (peek() == '}') {
			state_ = State::End;
			consume(1);
			commit();
			return nullptr;
		}
		throw Except("Unknown symbols: {}", peek_until(" \t\r\n"));
	}
	default:
		assert(false && "Logic error: this path has to be unreachable");
		std::unreachable();
	}
}
catch (std::exception &e) {
	ERR("{}", e.what());
}


void
Section::process_name()
{
	assert(state_ == State::Start);
	consume_prefix(name_);
	if (peek() == '=') {
		consume_expected_char('=', name_);
		section_alias_ = consume_until(parsing_helpers::delimeters + "/");
	}
}

void
Section::process_comment()
{
	auto old = std::exchange(accumulate_enabled_, accumulate_comments_);
	consume_all();
	accumulate_enabled_ = old;
}
