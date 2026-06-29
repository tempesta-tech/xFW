/**
 *	LineConsumer API implementation
 *
 * SPDX-FileCopyrightText: © 2026 Tempesta Technologies, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "line_consumer.hh"

std::tuple<std::string_view, std::shared_ptr<LineConsumer>>
LineConsumer::consume_line(std::string_view lv, int line_num)
{
	line_num_ = line_num;
	line_ = lv;
	auto parser = consume_line();
	return {line_, parser};
}

void
LineConsumer::consume(size_t count)
{
	return consume(count, accumulate_enabled_);
}

void
LineConsumer::consume(size_t count, bool accumulate)
{
	assert(count <= line_.size());
	if (accumulate)
		accumulated_.append(line_.substr(0, count));

	line_.remove_prefix(count);
}

std::string_view
LineConsumer::consume_assignment(std::string_view key, std::string_view terminators)
{
	consume_prefix(key);
	skip_spaces();
	consume_expected_char('=', key);
	skip_spaces();
	return consume_until(terminators);
}

void
LineConsumer::consume_prefix(std::string_view prefix)
{
	assert(line_.starts_with(prefix) && "Prefix not found in input");
	consume(prefix.size());
}

void
LineConsumer::consume_all()
{
	consume(line_.size());
}

std::string_view
LineConsumer::consume_until(std::string_view terminators)
{
	size_t pos = line_.find_first_of(terminators);
	if (pos == std::string_view::npos)
		pos = line_.size();
	std::string_view result = line_.substr(0, pos);
	consume(pos);
	return result;
}


void
LineConsumer::consume_expected_char(char expected, std::string_view context)
{
	if (line_.empty()) {
		throw Except("Expected '{}' after '{}', but got end of "
			     "input",  expected, context);
	}

	char actual = peek();
	if (actual != expected) {
		throw Except("Expected '{}' after '{}', but got '{}'",
			     expected, context, actual);
	}

	consume(1);
}

char
LineConsumer::peek() const
{
	return line_.empty() ? '\0' : line_.front();
}

std::string_view
LineConsumer::peek_until(std::string_view terminators)
{
	size_t pos = line_.find_first_of(terminators);
	if (pos == std::string_view::npos)
		pos = line_.size();
	return line_.substr(0, pos);
}


void
LineConsumer::skip_spaces()
{
	auto it = std::find_if_not(line_.begin(), line_.end(), [](char c) {
		return std::isspace(static_cast<unsigned char>(c));
	});
	
	consume(std::distance(line_.begin(), it), accumulate_spaces_);
}