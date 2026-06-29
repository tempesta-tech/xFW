/**
 *	LineConsumer API
 *
 * SPDX-FileCopyrightText: © 2026 Tempesta Technologies, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#pragma once
#include <charconv>
#include <concepts>
#include <fmt/core.h>
#include <memory>
#include <source_location>
#include <string_view>
#include <tuple>

#include "../error.hh"

namespace parsing_helpers {

const std::string spaces = " \t";
const std::string delimeters = "=,;{} \t\r\n";

template<typename Type>
Type parse_as(std::string_view sv);

template<std::unsigned_integral Type>
inline Type parse_as(std::string_view lv)
{
	Type num{};
	auto [ptr, ec] = std::from_chars(lv.data(), lv.data() + lv.size(), num);
	if (ec != std::errc())
		throw Except("Invalid int '{}': {}", lv, std::make_error_code(ec).message());
	if (ptr != lv.data() + lv.size())
		throw Except("Invalid int '{}': trailing characters", lv);

	return num;
}

} // namespace parsing_helpers

/**
 * This is the base for every section. In the future, this class is intended to
 * provide an API for working with the input line, while making the line itself
 * a private member, inaccessible to derived classes. It will help to make code
 *  more strict and easy..
 */
class LineConsumer: public std::enable_shared_from_this<LineConsumer>
{
public:
	LineConsumer() = default;
	virtual ~LineConsumer() = default;

	std::tuple<std::string_view, std::shared_ptr<LineConsumer>>
	consume_line(std::string_view lv, int line_num);

public:
	/**
	 * Get line as input and return unprocessed tail and parser to continue tail
	 * processing.
	 */
	virtual std::shared_ptr<LineConsumer> consume_line() = 0;

	/**
	 * Get path to section, to trace info about error more accurate.
	 * Could be more helpful then line_num, for example, when
	 * the configuration is written in one line.
	 */
	virtual std::string get_path() const = 0;

public:
	/**
	 * Consume the next character if it matches expected, otherwise throw.
	 * Return the rest of the line.
	 * If `accumulate_` is enabled, the consumed portion is also appended
	 * to the internal buffer `accumulated_` for later retrieval or inspection.
	 */
	void consume_expected_char(char expected, std::string_view context);

	/**
	 * Consume the next `count` characters from the input string.
	 *
	 * If `accumulate_` is enabled, the consumed portion is also appended
	 * to the internal buffer `accumulated_` for later retrieval or inspection.
	 */
	void consume(size_t count);

	/**
	 * Parses and returns the value assigned to the given key in the form
	 * `key = value`, consuming the key, `=`, and spaces inside assignment.
	 *
	 * Stops consuming at the first character found in `terminators`,
	 * which is not consumed. Throws if the key is not found or if '=' is missing.
	 *
	 * Example: for input "rate = 1000 ;" and terminators=";{", returns "1000".
	 *
	 * If `accumulate_` is enabled, the consumed portion is also appended
	 * to the internal buffer `accumulated_` for later retrieval or inspection.
	 */
	std::string_view
	consume_assignment(std::string_view key,
		std::string_view terminators = parsing_helpers::delimeters);

	/**
	 * Parses an assignment in the form `key = value`, returning the value
	 * converted to type Type. Removes the parsed part from `lv`.
	 *
	 * Throws if key doesn't match, '=' is missing, or value can't be parsed.
	 *
	 * If `accumulate_` is enabled, the consumed portion is also appended
	 * to the internal buffer `accumulated_` for later retrieval or inspection.
	 */
	template <typename Type>
	Type
	consume_typed_assignment(std::string_view key,
		std::string_view terminators = parsing_helpers::delimeters)
	{
		std::string_view value = consume_assignment(key, terminators);
		return parsing_helpers::parse_as<Type>(value);
	}

	/**
	 * Requires that the input starts with the given prefix.
	 * Removes prefix from line. Asserts if prefix is not found.
	 *
	 * If `accumulate_` is enabled, the consumed portion is also appended
	 * to the internal buffer `accumulated_` for later retrieval or inspection.
	 */
	void consume_prefix(std::string_view prefix);

	/**
	 * Consumes all input.
	 *
	 * If `accumulate_` is enabled, the consumed portion is also appended
	 * to the internal buffer `accumulated_` for later retrieval or inspection.
	 */
	void consume_all();

	/**
	 * Consumes input up to (but not including) the first character from
	 * `terminators`.
	 *
	 * If `accumulate_` is enabled, the consumed portion is also appended
	 * to the internal buffer `accumulated_` for later retrieval or inspection.
	 */
	std::string_view
	consume_until(std::string_view terminators);

	std::string_view
	consume_until_delimeters()
	{
		return consume_until(parsing_helpers::delimeters);
	}

	/**
	 * Check if there is data for consume.
	 */
	bool empty() const
	{
		return line_.empty();
	}

	/**
	 * Peek at the next character without consuming it
	 */
	char peek() const;

	/**
	 * Peek input up to (but not including) the first character from
	 * `terminators`.
	 */
	std::string_view
	peek_until(std::string_view terminators);

	std::string_view
	peek_until_delimeters()
	{
		return peek_until(parsing_helpers::delimeters);
	}

	/**
	 * Skip all leading whitespace. Return the rest of the line.
	 */
	void skip_spaces();

private:
	/**
	 * Same as consume(count), but allows overriding accumulation behavior.
	 */
	void consume(size_t count, bool accumulate);

protected:
	template <typename... Args>
	[[noreturn]] void
	err(const std::source_location &loc, fmt::format_string<Args...> fmt,
	    Args&&... args) const
	{
		auto msg = fmt::format("Parser error at node {}, line {}: {}",
				       get_path(), line_num_,
				       fmt::format(fmt, std::forward<Args>(args)...));
		std::string loc_msg = fmt::format("{} (at {}:{} in {})",
						  msg, loc.file_name(), loc.line(),
						  loc.function_name());

		throw Exception(loc_msg);
	}

	int			line_num_ = 0;
	std::string_view	line_;
	std::string		accumulated_;
	bool			accumulate_enabled_ = false;
	bool			accumulate_spaces_ = false;
};
