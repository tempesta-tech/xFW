/**
 *	Edit processor API for section's parsing
 *
 * SPDX-FileCopyrightText: © 2026 Tempesta Technologies, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#pragma once

#include "line_consumer.hh"
#include "tcl_private.hh"

/**
 * EditProcessor is responsible for recognizing and classifying edit commands from
 * input strings. Instead of comparing raw string commands ("/add", "/del", "/replace")
 * everywhere in code, it maps them to strongly-typed values (EditType enum).
 */
class EditProcessor
{
public:
	enum class EditType {
		ADD,
		DELETE,
		REPLACE,
	};

	EditProcessor() = default;

public:
	/**
	 * Converts an EditType value into its string representation.
	 */
	static std::string_view
	to_string(EditType t) noexcept
	{
		using namespace std::literals;
		switch (t) {
		case EditProcessor::EditType::ADD:
			return "/add"sv;
		case EditProcessor::EditType::DELETE:
			return "/del"sv;
		case EditProcessor::EditType::REPLACE:
			return "/replace"sv;
		}
		assert(false && "Undefined edit type used");
		std::unreachable();
	}

	/**
	 * Attempts to recognize and consume an edit command from the provided
	 * LineConsumer. Returns rue if a valid command was recognized and stored,
	 * false otherwise.
	 */
	bool process(LineConsumer* consumer)
	{
		using namespace std::literals;

		auto name = consumer->peek_until_delimeters();
		if (name == "/add"sv) {
			set_edit_type(EditType::ADD);
			consumer->consume(name.size());
			return true;
		}
		else if (name == "/del"sv) {
			set_edit_type(EditType::DELETE);
			consumer->consume(name.size());
			return true;
		}
		else if (name == "/replace"sv) {
			set_edit_type(EditType::REPLACE);
			consumer->consume(name.size());
			return true;
		}

		return false;
	}

	/**
	 * Returns the result of processing as an optional EditType.
	 * If no valid command was found, the optional is empty.
	 *
	 * Attention:
	 * This is a destructive call; the object must not be used afterwards.
	 */
	std::optional<EditProcessor::EditType> get_result()
	{
		return std::move(edit_type_);
	}

private:
	void set_edit_type(EditType  t)
	{
		if (edit_type_.has_value())
			throw Except("Two edit types in a rule aren't allowed.");

		edit_type_ = t;
	}

protected:
	std::optional<EditProcessor::EditType> edit_type_;
};
