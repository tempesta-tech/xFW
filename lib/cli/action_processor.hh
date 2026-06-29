/**
 *	Action processor API for section's parsing
 *
 * SPDX-FileCopyrightText: © 2026 Tempesta Technologies, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#pragma once

#include "line_consumer.hh"
#include "tcl_private.hh"

/**
 * ActionProcessor is responsible for recognizing and classifying action commands
 * from input strings. Instead of comparing raw string commands ("allow", "block",
 * "ratelimit=<value>") everywhere in code, it maps them to strongly-typed values
 * (Action enum).
 */
class ActionProcessor
{
public:
	struct Action
	{
		std::string	ratelimit_;
		bool		allow_;
	};

	ActionProcessor() = default;

	/**
	 * Attempts to recognize and consume an action command from the provided
	 * LineConsumer. Returns rue if a valid command was recognized and stored,
	 * false otherwise.
	 */
	bool process(LineConsumer* consumer)
	{
		using namespace std::literals;

		auto name = consumer->peek_until_delimeters();
		if (name == "allow"sv) {
			set_action(Action{{}, true});
			consumer->consume(name.size());
			return true;
		}
		else if (name == "block"sv) {
			set_action(Action{{}, false});
			consumer->consume(name.size());
			return true;
		}
		else if (name == "ratelimit"sv) {
			auto rl = consumer->consume_assignment(name);
			set_action(Action{std::string(rl), true});
			return true;
		}

		return false;
	}

	/**
	 * Returns the result of processing as an optional Action.
	 * If no valid command was found, the optional is empty.
	 *
	 * Attention:
	 * This is a destructive call; the object must not be used afterwards.
	 */
	std::optional<Action> get_result()
	{
		return std::move(action_);
	}

private:
	void set_action(Action && action)
	{
		if (action_.has_value())
			throw Except("Two action in a rule aren't allowed.");

		action_.emplace(std::move(action));
	}

protected:
	std::optional<Action> action_;
};
