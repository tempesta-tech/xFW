/**
 *	Section API
 *
 * SPDX-FileCopyrightText: © 2026 Tempesta Technologies, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#pragma once
#include <cassert>
#include <memory>
#include <string>

#include "../error.hh"
#include "line_consumer.hh"
#include "action_processor.hh"
#include "edit_processor.hh"

/**
 * The base of a section (e.g. `xfw` or `tl`).
 */
class Section: public LineConsumer {
public:
	Section(const char *name,
		std::unique_ptr<ActionProcessor> action_processor = {},
		std::unique_ptr<EditProcessor> edit_processor = {})
		: LineConsumer(), name_(name)
		, action_processor_(std::move(action_processor))
		, edit_processor_(std::move(edit_processor))
	{}
	virtual ~Section() {}

	virtual std::shared_ptr<LineConsumer> consume_line() override;

	/**
	 * Path from the root to the current section. Basically you need to overload it.
	 */
	virtual std::string get_path() const override;

protected:
	/**
	 * Parse all the attributes of section
	*/
	[[noreturn]]
	virtual bool process_attributes()
	{
		assert(true && "process_attributes was called: implement "
				"it for your class or fix workflow.");
		throw Except("process_attributes was called: implement it for "
			     "your class or fix workflow.");
	}

	/**
	 * Parse all the body of section
	*/
	[[noreturn]]
	virtual std::pair<bool, std::shared_ptr<LineConsumer>> process_body()
	{
		assert(true && "process_body was called: implement "
				"it for your class or fix workflow.");
		throw Except("process_body was called: implement it for "
			     "your class or fix workflow.");
	}

protected:
	/**
	 * Move all data out of the class
	 */
	virtual void commit() = 0;

protected:
	void process_name();
	void process_comment();

protected:
	enum class State {
		Start,
		ProcessEditAction,
		ReadingAttributes,
		ProcessingAction,
		ProcessingBody,
		End
	};
	State			state_ = State::Start;
	const std::string	name_;
	bool			accumulate_comments_ = false;
	std::string		section_alias_;

	//We are moving to a chain-based processing model. See #208
	std::unique_ptr<ActionProcessor>	action_processor_;
	std::unique_ptr<EditProcessor>		edit_processor_;
};
