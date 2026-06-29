/**
 *	Tempesta client library logging
 *
 * Varios helpers, too small to form their own source files.
 *
 * SPDX-FileCopyrightText: © 2026 Tempesta Technologies, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#pragma once

#include <iostream>

namespace tcl {

class DbgStream {
public:
	DbgStream(const DbgStream &) =delete;
	DbgStream &operator=(const DbgStream &) =delete;

	DbgStream()
		: debug_(false)
	{}

	void enable() { debug_ = true; }
	void disable() { debug_ = false; }

	template<typename T>
	const DbgStream &
	operator<<(const T &v) const noexcept
	{
		if (debug_)
			std::cout << v;
		return *this;
	}

	const DbgStream &
	operator<<(std::ostream &(*manip)(std::ostream &)) const noexcept
	{
		if (debug_)
			manip(std::cout);
		return *this;
	}

private:
	bool debug_;
};

extern DbgStream dbg;

} // tcl
