/**
 *	Tempesta Xfw update error
 *
 * SPDX-FileCopyrightText: © 2026 Tempesta Technologies, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#pragma once

#include "../lib/error.hh"

/**
 * Currently, UpdateError is derived from std::runtime_error. Ideally, however,
 * we would like it to be derived from Except and constructed from a concrete
 * Error (for example, SrcIpNotFound).
 *
 * At the moment, we do not have an Error implementation (planned to live in
 * fw/libtus/error.hh), and we also cannot configure different logging levels
 * in Except (also planned for fw/libtus/error.hh).
 *
 * Once these two pieces are implemented, we will be able to remove the verify
 * function entirely and derive UpdateError directly from Except.
 */
class UpdateError : public std::runtime_error
{
public:
	template <typename... Args>
	UpdateError(fmt::format_string<Args...> fmt, Args&&... args)
		: std::runtime_error(fmt::format(fmt, std::forward<Args>(args)...))
	{}
};

/**
 * Currently, we use `UpdateError` checks when processing flatbuffers to
 * prevent possible fuzzing attacks or client errors. We would like to replace
 * these with a more detailed `Error` that still traces the problematic lines
 * on the server where the exception occurred, but only forwards the core
 * error information externally, without including debug details.
 */
template<typename... Args>
inline void verify(bool cond, const char* msg, Args&&... args)
{
	if (!cond)
		throw UpdateError(fmt::runtime(msg), std::forward<Args>(args)...);
}
