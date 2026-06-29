/**
 *	Tempesta manager shutdown related routings
 *
 * SPDX-FileCopyrightText: © 2026 Tempesta Technologies, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
 #pragma once
#include <condition_variable>
#include <mutex>

#include "../lib/log.hh"

namespace {

inline std::condition_variable cv;
inline std::mutex mtx;
inline bool shutdown_requested = false;

} // end of anonymous namespace

static inline void
request_shutdown()
{
	TE_INF("Shutting down requested");
	{
		std::lock_guard<std::mutex> lock(mtx);
		shutdown_requested = true;
	}
	cv.notify_one();
}

static inline void
wait_for_shutdown()
{
	std::unique_lock<std::mutex> lock(mtx);
	cv.wait(lock, [] { return shutdown_requested; });
	TE_INF("Shutting down request received");
}
