/**
 *	Tempesta Escudo daemong logging
 *
 * SPDX-FileCopyrightText: © 2026 Tempesta Technologies, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#pragma once
#include <string_view>

#include "error.hh"

#include <spdlog/spdlog.h>
#include "spdlog/sinks/basic_file_sink.h"

// Logging definitions in case we migrate to another logger.
#define TE_DBG(...)		spdlog::debug(__VA_ARGS__)
#define TE_INF(...)		spdlog::info(__VA_ARGS__)
#define TE_WRN(...)		spdlog::warn(__VA_ARGS__)
#define TE_ERR(...)		spdlog::error(__VA_ARGS__)

namespace te {

inline void
log_init(const std::string log_path)
try {
	auto logger = spdlog::basic_logger_mt("basic_logger", log_path);
	logger->set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%^%l%$] (%s:%#) %v");
	
#ifdef NDEBUG
	logger->set_level(spdlog::level::info);
#else
	logger->set_level(spdlog::level::debug);
#endif

	//We have to flush at least on error. But if there is no performance
	//issue, than we can change it to every message with spdlog::level::trace.
	logger->flush_on(spdlog::level::trace);
	spdlog::set_default_logger(logger);

	//global setting for all registered loggers
	spdlog::flush_every(std::chrono::seconds(1));
}
catch (const spdlog::spdlog_ex &ex) {
	throw Except("Log init failed: ", ex.what());
}

inline void
log_deinit()
{
	spdlog::shutdown();
}

} // end of Tempesta Escudo namespace
