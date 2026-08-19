/**
 *	API for section with name "tcp_syn_drop_filter"
 *
 * SPDX-FileCopyrightText: © 2026 Tempesta Technologies, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#pragma once

#include "tcl_private.hh"
#include "section.hh"

struct TcpSynDropSection final: public Section {
public:
	TcpSynDropSection(XfwConf &conf)
		: Section("tcp_syn_drop", std::unique_ptr<ActionProcessor>(),
			  std::make_unique<EditProcessor>())
		, xfw_conf_(conf)
	{}

	virtual ~TcpSynDropSection() override {}

private:
	virtual bool process_attributes() override;
	virtual void commit() override;

private:
	XfwConf				&xfw_conf_;
	std::optional<uint64_t>		hash_salt_;
	std::optional<uint64_t>		time_min_ms_;
	std::optional<uint64_t>		max_delay_ms_;
	std::optional<uint64_t>		block_timeout_ms_;
	std::optional<uint32_t>		retry_count_;
};

