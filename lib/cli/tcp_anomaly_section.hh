/**
 *	API for section with name "tcp_anomaly_filter"
 *
 * SPDX-FileCopyrightText: © 2026 Tempesta Technologies, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#pragma once

#include "../bitset.hh"

#include "tcl_private.hh"
#include "section.hh"

struct TcpAnomalySection final: public Section {
public:
	TcpAnomalySection(XfwConf &conf)
		: Section("tcp_anomaly_filter", std::unique_ptr<ActionProcessor>(),
			  std::make_unique<EditProcessor>())
		, xfw_conf_(conf)
	{}

	virtual ~TcpAnomalySection() override {}

private:
	virtual bool process_attributes() override;
	virtual void commit() override;

private:
	void consume_tcp_flags();
	void save_tcp_flags_combination(TcpControlBits);

private:
	XfwConf		&xfw_conf_;
	TcpAnomalyRule	anomaly_;
};