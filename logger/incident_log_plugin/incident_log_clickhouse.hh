/**
 *	Tempesta Incident Log clickhouse
 *
 * SPDX-FileCopyrightText: © 2026 Tempesta Technologies, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * The entire architecture is defined in the BPF map file: incident_log_maps.h.
 */
#pragma once

#include <string_view>

#include "../../bpf_uapi/incident_log_types.h"
#include "../../fw/logger/clickhouse/clickhouse_decorator.hh"

class IncidentLogClickhouse final: public ClickHouseDecorator
{
public:
	IncidentLogClickhouse(std::unique_ptr<IClickhouse> client,
		std::string_view table_name, size_t max_events);

public:
	void
	append_event(const IncidentKey &key, const IncidentLogStat &value,
		     uint64_t drop_cnt);
};
