/**
 *	Tempesta Manager stats logics
 *
 * SPDX-FileCopyrightText: © 2026 Tempesta Technologies, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#pragma once

#include "../../lib/bpf/array_map.hh"
#include "../../lib/bpf/per_cpu_counter.hh"
#include "../../bpf_uapi/stats.h"
#include "../../bpf_uapi/map_names.h"

/**
 * Incapsulates logic related to BPF statistics.
 */
class BpfStats {
public:
	BpfStats();

	BpfStats(const BpfStats &) = delete;
	BpfStats(BpfStats &&) = delete;

	/**
	 * load_global_stats() and then put it in Prometheus format.
	 */
	std::string load_global_stats_prometheus();

	XfwPerCpuStats load_global_stats();

private:
	using BpfPerCpuStats = BpfPerCpuCounter<XfwPerCpuStats>;

	BpfSingleElementMap<BpfPerCpuStats> global_stats_map_{MAP_GLBL_STAT_STR};
};
