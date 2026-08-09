/**
 *	Tempesta xFW eBPF filter
 *
 * SPDX-FileCopyrightText: © 2026 Tempesta Technologies, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "../../lib/log.hh"
#include "../../lib/error.hh"
#include "../../bpf_uapi/drop_stats.h"

#include "stats.hh"

BpfStats::BpfStats()
{
	TE_INF("Global stats bpf map successfully opened");
}

void
format_stat(std::stringstream &ss, const XfwStatInfo &field,
	    const XfwPacketStats &packet_stats)
{
	ss << "# HELP " << field.name << "_packets Total " << field.desc << " packets.\n";
	ss << "# TYPE " << field.name << "_packets counter\n";
	ss << field.name << "_packets " << packet_stats.packets << "\n";

	ss << "# HELP " << field.name << "_bytes Total " << field.desc << " bytes.\n";
	ss << "# TYPE " << field.name << "_bytes counter\n";
	ss << field.name << "_bytes " << packet_stats.bytes << "\n";
}

std::string
BpfStats::load_global_stats_prometheus()
{
	std::stringstream ss;
	XfwPerCpuStats stats = load_global_stats();
	
	for (size_t i = 0; i < XFW_PASS_STAT_MAX; ++i)
		format_stat(ss, xfw_pass_stats[i], stats.pass[i]);

	for (size_t i = 0; i < XFW_TRAFFIC_STAT_MAX; ++i)
		format_stat(ss, xfw_traffic_stats[i], stats.traffic[i]);

	for (size_t i = 0; i < XFW_TX_STAT_MAX; ++i)
		format_stat(ss, xfw_tx_stats[i], stats.transmitted[i]);

	format_stat(ss, xfw_drop_stats[XFW_SYNCOOKIE_FAILED],
		    stats.syncookie_failed);

	return ss.str();
}

XfwPerCpuStats
BpfStats::load_global_stats()
{
	BpfPerCpuStats stats;
	int res = global_stats_map_.get(stats);
	if (res != 0)
		throw Except("Global stats arenot found");
	return stats.sum();
}
