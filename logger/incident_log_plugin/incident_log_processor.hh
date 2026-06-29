/**
 *	Tempesta Incident Log Processor
 *
 * SPDX-FileCopyrightText: © 2026 Tempesta Technologies, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * The entire architecture is defined in the BPF map file: incident_log_maps.h.
 */
#pragma once
#include <chrono>

#include <clickhouse/client.h>

#include "../../fw/logger/plugin_processor_iface.hh"
#include "../../lib/fd_guard.hh"
#include "../../lib/bpf/array_map.hh"
#include "../../lib/bpf/hash_map.hh"
#include "../../lib/bpf/map.hh"
#include "../../lib/bpf/per_cpu_counter.hh"
#include "../../xfw/incident_log_types.h"
#include "../../xfw/map_names.h"

#include "incident_log_clickhouse.hh"


class IncidentLogProcessor final: public IPluginProcessor
{
public:
	using clock = std::chrono::steady_clock;

	IncidentLogProcessor(unsigned cpu, std::unique_ptr<IClickhouse>,
		const char* table_name, size_t max_events);
	~IncidentLogProcessor() override;

public:
	virtual int has_stopped() noexcept override;
	virtual void request_stop() noexcept override;

	virtual int consume(size_t *cnt) noexcept override;
	virtual int send(bool force) noexcept override;

	virtual std::string_view name() const noexcept override;

private:
	using BpfIncidentLogMap = BpfHashMap<IncidentKey, IncidentLogStat>;

	static std::unique_ptr<BpfIncidentLogMap>
	create_incident_map(size_t cpu, bool active);

	/*
	 * We need to populate MAP_LOG_ACTIVE_FD_REF with the FDs of the inner maps.
	 * Until the outer map slots are filled, the call:
	 *	void *incident_map = bpf_map_lookup_elem(&MAP_LOG_ACTIVE_FD_REF, &cpu);
	 * will return NULL.
	 *
	 * To make it work:
	 * 1. Create an inner map for CPU.
	 * 2. Obtain the FD of each inner map.
	 * 3. Update the outer map using bpf_map_update_elem() so that the FDs
	 *    are placed into the corresponding slots.
	 */
	void populate_percpu_maps();

private:
	/*
	 * Reads the entire content of the inactive map in batch mode to
	 * reduce syscall overhead, transfers the data to the ClickHouse
	 * writer, and then clears the map to make it ready for reuse.
	 */
	void read_and_clear_inactive_map(uint64_t) noexcept;

	/*
	 * Swaps the currently active BPF map with its inactive counterpart,
	 * making the previously active map ready for data extraction.
	 */
	int swap_active_map() noexcept;

	int handle_swap_event(uint64_t) noexcept;

private:
	using BpfIncidentPerCpuNotifyInfos = BpfPerCpuCounter<IncidentPerCpuNotifyInfo>;

	static uint64_t
	get_dropped_ev_cnt(const BpfIncidentPerCpuNotifyInfos &infos) noexcept
	{
		return infos.sum(&IncidentPerCpuNotifyInfo::drop_cnt);
	}

private:
	using BpfIncidentLogActiveFdMap = BpfHashMap<uint32_t, uint32_t>;
	using BpfIncidentLogEventsMap = BpfSingleElementMap<BpfIncidentPerCpuNotifyInfos>;

	const size_t				cpu_;
	const std::chrono::milliseconds		timer_interval_ = std::chrono::seconds(1);
	const size_t				batch_size_ = 1024;

	std::unique_ptr<BpfIncidentLogMap>	active_map_;
	std::unique_ptr<BpfIncidentLogMap>	inactive_map_;

	BpfIncidentLogActiveFdMap	incident_log_active_fd_{MAP_LOG_ACTIVE_FD_STR};
	BpfIncidentLogEventsMap		incident_log_events_{MAP_LOG_EVENTS_STR};

	uint64_t			last_swap_ts_;
	clock::time_point		next_swap_;

	bool				stopped_{false};
	bool				stop_called_{false};
	IncidentLogClickhouse		writer_;
};
