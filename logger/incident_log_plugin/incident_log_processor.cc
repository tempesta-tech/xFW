/**
 *	Tempesta Incident Log Processor
 *
 * SPDX-FileCopyrightText: © 2026 Tempesta Technologies, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <format>
#include <span>
#include <spdlog/spdlog.h>

#include "../../fw/libtus/error.hh"

#include "incident_log_processor.hh"

using namespace std::chrono;
using namespace std::chrono_literals;
using namespace std::literals;

IncidentLogProcessor::IncidentLogProcessor(unsigned cpu,
	std::unique_ptr<IClickhouse> client, const char* table_name, size_t max_events)
	: cpu_(cpu)
	, active_map_(create_incident_map(cpu, true))
	, inactive_map_(create_incident_map(cpu, false))
	, next_swap_(clock::now() + timer_interval_)
	, writer_(std::move(client), table_name, max_events)
{
	if (cpu > MAX_INCIDENT_CPU)
		throw Except("[CPU {}] Can't start IncidentLogProcessor: "
			     "too big number ", cpu);

	populate_percpu_maps();

	spdlog::info("[CPU {}] IncidentLogProcessor started. Timer "
		     "interval: {}ms", cpu, timer_interval_.count());
}

IncidentLogProcessor::~IncidentLogProcessor()
{
	BpfIncidentPerCpuNotifyInfos events;
	if (incident_log_events_.get(events) < 0)
		return;

	int err = swap_active_map();
	if (!err)
		read_and_clear_inactive_map(get_dropped_ev_cnt(events));

	spdlog::info("[CPU {}] IncidentLogProcessor stopped.", cpu_);
}

int
IncidentLogProcessor::has_stopped() noexcept
{
	return stopped_ ? 1 : 0;
}

void
IncidentLogProcessor::request_stop() noexcept
{
	stop_called_ = true;
}

int
IncidentLogProcessor::consume(size_t *cnt) noexcept
{
	*cnt = 0;

	if (stopped_) [[unlikely]]
		return 0;

	BpfIncidentPerCpuNotifyInfos events;
	if (incident_log_events_.get(events) < 0 || cpu_ >= events.size()) {
		/* 
		 * The error codes come from the libtus library. We plan to introduce
		 * lightweight error types that won't require `static_cast<int>`,
		 * while still allowing detailed information to be exported for
		 * logging. For example, we will have an error like BPF_MAP_CORRUPTED
		 * to represent this condition.
		 */
		return -static_cast<int>(Err::DB_CLT_TRANSIENT);
	}

	if (stop_called_) [[unlikely]] {
		/*
		 * It would be good to cleanup incident_log_active_fd_. But our
		 * bpf version doesn't support this.
		 */
		spdlog::debug("[CPU {}] swap triggered (stop)", cpu_);

		handle_swap_event(get_dropped_ev_cnt(events));
		stopped_ = true;
		return 0;
	}

	if (clock::now() >= next_swap_) {
		spdlog::debug("[CPU {}] swap triggered (timeout)", cpu_);
		return handle_swap_event(get_dropped_ev_cnt(events));
	}

	if (last_swap_ts_ >= events.cpu(cpu_).swap_ts) [[likely]]
		return 0;

	const uint64_t drop_cnt = get_dropped_ev_cnt(events);
	spdlog::debug("[CPU {}] swap triggered (overflow), lost = {}", cpu_, drop_cnt);
	return handle_swap_event(drop_cnt);
}

int
IncidentLogProcessor::send(bool force) noexcept
{
	if (writer_.flush(force))
		return 0;

	return -static_cast<int>(Err::DB_CLT_TRANSIENT);
}

std::string_view
IncidentLogProcessor::name() const noexcept
{
	return "incident_log"sv;
}

std::unique_ptr<IncidentLogProcessor::BpfIncidentLogMap>
IncidentLogProcessor::create_incident_map(size_t cpu, bool active)
{
	const std::string map_name =  std::format("{}_{}_{}",
		MAP_LOG_BASENAME_STR, active ? 0: 1, cpu);

	if (map_name.size() >= BPF_OBJ_NAME_LEN)
		throw Except("Map name '{}' is too long", map_name);

	LIBBPF_OPTS(bpf_map_create_opts, opts, .map_flags = 0);
	FdGuard fd(bpf_map_create(BPF_MAP_TYPE_HASH,
		map_name.c_str(),
		sizeof(in6_addr),
		sizeof(IncidentLogStat),
		MAX_INCIDENTS_PER_CPU,
		&opts),
		"Can't create BPF_MAP_TYPE_HASH for incident logging"sv
	);
	//String is too small, don't need to move it.
	return std::make_unique<BpfIncidentLogMap>(map_name.c_str(), std::move(fd));
}

void
IncidentLogProcessor::populate_percpu_maps()
{
	BpfIncidentPerCpuNotifyInfos events;
	int err = incident_log_events_.get(events);
	if (err < 0 || cpu_ >= events.size())
		throw Except("[CPU {}] Can't get bpf-events for cpu.",  cpu_);

	err = incident_log_active_fd_.update(cpu_, active_map_->fd());
	if (err < 0)
		throw Except("[CPU {}] Can't assign incident log map.", cpu_);
}

int
IncidentLogProcessor::swap_active_map() noexcept
{
	//It would be good to let kernel know that it doesn't have to write data.
	int err = incident_log_active_fd_.update(cpu_, inactive_map_->fd());
	if (err < 0) {
		spdlog::error("[CPU {}] Can't replace active map with inactive: "
			      "{}", cpu_, err);
		return err;
	}

	swap(active_map_, inactive_map_);
	return err;
}

void
IncidentLogProcessor::read_and_clear_inactive_map(uint64_t drop_cnt) noexcept
{
	size_t total = 0;

	static_assert(sizeof(total) * 8 >= __builtin_clz(MAX_INCIDENTS_PER_CPU - 1) + 1,
		      "total is too small to hold MAX_INCIDENTS_PER_CPU");

	int err = inactive_map_->drain_by_batch(
		[&](std::span<const in6_addr> keys,
		    std::span<const IncidentLogStat> values)
		{
			for (size_t i = 0; i < keys.size(); ++i)
				writer_.append_event(keys[i], values[i], drop_cnt);

			total += keys.size();
		},
		batch_size_);

	if (err) {
		spdlog::error("[CPU {}] Failed to drain BPF map: {}", cpu_,
			      std::strerror(-err));
		return;
	}

	spdlog::debug("[CPU {}] Map cleared: {} elements.", cpu_, total);
	return;
}

int
IncidentLogProcessor::handle_swap_event(uint64_t drop_cnt) noexcept
{
	int err = swap_active_map();
	if (err)
		return err;

	read_and_clear_inactive_map(drop_cnt);

	/*
	 * Events consuming in user space go on the same CPU, which collect events
	 * in bpf, so chrono events are synchronized and could be treated as 
	 * monotonic. That's why we use timer to syncronize events in bpf-part
	 * and in user space. It is better not to use events[cpu_].swap_ts
	 * to set up last_swap_ts_ because read_and_clear_inactive_map can takes
	 * long time while flushing into CH.
	 */
	auto now = std::chrono::steady_clock::now();
	last_swap_ts_ = std::chrono::duration_cast<std::chrono::nanoseconds>(
				now.time_since_epoch()).count();

	next_swap_ = now + timer_interval_;
	return 0;
}
