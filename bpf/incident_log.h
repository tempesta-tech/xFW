/**
 *	Tempesta bpf helpers for incident loging
 *
 * SPDX-FileCopyrightText: © 2026 Tempesta Technologies, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Each CPU maintains its own "active" incident-log map, where packet counters
 * and statistics are accumulated.  When a per-CPU map becomes full
 * (-ENOMEM on insert) or a timeout expires, the program pushes a notification
 * event to user space through a ring buffer. The user-space daemon then swaps
 * active map to inactive, reads the inactive map (which is now ready for export)
 * and flushes its contents to the incident storage (e.g., ClickHouse or another
 * backend).
 *
 * The scheme avoids lock contention and provides zero-copy handoff between
 * kernel and user space for log flushing.
 */
#pragma once

#include <linux/errno.h>

#include "vmlinux.h"
#include "../common/bpf_uapi.h"

#include "compiler.h"
#include "incident_log_maps.h"

static __always_inline void
register_packet_percpu(XfwPacketStats *s, uint32_t pkt_sz)
{
	s->packets++;
	s->bytes += pkt_sz;
}

#define REG_PACKET_GLOBAL(ctx, reason_idx)				\
	register_packet_percpu(&(ctx)->g_stats->diagnostic[reason_idx],	\
			       (ctx)->pkt_sz)

#define REG_PACKET_REASON(ctx, reason_idx)				\
	register_packet_percpu(&ctx->g_stats->decision[reason_idx], (ctx)->pkt_sz)

/*
 * Emit a swap notification for the currently active per-CPU map.
 * 
 * This function is called when the active map for a CPU needs to be swapped.
 * It pushes a swap event to the per-CPU notification buffer to inform
 * userspace that the previously active map is ready to be consumed.
 */
static __always_inline void
push_swap_event()
{
	const unsigned zero = 0;
	IncidentPerCpuNotifyInfo *ev = bpf_map_lookup_elem(&MAP_LOG_EVENTS_REF,
							   &zero);
	if (unlikely(!ev))
		return;

	ev->swap_ts = bpf_ktime_get_ns();
}

/*
 * Emit a swap notification and account a dropped event.
 * 
 * This is called when a map swap is required and the current event cannot be
 * inserted (e.g. due to capacity exhaustion). In addition to notifying userspace
 * about the map swap, the per-CPU drop counter is incremented.
 */
static __always_inline void
push_swap_event_and_update_drop_cnt()
{
	const unsigned zero = 0;
	IncidentPerCpuNotifyInfo *ev = bpf_map_lookup_elem(&MAP_LOG_EVENTS_REF,
							   &zero);
	if (unlikely(!ev))
		return;

	ev->drop_cnt += 1;
	ev->swap_ts = bpf_ktime_get_ns();
}

/*
 * Account a dropped incident event.
 *
 * This function is used when an event cannot be recorded due to
 * resource exhaustion or temporary unavailability of the target map.
 */
static __always_inline void
update_drop_cnt()
{
	const unsigned zero = 0;
	IncidentPerCpuNotifyInfo *ev = bpf_map_lookup_elem(&MAP_LOG_EVENTS_REF,
							   &zero);
	if (unlikely(!ev))
		return;
	
	ev->drop_cnt += 1;
}

static __always_inline void
populate_incident_key(const XfwIp* ilog_addr, IncidentKey *key)
{
	__builtin_memcpy(key->addr, ilog_addr->addr32, sizeof(key->addr));
}

static __always_inline bool
ilog_addr_presented(const XfwIp *addr)
{
	return addr->addr32[0] | addr->addr32[1] | addr->addr32[2] | addr->addr32[3];
}

/*
 * Maintain a per-CPU insertion counter for the currently active map.
 *
 * The counter is incremented on each insert as long as the active map
 * remains unchanged. When the active map changes (e.g. after a map rotation),
 * the counter is reset and tracking continues for the new map.
 *
 * This counter is used to estimate map usage and to trigger swap or
 * mitigation logic before the map becomes full, preventing event loss.
 * 
 * Retuns current insertion count for the active map.
 */
static __always_inline uint64_t
update_map_info(uint64_t active_map_hint)
{
	const unsigned zero = 0;
	IncidentPerCpuBpfOnlyInfo *inf = bpf_map_lookup_elem(&MAP_LOG_EV_CNT_REF,
							     &zero);
	if (unlikely(!inf))
		return 0;

	/* Same map is still active — just increment the insertion counter */
	if (likely(inf->last_used_map_hint == active_map_hint))
		return ++inf->insert_cnt;
	
	/*
	 * Active map has changed.
	 * Reset the counter and start tracking inserts for the new map.
	 */
	inf->insert_cnt = 1;
	inf->last_used_map_hint = active_map_hint;
	return 1;
}

static __always_inline void
register_incident(const XfwIp* ilog_addr, XfwPerCpuStats *global_stats,
		  uint32_t pkt_sz, enum XfwStatistic reason)
{
	register_packet_percpu(&global_stats->decision[reason], pkt_sz);

	if (!ilog_addr_presented(ilog_addr)) {
		XFW_CTX_DBG("Source address for the problematic packet "
			    "is not yet known");
		update_drop_cnt();
		return;
	}

	IncidentKey key;
	populate_incident_key(ilog_addr, &key);

	const u32 cpu = bpf_get_smp_processor_id();
	void *incident_map = bpf_map_lookup_elem(&MAP_LOG_ACTIVE_FD_REF, &cpu);
	if (unlikely(!incident_map)) {
		XFW_CTX_DBG("Can't find incident map");
		update_drop_cnt();
		return;
	}

	IncidentLogStat *stat = bpf_map_lookup_elem(incident_map, &key);
	if (stat) {
		stat->reason |= (IncidentLogReasons)1 << reason;
		stat->packets++;
		stat->bytes += pkt_sz;
		return;
	}

	const IncidentLogStat new_stat = {
		.reason = (IncidentLogReasons)1 << reason,
		.packets = 1,
		.bytes = pkt_sz
	};
	long ret = bpf_map_update_elem(incident_map, &key, &new_stat, BPF_NOEXIST);
	if (likely(ret >= 0)) {
		const uint64_t new_size = update_map_info((uint64_t)incident_map);
		if (new_size >= INCIDENT_FLUSH_THRESHOLD)
			push_swap_event();
		return;
	}

	/*
	 * Never mind if we will miss some events - they are not
	 * crucial, but it will help to work without a synchronization.
	 * Just register dropped event.
	 */
	XFW_CTX_DBG("Lost incident event");
	if (ret == -ENOMEM || ret == -E2BIG)
		push_swap_event_and_update_drop_cnt();
	else 
		update_drop_cnt();
}

#define REGISTER_INCIDENT(ctx, reason)					\
	register_incident(&(ctx)->ilog_addr, (ctx)->g_stats, (ctx)->pkt_sz, reason)
