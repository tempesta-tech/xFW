/**
 *	Tempesta bpf maps for incident loging
 *
 * SPDX-FileCopyrightText: © 2026 Tempesta Technologies, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Design:
 * --------
 * BPF_MAP_TYPE_HASH maps store per-CPU decision statistics.
 * Each CPU has two dedicated maps:
 *   - an active map, used by the BPF program for updates
 *   - an inactive map, read by userspace after a swap
 *
 * The active maps are referenced from a BPF_MAP_TYPE_ARRAY_OF_MAPS, where each
 * array element corresponds to the active map of a specific CPU.
 * This design provides isolation between CPUs and allows lock-free updates.
 *
  * Swap flow:
 * 	1. Kernel detects overflow in active map -> emits swap event via ring buffer.
 * 	2. Userspace receives event, swaps active/inactive maps, reads inactive map.
 *
 * ------------------------------------------------
 * Note 1:
 * - Each CPU owns two independent maps (active and inactive).
 * - The total number of maps created in userspace is: cpu_count * 2.
 * - Only the active maps are inserted into the ARRAY_OF_MAPS for in-kernel access.
 * - All maps are created dynamically in userspace and are not pinned.
 *
 * ------------------------------------------------
 * Note 2: Under heavy load, the following issue may occur:
 * - The map becomes full, and the kernel emits an event.
 * - The user space process takes over the CPU, reads the event, and performs
 *   various tasks. During this time, the kernel may lose events.
 *
 * To mitigate this, we configure the maps to be large enough to handle even
 * a 2M botnet spike in a single burst. Under normal conditions, maps are swapped
 * and cleared on a timer, which prevents overflow.
 *
 * Currently, the map size and timer period are tuned so that even under a load
 * of 2 million requests per second, the system should be able to rotate maps
 * before they overflow. However, in extreme cases where the user space takes
 * longer to process events than expected, event loss is still possible.
 *
 * Ideally, the timer period should be chosen so that, even under peak load,
 * maps never reach full capacity before being swapped and cleared.
 *
 * Rationale for avoiding BPF_MAP_TYPE_PERCPU_HASH:
 * ------------------------------------------------
 * 1. In PERCPU_HASH, each key stores a per-CPU array of values.
 *    Deleting or updating a key requires touching all per-CPU entries,
 *    introducing unnecessary synchronization overhead.
 *    (See kernel source:
 *    https://codebrowser.dev/linux/linux/kernel/bpf/map_iter.c.html#:~:text=if%20(!is_percpu,)%20*%20num_possible_cpus()%3B)
 *
 * 2. When a PERCPU_HASH map overflows, the overflow event is triggered
 *    simultaneously on all CPUs, since the map shares a global key space.
 *    This completely breaks per-CPU autonomy and can lead to bursts of
 *    concurrent event handling, increasing latency and CPU load.
 *
 * 3. The effective number of unique keys differs:
 *       - PERCPU_HASH:     max_entries
 *       - ARRAY_OF_MAPS:   num_cpus * max_entries
 *    This provides better scalability and isolation for per-CPU statistics.
 */
#pragma once

#include "../common/incident_log_types.h"

/**
 * These BPF_MAP_TYPE_HASH maps hold per-CPU decision statistics.
 * Every CPU has two dedicated maps: one active and one inactive.
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_INCIDENTS_PER_CPU);
	__type(key, IncidentKey);
	__type(value, IncidentLogStat);
	// Inner def can't be pinned; fd will be stored in array-of-maps
} MAP_LOG_BASENAME_REF SEC(".maps");

/**
 * Array-of-maps holding active maps per CPU.
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
	__uint(max_entries, MAX_INCIDENT_CPU);
	__uint(key_size, sizeof(uint32_t));
	__uint(value_size, sizeof(uint32_t));
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__array(values, MAP_LOG_BASENAME_REF);
} MAP_LOG_ACTIVE_FD_REF SEC(".maps");

/**
 * Used for asynchronous notifications from kernel to user space. Each time a CPU
 * swaps its incident log map, a small `IncidentPerCpuNotifyInfo` record is pushed.
 * The record stores the **monotonic timestamp** of the swap event.
 * The user-space loop consumes these events and can determine:
 *   - how many events were dropped during the previous map’s lifetime,
 *   - and whether a swap has occurred since the last observed event.
 */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct IncidentPerCpuNotifyInfo);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} MAP_LOG_EVENTS_REF SEC(".maps");

typedef struct IncidentPerCpuBpfOnlyInfo {
	uint64_t	last_used_map_hint;
	uint64_t	insert_cnt;
} __attribute__((aligned(64))) IncidentPerCpuBpfOnlyInfo;

/**
 * Per-CPU map for BPF internal bookkeeping; **should NOT be used in user space**.
 *
 * This map controls the number of elements in the MAP_LOG_EVENTS_REF map.
 * The per-CPU insertion counter (`insert_cnt`) tracks the number of events
 * added to the currently active map. When the active map changes
 * (e.g., after a rotation or refill), the counter is reset for the new map.
 *
 * Note: The returned insertion count may slightly overestimate the real
 * number of inserts in rare cases. This occurs if, between timer ticks,
 * the active map switches twice but the second map receives no inserts.
 * The counter for the second map may then start from the old value.
 * Such overestimation is minor and safe, as these events are rare and do
 * not affect overall logic.
 *
 * When MAP_LOG_EV_CNT_REF reaches ~80% capacity, BPF logic generates an
 * event to userspace. The map is then **cleared only when the next insert**
 * occurs and the active map has changed (i.e., `last_used_map_hint` differs),
 * ensuring the previous data is safe to read by userspace.
 */
CHECK_MAP_NAME_LEN(MAP_LOG_EV_CNT_STR);
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, uint32_t);
	__type(value, IncidentPerCpuBpfOnlyInfo);
	__uint(max_entries, 1);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} MAP_LOG_EV_CNT_REF SEC(".maps");
