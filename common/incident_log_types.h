/**
 *	Tempesta xFW user-space API for incident logging
 *
 * See the rules for shared struct declarations in bpf_uapi.h.
 *
 * SPDX-FileCopyrightText: © 2026 Tempesta Technologies, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#pragma once

#ifndef BPF_PROGRAM
#include <linux/types.h>
#else
#include "vmlinux.h"
#endif

#include "static_assert.h"
#include "statistics.h"

/**
 * Maximum incidents per CPU.
 *
 * Chosen value: 2^18 = 262144
 *
 * Rationale:
 * - Timer interval: 1 second.
 * - Load: ~2,000,000 requests per second distributed across 8 CPUs.
 *   => ~250,000 requests per CPU per second.
 * - To safely handle all incidents within one timer interval, we reserve a per-CPU
 *   buffer of 2^18 entries (262144), which covers the expected load with some margin.
 * - Note: In practice, there may be more CPUs.
 */
#define MAX_INCIDENTS_PER_CPU		(1 << 18) /* 2^18 = 262144 */
#define INCIDENT_FLUSH_THRESHOLD	(MAX_INCIDENTS_PER_CPU * 4 / 5) /* 80% */
#define MAX_INCIDENT_CPU		128

typedef struct IncidentKey {
	__be32			addr[4]; /* IPv4 occupies one word; remaining words are zero. */
} IncidentKey;

typedef uint64_t	IncidentLogReasons;

/*
 * @reason	- Each bit corresponds to a value from XfwStatistic enum
 */
typedef struct IncidentLogStat {
	IncidentLogReasons	reason;
	uint64_t		packets;
	uint64_t		bytes;

#ifdef __cplusplus
	IncidentLogStat() noexcept
		: reason{0}, packets{0}, bytes{0}
	{}
#endif
	STATIC_ASSERT(XFW_DECISION_STAT_MAX <= sizeof(IncidentLogReasons) * 8,
		"Number of flags exceeds the number of bits in IncidentLogStat::reason");
} IncidentLogStat;

/*
 * @swap_ts	- Time is measured with bpf_ktime_get_ns().
 *		  Strictly increasing only on local CPU without NMIs.
 */
typedef struct IncidentPerCpuNotifyInfo {
	uint64_t		swap_ts;
	uint64_t		drop_cnt;

#ifdef __cplusplus
	IncidentPerCpuNotifyInfo()
		: swap_ts{0}, drop_cnt{0}
	{}
#endif
} __attribute__((aligned(64))) IncidentPerCpuNotifyInfo;
