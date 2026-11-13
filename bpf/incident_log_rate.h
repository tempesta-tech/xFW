/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Per-CPU sliding-window budget and sampling for incident logging.
 *
 * SPDX-FileCopyrightText: © 2026 Tempesta Technologies, Inc.
 */
#pragma once

#ifdef BPF_PROGRAM
#include "vmlinux.h"
#else
#include <stdbool.h>
#include <stdint.h>
#endif

#include "../bpf_uapi/limits.h"

typedef struct XfwLogRateSlot {
	uint64_t	window_idx;
	uint32_t	events;
} XfwLogRateSlot;

typedef struct XfwLogRateLimit {
	XfwLogRateSlot	slot[2];
	uint32_t	sample_count;
} __attribute__((aligned(64))) XfwLogRateLimit;

static __always_inline bool
xfw_log_sample_allow(XfwLogRateLimit *bucket)
{
	if (++bucket->sample_count < XFW_LOG_SAMPLE_INTERVAL)
		return false;

	bucket->sample_count = 0;
	return true;
}

/*
 * Count admitted registrations, not attempts. Rejected attempts must not
 * prolong suppression. As with packet rate limits, the previous window is
 * weighted by its remaining overlap with the current sliding window.
 *
 * The window is at most 2^31 jiffies. A 32-bit event count multiplied by
 * the remaining jiffies therefore fits in uint64_t.
 */
static __always_inline bool
xfw_log_rate_allow(XfwLogRateLimit *bucket, uint64_t now, uint32_t shift,
		   uint32_t limit)
{
	if (!limit || shift >= 32)
		return false;

	const uint64_t window_idx = now >> shift;
	const uint64_t window_jiffies = 1ULL << shift;
	const uint64_t overlap = window_jiffies - (now & (window_jiffies - 1));
	XfwLogRateSlot *curr = &bucket->slot[window_idx & 1];
	const XfwLogRateSlot *prev = &bucket->slot[(window_idx - 1) & 1];

	if (curr->window_idx != window_idx) {
		curr->events = 0;
		curr->window_idx = window_idx;
	}

	uint64_t previous = 0;

	if (window_idx && prev->window_idx == window_idx - 1)
		previous = prev->events;

	const uint64_t effective = curr->events + (previous * overlap >> shift);

	if (effective >= limit)
		return false;

	curr->events++;

	return true;
}
