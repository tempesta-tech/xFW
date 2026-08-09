/**
 *	Tempesta xFW common statistic structures for eBPF and user-space
 *
 * See the rules for the declarations in types.h.
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

#include "pass_stats.h"
#include "traffic_stats.h"
#include "tx_stats.h"

typedef struct XfwPacketStats {
	uint64_t	packets;
	uint64_t	bytes;

#ifdef __cplusplus
	XfwPacketStats &
	operator+=(const XfwPacketStats &s) noexcept
	{
		packets += s.packets;
		bytes += s.bytes;

		return *this;
	}
#endif
} XfwPacketStats;

/*
 * Per-CPU counters for PASS, TX, traffic and selected DROP statistics.
 *
 * Blocking security events are maintained by the incident logging subsystem
 * and exported to ClickHouse. Feature-specific Prometheus counters may also
 * account for the same packet, as with failed SYN-cookie processing.
 */
typedef struct XfwPerCpuStats {
	XfwPacketStats		pass[XFW_PASS_STAT_MAX];
	XfwPacketStats		transmitted[XFW_TX_STAT_MAX];
	XfwPacketStats		traffic[XFW_TRAFFIC_STAT_MAX];
	XfwPacketStats		syncookie_failed;

#ifdef __cplusplus
	XfwPerCpuStats &
	operator+=(const XfwPerCpuStats &other) noexcept
	{
		for (size_t i = 0; i < XFW_PASS_STAT_MAX; ++i)
			pass[i] += other.pass[i];
		for (size_t i = 0; i < XFW_TX_STAT_MAX; ++i)
			transmitted[i] += other.transmitted[i];
		for (size_t i = 0; i < XFW_TRAFFIC_STAT_MAX; ++i)
			traffic[i] += other.traffic[i];
		syncookie_failed += other.syncookie_failed;
		return *this;
	}
#endif
} XfwPerCpuStats;
