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

#include "statistics.h"
#include "statistics_diagnostic.h"

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

typedef struct XfwPerCpuStats {
	XfwPacketStats		decision[XFW_DECISION_STAT_MAX];
	XfwPacketStats		diagnostic[XFW_DIAGNOSTIC_STAT_MAX];

#ifdef __cplusplus
	XfwPerCpuStats &
	operator+=(const XfwPerCpuStats &other) noexcept
	{
		for (size_t i = 0; i < XFW_DECISION_STAT_MAX; ++i)
			decision[i] += other.decision[i];
		for (size_t i = 0; i < XFW_DIAGNOSTIC_STAT_MAX; ++i)
			diagnostic[i] += other.diagnostic[i];
		return *this;
	}
#endif
} XfwPerCpuStats;
