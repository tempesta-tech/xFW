/**
 *	Tcp anomaly features
 *
 * SPDX-FileCopyrightText: © 2026 Tempesta Technologies, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#pragma once
#ifdef BPF_PROGRAM
#include "vmlinux.h"
#else
#include <cstdint>
#endif

enum TcpAnomalyFeature : uint8_t {
	XFW_BAD_FLAGS		= 0,
	XFW_SYN_WIHOUT_OPTIONS	= 1,
	XFW_SYN_WITH_PAYLOAD	= 2,
	XFW_SYN_WITH_SEQ_NO	= 3,
	XFW_TCP_ANOMALY_FEATURE_MAX
};
