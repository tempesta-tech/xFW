/**
 *	Tempesta BPF TX packet statistics.
 *
 * SPDX-FileCopyrightText: © 2026 Tempesta Technologies, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#pragma once

#include "statistics_types.h"

enum XfwTxStat {
	XFW_SYNCOOKIE_GENERATED,
	XFW_TX_STAT_MAX
};

#if defined(__clang__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wc99-designator"
// We intentionally use C99-style array designators ([index] = value)
// because this syntax makes the mapping between enum values and
// string literals explicit and less error-prone.
//
// GCC and Clang warn in C++ mode that this is a "C99 extension"
// (-Wc99-designator), but the generated code is perfectly valid and
// supported by both compilers. We suppress the warning to keep the
// initialization concise and consistent between C and C++ builds.
#endif
static const struct XfwStatInfo xfw_tx_stats[] = {
	[XFW_SYNCOOKIE_GENERATED]		= {"xfw_syncookie_generated",
						   "Transmit packet back to "
						   "client with syncookie"}
};
XFW_STAT_ARRAY_ASSERT(xfw_tx_stats, XFW_TX_STAT_MAX);

#if defined(__clang__)
#pragma clang diagnostic pop
#endif
