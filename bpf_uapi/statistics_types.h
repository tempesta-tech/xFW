/*
 *	Tempesta statistic types.
 *
 * SPDX-FileCopyrightText: © 2026 Tempesta Technologies, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#pragma once

#include "static_assert.h"

/*
 * @name	- statistic's name
 * @desc	- main description
 */
struct XfwStatInfo {
	const char * const name;
	const char * const desc;
};

#define XFW_STAT_ARRAY_ASSERT(array, max)				\
STATIC_ASSERT(sizeof(array) / sizeof(struct XfwStatInfo) == (max),	\
	      "Statistics table is out of sync with enum")
