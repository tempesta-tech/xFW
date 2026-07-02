/**
 *	Tempesta static_assert shared between ebpf program and user-space tools
 *
 * SPDX-FileCopyrightText: © 2026 Tempesta Technologies, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#pragma once

#if defined(__cplusplus)
#define STATIC_ASSERT(expr, msg) static_assert((expr), msg)
#else
#define STATIC_ASSERT(expr, msg) _Static_assert((expr), msg)
#endif
