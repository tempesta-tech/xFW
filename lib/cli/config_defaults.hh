/**
 *	Tempesta Xfw default configuration settings
 *
 * SPDX-FileCopyrightText: © 2026 Tempesta Technologies, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#pragma once

static constexpr uint64_t TCP_SYN_DROP_DEFAULT_TIME_MIN = 500;
static constexpr uint64_t TCP_SYN_DROP_DEFAULT_MAX_DELAY = 3000;
/*
 * Zero means unlimited: the record remains blocked until LRU eviction.
 */
static constexpr uint64_t TCP_SYN_DROP_DEFAULT_BLOCK_TIMEOUT = 0;
