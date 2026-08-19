/**
 *	Tempesta Xfw default configuration settings
 *
 * SPDX-FileCopyrightText: © 2026 Tempesta Technologies, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#pragma once

/*
 * Minimum delay between the initial SYN and its first valid retransmission.
 */
static constexpr uint64_t TCP_SYN_DROP_DEFAULT_MIN_DELAY_MS = 500;
/*
 * Maximum delay allowed between consecutive SYN retransmissions.
 */
static constexpr uint64_t TCP_SYN_DROP_DEFAULT_MAX_DELAY_MS = 3000;
/*
 * How long a tuple remains blocked after exhausting the allowed retries.
 * Zero means unlimited: the record remains blocked until LRU eviction.
 */
static constexpr uint64_t TCP_SYN_DROP_DEFAULT_BLOCK_TIMEOUT_MS = 0;
/*
 * Default SYN-cookie timer values.
 */
static constexpr uint32_t DEFAULT_PASSIVE_TIMER_SEC = 1;
static constexpr uint32_t DEFAULT_FLOOD_TIMER_SEC = 1;
