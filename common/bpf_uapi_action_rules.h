/**
 *	Tempesta xFW action structures common for eBPF and manager
 *
 * See the rules for shared struct declarations in bpf_uapi.h.
 *
 * SPDX-FileCopyrightText: © 2026 Tempesta Technologies, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#pragma once

#ifdef BPF_PROGRAM
#include "vmlinux.h"
#else
#include <linux/types.h>
#endif

#ifdef __cplusplus
#include <optional>
#endif

#include "limits.h"

typedef uint8_t					XfwRLimitIdx;

enum XfwAction: uint8_t {
	XFW_ACTION_ALLOW,
	XFW_ACTION_BLOCK,
	XFW_ACTION_RATE_LIMIT
};

/**
 * @action	- XfwAction value
 * @named_idx	- named rate limit idx
 */
typedef struct XfwSrcRule {
	uint8_t		action;
	XfwRLimitIdx	named_idx;

#ifdef __cplusplus
	using named_idx_type = decltype(named_idx);
	static_assert(XFW_MAX_NAMED_RATELIMITS
		      <= std::numeric_limits<named_idx_type>::max(),
		      "named_idx_type too small to hold XFW_MAX_NAMED_RATELIMITS value");
	 /* Set named_idx to "invalid" value */
	XfwSrcRule() noexcept
		: action{ XfwAction::XFW_ACTION_ALLOW }
		, named_idx{ std::numeric_limits<named_idx_type>::max() }
	{}

	explicit XfwSrcRule(bool allow, const std::optional<size_t> &ratelimit) noexcept
		: named_idx{ std::numeric_limits<named_idx_type>::max() }
	{
		if (!allow) {
			action = XfwAction::XFW_ACTION_BLOCK;
		}
		else if (ratelimit.has_value()) {
			action = XfwAction::XFW_ACTION_RATE_LIMIT;
			named_idx = ratelimit.value();
		}
		else {
			action = XfwAction::XFW_ACTION_ALLOW;
		}
	}
	
	bool operator==(const XfwSrcRule&) const = default;
#endif
} XfwSrcRule;

/**
 * Generic rate limiting action implementing the leaky buckets algorithm.
 *
 * @pkt_tok		- tokens for packet counter
 * @byte_tok		- tokens for byte counter
 * @nrefill_jiff	- timestamp in jiffies for the next refill of the bucket
 *
 * This structure may reside in one of three maps:
 * MAP_RATELIMIT_REF, MAP_SRC_RATELIMIT_REF, or MAP_SRC_PORT_RL_REF.
 */
typedef struct XfwRLimitLeakyBckt {
	int64_t			pkt_tok;
	int64_t			byte_tok;
	/* TODO #87: Timestamp of the next refill interval (in jiffies). */
	uint64_t		nrefill_jiff;

#ifdef __cplusplus
		/* TODO #87: Exhaust the bucket so the next check refills it first. */
	void
	reset() noexcept
	{
		/* TODO #87: Maybe we will not need reset function after #87. */
		nrefill_jiff = 0;
	}
#endif
} __attribute__((aligned(64))) XfwRLimitLeakyBckt;

typedef struct XfwRLimitRule {
	/* Used to read the XfwRLimitLeakyBckt at bucket_idx from the
	 * preallocated bucket array (MAP_RATELIMIT_REF).
	 */
	uint32_t	bucket_idx;
	/* Rate limit as index into named rate limits. */
	XfwRLimitIdx	named_idx;

#ifdef __cplusplus
	using named_idx_type = decltype(named_idx);
	using bucket_idx_type = decltype(bucket_idx);
	static_assert(XFW_MAX_NAMED_RATELIMITS
		      <= std::numeric_limits<named_idx_type>::max(),
	              "named_idx_type too small to hold XFW_MAX_NAMED_RATELIMITS value");
	 /* Set bucket_idx and named_idx to "invalid" value */
	XfwRLimitRule() noexcept
		: bucket_idx{ std::numeric_limits<bucket_idx_type>::max() }
		, named_idx{ std::numeric_limits<named_idx_type>::max() }
	{}

	bool operator==(const XfwRLimitRule&) const = default;
#endif
} XfwRLimitRule;

/**
 * Base xFW action rule.
 *
 * It is used everywhere except src ip filter.
 * Src ip filter is different because it do not use global
 * rate limit bucket store indexed by bucket_idx, so we can save
 * some space in it introducing separate type.
 *
 * @action		- XfwAction value
 * @rlimit		- rate limit handler
 */
typedef struct XfwActionRule {
	uint8_t			action;
	XfwRLimitRule		rlimit;

#ifdef __cplusplus
	XfwActionRule()
		: action{XfwAction::XFW_ACTION_ALLOW}
	{}

	explicit XfwActionRule(uint8_t action)
		: action(action)
	{}

	explicit XfwActionRule(bool allow,
			       const std::optional<XfwRLimitIdx> &ratelimit)
			       noexcept
	{
		if (!allow) {
			action = XfwAction::XFW_ACTION_BLOCK;
		}
		else if (ratelimit.has_value()) {
			action = XfwAction::XFW_ACTION_RATE_LIMIT;
			rlimit.named_idx = ratelimit.value();
		}
		else {
			action = XfwAction::XFW_ACTION_ALLOW;
		}
	}
	
	bool operator==(const XfwActionRule&) const = default;
#endif
} XfwActionRule;
