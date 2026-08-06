/**
 *	Tempesta xFW filtering logic common for TC and XDP programs
 *
 * These constants/macros are required to call functions from this file in
 * different modules, such as TC or XDP. Depending on the context, they should
 * expand to the corresponding macros/functions of the specific module.
 *
 * SPDX-FileCopyrightText: © 2026 Tempesta Technologies, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#pragma once

#include "../bpf_uapi/ip_helpers.h"

/* Print debug messages of the context of a subsustem using the routines. */
#pragma push_macro("BANNER")
#undef BANNER
#define BANNER "filter"
#include "../bpf_uapi/proto_keys.h"

#include "log.h"

#include "ctx.h"
#include "shadow_map_tools.h"
#include "incident_log.h"

#if defined(XFW_TC)
#define XFW_CTX_PASS		TC_ACT_OK
#define XFW_CTX_DROP		TC_ACT_SHOT
#elif defined(XFW_XDP)
#define XFW_CTX_PASS		XDP_PASS
#define XFW_CTX_DROP		XDP_DROP
#elif defined(XFW_DNS)
#define XFW_CTX_PASS		XDP_PASS
#define XFW_CTX_DROP		XDP_DROP
#else
#error "Undefined program type: should be TC or XDP"
#endif

/*
 * Read-only for eBPF.
 * Keys are taken from XfwRLimitRule.bucket_idx.
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, uint32_t);
	__type(value, XfwRLimitSlidingWindow);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, XFW_MAX_RATE_LIMITER_BUCKETS);
	__uint(map_flags, BPF_F_MMAPABLE);
} MAP_RATELIMIT_REF SEC(".maps");

/**
 * CHAIN - macro to sequentially call packet filters in eBPF/XDP/TC.
 * Have the same contract as bpf_tail_call.
 * If the filter returns a value other than XFW_CTX_CONTINUE, the chain stops
 * and the value is returned; otherwise, processing continues to the next filter.
 * Before passing the result to the kernel, you need to call finalize_result
 * on the result.
 */
#define CHAIN(filter, ...)						\
do {									\
	int r = filter(__VA_ARGS__);					\
	if (r != XFW_CTX_CONTINUE)					\
		return r;						\
} while (0)

#define CHAIN_PASS_ALL(filter, ...)					\
do {									\
	r = filter(__VA_ARGS__);					\
	if (r == XFW_CTX_CONTINUE)					\
		break;							\
	if (r == XFW_CTX_PASS)						\
		goto pass;						\
	return r;							\
} while (0)

/**
 * Override XFW_CTX_DROP with XFW_CTX_PASS in case of evaluation mode enabled.
 * Should be called before passing the result to the kernel.
 */
static __always_inline int
finalize_result(const XfwFilterCfg *cfg, int code)
{
	if (code == XFW_CTX_DROP && cfg->rules.evaluation_mode.enabled) {
		XFW_CTX_DBG("Packet would be dropped, "
			    "but allowed in evaluation mode");
		return XFW_CTX_PASS;
	}

	return code;
}

static __always_inline void
count_traffic_stat(XfwPerCpuStats *g_stats, uint32_t pkt_sz,
		   enum XfwTrafficStat reason)
{
	++g_stats->traffic[reason].packets;
	g_stats->traffic[reason].bytes += pkt_sz;
}

static __always_inline void
count_pass_stat(XfwPerCpuStats *g_stats, uint32_t pkt_sz,
		enum XfwPassStat reason)
{
	++g_stats->pass[reason].packets;
	g_stats->pass[reason].bytes += pkt_sz;
}

static __always_inline void
count_tx_stat(XfwPerCpuStats *g_stats, uint32_t pkt_sz,
	      enum XfwTxStat reason)
{
	++g_stats->transmitted[reason].packets;
	g_stats->transmitted[reason].bytes += pkt_sz;
}

/**
 * Avoid returning DROP codes directly without using these 2 functions, as it is
 * easy to forget updating the dropped packet statistics.
 */
#define XFW_MAKE_CTX_DROP_EXT(ctx, reason_idx, postfix, args...)	\
({									\
	REGISTER_INCIDENT(ctx, reason_idx);				\
	XFW_CTX_DBG("[DROP] %s" postfix,				\
		    xfw_drop_stats[reason_idx].desc, ##args);	\
	XFW_CTX_DROP;							\
})

#define XFW_MAKE_CTX_DROP(ctx, reason_idx, args...)			\
	XFW_MAKE_CTX_DROP_EXT(ctx, reason_idx, "", ##args)

/**
 * Avoid returning PASS codes directly without using these 2 functions, as it is
 * easy to forget updating the passed packet statistics.
 */
#define XFW_MAKE_CTX_PASS_EXT(ctx, reason_idx, postfix, args...)	\
({									\
	count_pass_stat(ctx->g_stats, ctx->pkt_sz, reason_idx);		\
	XFW_CTX_DBG("[PASS] %s" postfix,				\
		    xfw_pass_stats[reason_idx].desc, ##args);		\
	XFW_CTX_PASS;							\
})

#define XFW_MAKE_CTX_PASS(ctx, reason_idx, args...)			\
	XFW_MAKE_CTX_PASS_EXT(ctx, reason_idx, "", ##args)

/**
 * Avoid returning TX codes directly without using this function, as it is
 * easy to forget updating the forwarded packet statistics.
 * We don't need TX code for tc program, only for xdp.
 */
#define MAKE_XDP_TX(ctx, reason_idx, args...)				\
({									\
	count_tx_stat(ctx->g_stats, ctx->pkt_sz, reason_idx);		\
	XFW_CTX_DBG("[TRANSMIT] %s",					\
		    xfw_tx_stats[reason_idx].desc, ##args);		\
	XDP_TX;								\
})

/**
 * Checks whether the given rate limit bucket allows an operation.
 *
 * This function updates the internal state of the rate limit bucket
 * (e.g., consuming tokens or updating timestamps) according to the
 * configured rate limit, and determines whether the operation is allowed.
 *
 * Returns true  if the operation is within the allowed rate limit (can proceed).
 * Returns false if the rate limit has been exceeded (should be limited/dropped).
 */
static __always_inline bool
xfw_is_within_rlimit(const XfwGlobalCtx *ctx, const XfwPacketRate *rate,
                     XfwRLimitSlidingWindow *bucket)
{
	const uint64_t window_idx = ctx->ts_jiff >> ctx->cfg->rl_window.shift;
	const uint64_t offset = ctx->ts_jiff & ctx->cfg->rl_window.mask;
	const uint64_t overlap = ctx->cfg->rl_window.jiffies - offset;

	XfwRLimitSlot *curr = &bucket->slot[window_idx & 1];
	XfwRLimitSlot *prev = &bucket->slot[(window_idx - 1) & 1];

	/*
	* Lazily recycle the slot when it is reused for a new window.
	*
	* Concurrent CPUs may race while resetting the slot, resulting in a few
	* lost updates around the window boundary. This is acceptable for this
	* approximate lock-free rate limiter.
	*/
	if (READ_ONCE(curr->window_idx) != window_idx) {
		WRITE_ONCE(curr->pkts, 0);
		WRITE_ONCE(curr->bytes, 0);
		WRITE_ONCE(curr->window_idx, window_idx);
	}

	uint64_t curr_pkts = READ_ONCE(curr->pkts);
	uint64_t curr_bytes = READ_ONCE(curr->bytes);

	uint64_t prev_pkts = 0;
	uint64_t prev_bytes = 0;

	if (window_idx != 0 && READ_ONCE(prev->window_idx) == window_idx - 1) {
		prev_pkts = READ_ONCE(prev->pkts);
		prev_bytes = READ_ONCE(prev->bytes);
	}

	/*
	 * Approximate sliding-window interpolation:
	 *	effective = current + previous * remaining_fraction
	 *
	 * The multiplication is performed before the shift. Configuration
	 * validation guarantees:
	 *	max_rate * window_jiffies <= UINT64_MAX
	 *
	 * Therefore, the intermediate multiplication cannot overflow uint64_t.
	 * With a 1024-jiffy window the theoretical maximum supported rate is:
	 *
	 *   UINT64_MAX / 1024
	 *       = 18,014,398,509,481,983 bytes/s (≈18 PB/s)
	 */
	uint64_t effective_pkts =
		curr_pkts + (prev_pkts * overlap >> ctx->cfg->rl_window.shift);

	uint64_t effective_bytes =
		curr_bytes + (prev_bytes * overlap >> ctx->cfg->rl_window.shift);

	if (effective_pkts >= rate->packets)
		return false;

	if (ctx->pkt_sz > rate->bytes)
		return false;

	if (effective_bytes > rate->bytes - ctx->pkt_sz)
		return false;

	__atomic_fetch_add(&curr->pkts, 1, __ATOMIC_RELAXED);
	__atomic_fetch_add(&curr->bytes, ctx->pkt_sz, __ATOMIC_RELAXED);

	return true;
}

/**
 * Checks whether a packet is allowed by its configured rate limits.
 *
 * This function retrieves the appropriate rate limit bucket for the given rule,
 * ensures the bucket is initialized and valid, and then checks the state
 * via the lower-level rate limit function.
 *
 * Returns true if the packet is allowed by the rate limits (can pass).
 * Returns false if the packet exceeds the rate limits (should be limited/dropped).
 */
static __always_inline bool
xfw_is_allowed_by_rlimits(const XfwGlobalCtx *ctx, const XfwRLimitRule *rule)
{
	XfwRLimitSlidingWindow *bucket;

	if (!rule)
		return true;

	bucket = bpf_map_lookup_elem(&MAP_RATELIMIT_REF, &rule->bucket_idx);
	VERIFY_TRUE_OR_RETURN(bucket, true);
	VERIFY_TRUE_OR_RETURN(rule->named_idx < XFW_MAX_NAMED_RATELIMITS, true);

	return xfw_is_within_rlimit(ctx, &ctx->cfg->named_rates[rule->named_idx],
					bucket);
}

typedef union XfwIpLpmKey {
	XfwIpv4LpmKey	addr4;
	XfwIpv6LpmKey	addr6;
} XfwIpLpmKey;

static __always_inline void
ipv4_populate_lpm_key(__be32 addr, XfwIpv4LpmKey *key)
{
	key->prefixlen = 32;
	key->addr = addr;
}

static __always_inline void
ipv6_populate_lpm_key(const struct in6_addr *addr, XfwIpv6LpmKey *key)
{
	key->prefixlen = 128;
	xfw_ipv6_addr_cpy(key->addr, addr);
}

#undef BANNER
#pragma pop_macro("BANNER")
