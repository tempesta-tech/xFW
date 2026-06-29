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

#include "../common/ip_helpers.h"

/* Print debug messages of the context of a subsustem using the routines. */
#ifndef BANNER
#define BANNER "filter"
#endif
#include "../common/bpf_uapi_proto_keys.h"

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
	__type(value, XfwRLimitLeakyBckt);
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

/**
 * Override XFW_CTX_DROP with XFW_CTX_PASS in case of evaluation mode enabled.
 * Should be called before passing the result to the kernel.
 */
static __always_inline int
finalize_result(const XfwGlobalCtx *ctx, int code)
{
	if (code == XFW_CTX_DROP && ctx->cfg->rules.evaluation_mode.enabled) {
		XFW_CTX_DBG("Packet would be dropped, "
			    "but allowed in evaluation mode");
		return XFW_CTX_PASS;
	}

	return code;
}

#define XFW_MAKE_CTX_DECISION_CODE(ctx, code, reason_idx, prefix, postfix,\
				   args...)				\
({									\
	XFW_CTX_DBG(prefix "%s" postfix, xfw_decision_stat[reason_idx].desc,\
		    ##args);						\
	code;								\
})

/**
 * Avoid returning DROP codes directly without using this function, as it is
 * easy to forget updating the dropped packet statistics.
 */

#define XFW_MAKE_CTX_DROP(ctx, reason_idx, args...)			\
({									\
	REGISTER_INCIDENT(ctx, reason_idx);				\
	XFW_MAKE_CTX_DECISION_CODE(ctx, XFW_CTX_DROP, reason_idx, "[DROP]",\
				   "", ##args);				\
})

#define XFW_MAKE_CTX_DROP_EXT(ctx, reason_idx, postfix, args...)	\
({									\
	REGISTER_INCIDENT(ctx, reason_idx);				\
	XFW_MAKE_CTX_DECISION_CODE(ctx, XFW_CTX_DROP, reason_idx, "[DROP]",\
				   postfix, ##args);			\
})

/**
 * Avoid returning PASS codes directly without using this function, as it is
 * easy to forget updating the passed packet statistics.
 */
#define XFW_MAKE_CTX_PASS(ctx, reason_idx, args...)			\
	XFW_MAKE_CTX_DECISION_CODE(ctx, XFW_CTX_PASS, reason_idx, "[PASS]",\
				   "", ##args)

#define XFW_MAKE_CTX_PASS_EXT(ctx, reason_idx, postfix, args...)	\
	XFW_MAKE_CTX_DECISION_CODE(ctx, XFW_CTX_PASS, reason_idx, "[PASS]",\
				   postfix, ##args)
/**
 * Avoid returning TX codes directly without using this function, as it is
 * easy to forget updating the forwarded packet statistics.
 * We don't need TX code for tc program, only for xdp.
 *
 * TODO: should it be decision?
 * TODO #514: this macro is used only by tcp_syncookies_syn_filter() for
 *      accounting of generated syncookies - this should be in prometheus
 *      statistics, but not in incidents.
 */
#define MAKE_XDP_TX(ctx, reason_idx, args...)				\
({									\
	REGISTER_INCIDENT(ctx, reason_idx);				\
	XFW_MAKE_CTX_DECISION_CODE(ctx, XDP_TX, reason_idx, "[TRANSMIT]",\
				   "", ##args);				\
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
			 XfwRLimitLeakyBckt *bucket)
{
	uint64_t refill_ts = READ_ONCE(bucket->nrefill_jiff);
	/*
	 * TODO #87: fix with Cloudflare ratelimiting.
	 *
	 * - Instead of spinlocking or doing any kind of cas-loop, we just allow
	 * only single thread to perform refill and potentially loose any
	 * concurrent rate adjustments going from other threads. For this
	 * assumption we're awarded with the wait-free bucket refill.
	 */
	if (ctx->ts_jiff > refill_ts &&
	    __atomic_compare_exchange_n(&bucket->nrefill_jiff, &refill_ts,
					ctx->ts_jiff + JIFFIES_PER_SEC, false,
					__ATOMIC_ACQ_REL, __ATOMIC_RELAXED))
	{
		WRITE_ONCE(bucket->pkt_tok, rate->packets);
		WRITE_ONCE(bucket->byte_tok, rate->bytes);
	}
	/*
	 * In case if only one limit is set,
	 * default value for absent limit would be INT64_MAX
	 * That ensures correct logic in one limit case
	 */
	if (bucket->pkt_tok <= 0 || bucket->byte_tok <= 0) {
		return false;
	}

	__atomic_sub_fetch(&bucket->pkt_tok, 1, __ATOMIC_RELAXED);
	__atomic_sub_fetch(&bucket->byte_tok, ctx->pkt_sz,
			   __ATOMIC_RELAXED);
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
	XfwRLimitLeakyBckt *bucket;

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
ipv4_populate_dst_key(const struct iphdr *ip4_hdr, int l4_proto,
	XfwDstKey *dst_key)
{
	dst_key->ipver = XFW_IP_VER_4;
	dst_key->proto = (uint8_t)l4_proto;
	xfw_ipv4_to_ipv6_mapped(ip4_hdr->daddr, dst_key->addr.addr32);
}

static __always_inline void
ipv6_populate_lpm_key(const struct in6_addr *addr, XfwIpv6LpmKey *key)
{
	key->prefixlen = 128;
	xfw_ipv6_addr_cpy(key->addr, addr);
}

static __always_inline void
ipv6_populate_dst_key(const struct ipv6hdr *ip6_hdr, int l4_proto,
	XfwDstKey *dst_key)
{
	dst_key->ipver = XFW_IP_VER_6;
	dst_key->proto = (uint8_t)l4_proto;
	dst_key->addr.in6 = ip6_hdr->daddr;
}
