/**
 *	Tempesta xFW timeout based TCP SYN flood protection implementation
 *
 * SPDX-FileCopyrightText: © 2026 Tempesta Technologies, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#pragma once

#include "vmlinux.h"

#pragma push_macro("BANNER")
#undef BANNER
#define BANNER "syn_drop"
#include "log.h"

#include "filter.h"
#include "tcp_flow.h"

#define XFW_SYN_BLOCKED                        UINT64_MAX

typedef struct XfwSynDropCtx {
	void *stage1_map;
	void *stage2_map;
	const void *key;
} XfwSynDropCtx;

/*
 * The stage 1 map stores SYN tuples which have not yet passed the initial
 * retransmission timing check.
 *
 * jtxtstamp records the first SYN time, or XFW_SYN_BLOCKED to reject the
 * tuple until LRU eviction. Check the sentinel before timestamp arithmetic.
 */
typedef struct XfwSynStage1Entry {
	uint64_t	jtxtstamp;
} XfwSynStage1Entry;

/*
 * The stage 2 map stores tuples which have already passed the first timing
 * check and whose following SYN retransmissions are being tracked.
 *
 * Once retry_count is exhausted, the entry is kept in the map and marked
 * as blocked instead of being removed. Keeping the entry prevents a
 * subsequent SYN for the same tuple from starting the authentication
 * sequence again and thus bypassing the retry limit.
 *
 * blocked_until is 0 while active, XFW_SYN_BLOCKED for a permanent block,
 * or a finite expiration timestamp. After a finite block expires, the next
 * SYN starts a new stage 1 validation cycle and is dropped. Permanent blocks
 * remain until LRU eviction.
 */
typedef struct XfwSynStage2Entry {
	uint64_t	jtxtstamp;
	uint64_t	max_delay;
	uint64_t	blocked_until;
	uint32_t	retry_count;
} XfwSynStage2Entry;

/* CPU ownership is encoded by the outer map index, not the tuple key. */
typedef struct XfwIpv4SynKey {
	XfwIpv4TcpFlow flow;
	uint32_t seq;
} XfwIpv4SynKey;

typedef struct XfwIpv6SynKey {
	XfwIpv6TcpFlow flow;
	uint32_t seq;
} XfwIpv6SynKey;

STATIC_ASSERT(sizeof(XfwIpv4SynKey) == 16, "Unexpected IPv4 SYN key size");
STATIC_ASSERT(sizeof(XfwIpv6SynKey) == 40, "Unexpected IPv6 SYN key size");

/*
 * Stage 1 map:
 *
 *   first SYN              -> insert and drop
 *   valid retransmission   -> move to stage 2 map and pass
 *   invalid retransmission -> block until LRU eviction
 *
 * These one-entry templates only describe the inner maps. The loader sets
 * the actual per-CPU capacities independently for both stages.
 */
struct XfwSynStage1Ipv4Map {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 1);
	__type(key, XfwIpv4SynKey);
	__type(value, XfwSynStage1Entry);
};

struct XfwSynStage1Ipv6Map {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 1);
	__type(key, XfwIpv6SynKey);
	__type(value, XfwSynStage1Entry);
};

/*
 * Stage 2 map:
 *
 * The smaller map is isolated from the large stage 1 map so that a flood
 * with random tuples cannot directly evict all validated connections.
 */
struct XfwSynStage2Ipv4Map {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 1);
	__type(key, XfwIpv4SynKey);
	__type(value, XfwSynStage2Entry);
};

struct XfwSynStage2Ipv6Map {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 1);
	__type(key, XfwIpv6SynKey);
	__type(value, XfwSynStage2Entry);
};

/*
 * The loader sizes these arrays for all possible CPUs, divides each stage's
 * capacity among them and installs independent LRU hashes before attachment.
 * Inner maps use a common LRU within their owning CPU's map.
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
	__uint(max_entries, 1);
	__type(key, uint32_t);
	__array(values, struct XfwSynStage1Ipv4Map);
} MAP_SYN_STAGE1_IPV4_REF SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
	__uint(max_entries, 1);
	__type(key, uint32_t);
	__array(values, struct XfwSynStage1Ipv6Map);
} MAP_SYN_STAGE1_IPV6_REF SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
	__uint(max_entries, 1);
	__type(key, uint32_t);
	__array(values, struct XfwSynStage2Ipv4Map);
} MAP_SYN_STAGE2_IPV4_REF SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
	__uint(max_entries, 1);
	__type(key, uint32_t);
	__array(values, struct XfwSynStage2Ipv6Map);
} MAP_SYN_STAGE2_IPV6_REF SEC(".maps");

/*
 * Move a tuple from the large stage 1 map to the smaller stage 2 map.
 *
 * The new entry is inserted first. This way a map insertion failure does
 * not remove the only existing protection state.
 */
static __always_inline bool
xfw_promote_syn(const XfwSynDropCtx *drop_ctx, uint64_t now,
		const XfwRulesCfgTcpSynDrop *cfg)
{
	XfwSynStage2Entry retry = {
		.jtxtstamp = now,
		.max_delay = cfg->max_delay_jiff * 2,
		.blocked_until = 0,
		.retry_count = 1,
	};

	/*
	 * Keep BPF_NOEXIST to avoid overwriting an existing stage 2 entry in
	 * case of stale state. In that case the current SYN is dropped
	 * conservatively instead of destroying the existing protection state.
	 */
	if (bpf_map_update_elem(drop_ctx->stage2_map, drop_ctx->key, &retry,
				BPF_NOEXIST))
	{
		XFW_CTX_DBG("Failed to add SYN tuple to the syn retry table");
		return false;
	}

	bpf_map_delete_elem(drop_ctx->stage1_map, drop_ctx->key);

	return true;
}

/*
 * Validate a retransmitted SYN using its stage 1 entry.
 *
 * The first SYN for this key has already been recorded and dropped. The
 * key contains the complete IPv4 or IPv6 TCP flow and initial sequence
 * number. Drop the current SYN if jtxtstamp is XFW_SYN_BLOCKED.
 *
 * Validate the retransmission against the inclusive timing window:
 *
 *     jtxtstamp + min_delay_jiff <= now <= jtxtstamp + max_delay_jiff.
 *
 * A SYN outside this window sets jtxtstamp to XFW_SYN_BLOCKED until eviction.
 *
 * For a valid retransmission, insert stage 2 state before removing the
 * stage 1 entry. Promotion counts this SYN as the first valid retry and
 * starts a new timing window at now with twice the configured max_delay.
 * If insertion fails, keep the original timestamp and drop the current SYN.
 *
 * @ctx:      packet context and TCP SYN drop configuration.
 * @drop_ctx: family-specific maps and complete TCP SYN key.
 * @entry:    stage 1 state for the key.
 *
 * Return XFW_CTX_CONTINUE after successful promotion so subsequent filters
 * can process the SYN, or XFW_CTX_DROP otherwise. Every drop in this
 * function registers an incident through XFW_MAKE_CTX_DROP[_EXT]().
 */
static __always_inline int
xfw_process_syn_stage1(const XfwGlobalCtx *ctx, const XfwSynDropCtx *drop_ctx,
		       XfwSynStage1Entry *entry)
{
	const uint64_t now = ctx->ts_jiff;
	/*
	 * The entry is permanently blocked until LRU eviction.
	 * Drop the current SYN.
	 */
	if (entry->jtxtstamp == XFW_SYN_BLOCKED)
		return XFW_MAKE_CTX_DROP(ctx, XFW_DROP_SYN_BLOCKED);

	/*
	 * The valid retransmission window is:
	 *
	 *     jtxtstamp + min_delay <= now <= jtxtstamp + max_delay
	 *
	 * Any SYN outside the window blocks the tuple until LRU eviction.
	 */
	const XfwRulesCfgTcpSynDrop *syn_cfg = &ctx->cfg->rules.tcp_syn_drop;
	if (entry->jtxtstamp + syn_cfg->min_delay_jiff > now
	    || now > entry->jtxtstamp + syn_cfg->max_delay_jiff)
	{
		entry->jtxtstamp = XFW_SYN_BLOCKED;
		return XFW_MAKE_CTX_DROP(ctx, XFW_DROP_SYN_BLOCKED);
	}

	if (!xfw_promote_syn(drop_ctx, now, syn_cfg)) {
		/*
		 * Stage 2 insertion failed, for example because this key
		 * already exists. Keep the original timestamp so a later SYN
		 * can retry validation against the original window.
		 */
		return XFW_MAKE_CTX_DROP(ctx,
					 XFW_DROP_SYN_CPU_AFFINITY_ERROR);
	}

	return XFW_CTX_CONTINUE;
}

static __always_inline bool
xfw_add_syn_stage1(const XfwSynDropCtx *drop_ctx, uint64_t now)
{
	XfwSynStage1Entry pending = {
		.jtxtstamp = now,
	};

	/*
	 * The current SYN becomes the first SYN of a new validation cycle.
	 * Remember it in the stage 1 map and deliberately drop it.
	 */
	if (bpf_map_update_elem(drop_ctx->stage1_map, drop_ctx->key, &pending,
				BPF_NOEXIST))
	{
		XFW_CTX_DBG("Failed to add SYN tuple to the syn pending table");
		return false;
	}

	return true;
}

/*
 * Process a SYN tuple which has already passed the initial retransmission
 * validation and was promoted from the stage 1 map to the stage 2 map.
 *
 * An entry in the stage 2 map means that:
 *
 *   1. the first SYN was dropped and recorded in the stage 1 map;
 *   2. a retransmitted SYN arrived within the initial valid time window:
 *
 *          stored_jiffies + min_delay <= now <= stored_jiffies + max_delay;
 *
 *   3. the tuple was removed from the stage 1 map and promoted to the
 *      stage 2 map;
 *   4. that retransmitted SYN was passed upstream.
 *
 * Further SYN retransmissions are processed as follows.
 *
 * First, check whether the tuple is currently blocked.
 *
 * There are two reasons why an entry may be blocked:
 *
 *   - a SYN arrived outside the allowed retransmission window. Such a
 *     timing violation blocks the tuple indefinitely, until the LRU map
 *     evicts the entry;
 *
 *   - `retry_count` was reached. In this case all following SYNs are
 *     blocked for `block_timeout`. A zero `block_timeout` means indefinite
 *     blocking until LRU eviction.
 *
 * A finite `block_timeout` requires the time when the block expires to be
 * stored in the stage 2 entry. Once the timeout expires, the tuple must not
 * immediately become trusted again. Its stage 2 state is removed and the
 * current SYN starts a new validation cycle as a first SYN: it is inserted
 * into the stage 1 map and dropped.
 *
 * For a non-blocked entry, validate the current SYN against the
 * retransmission window:
 *
 *          stored_jiffies + min_delay <= now <= stored_jiffies + max_delay.
 *
 * If the SYN arrives earlier than min_delay or later than max_delay, the
 * tuple is blocked indefinitely and the packet is dropped.
 *
 * If the timing is valid, count the SYN as a successful retransmission.
 * The SYN which reaches `retry_count` is still passed upstream because
 * the configuration says to block all following SYNs once `retry_count`
 * is reached. The entry is left in a state which causes the next SYN to
 * be blocked for `block_timeout`.
 *
 * If `retry_count` has not yet been reached, pass the SYN upstream and
 * prepare the entry for another possible retransmission. The protected
 * server may fail to send a SYN-ACK, therefore the next retransmission
 * must also be allowed. Use the current jiffies value as the new reference
 * time and increase `max_delay` using exponential backoff:
 *
 *          stored_jiffies = now;
 *          max_delay *= 2;
 *
 * Thus every successfully validated retransmission starts a new timing
 * window:
 *
 *          now + min_delay <= next_syn <= now + max_delay_with_backoff.
 *
 * @ctx:      packet context and TCP SYN drop configuration.
 * @drop_ctx: family-specific maps and complete TCP SYN key.
 * @entry:    stage 2 map state for the tuple.
 *
 * Return `XFW_CTX_CONTINUE` for a valid retransmitted SYN which may be
 * forwarded to upstream, or XDP_DROP when the tuple is blocked or the
 * retransmission timing is invalid.
 *
 * SYNs dropped as part of the validation algorithm itself do not represent
 * a rule violation and are returned as plain XDP_DROP.
 *
 * XFW_MAKE_CTX_DROP() is used only when the SYN tuple is actually blocked,
 * so that such drops are registered as tcp_syn_drop incidents.
 */
static __always_inline int
xfw_process_syn_stage2(const XfwGlobalCtx *ctx, const XfwSynDropCtx *drop_ctx,
		       XfwSynStage2Entry *entry)
{
	const uint64_t now = ctx->ts_jiff;
	/*
	 * The entry is permanently blocked until LRU eviction.
	 * Drop the current SYN.
	 */
	if (entry->blocked_until == XFW_SYN_BLOCKED)
		return XFW_MAKE_CTX_DROP(ctx, XFW_DROP_SYN_BLOCKED);

	/*
	 * `retry_count` may impose a finite block. Once it expires, restart
	 * validation from the current SYN instead of immediately trusting
	 * the tuple again.
	 */
	if (entry->blocked_until) {
		if (now < entry->blocked_until) {
			return XFW_MAKE_CTX_DROP_EXT(ctx, XFW_DROP_SYN_BLOCKED,
						     ": %s", "blocking timeout"
						     " has not expired");
		}

		/*
		 * The finite block has expired. Treat this SYN as the first SYN
		 * of a new validation cycle.
		 * Keep the stage 2 entry until the new stage 1 entry is
		 * successfully created. If insertion into the stage 1 map
		 * fails, deleting the stage 2 entry would lose all state for
		 * this tuple and allow the next SYN to start validation from
		 * scratch.
		 */
		if (xfw_add_syn_stage1(drop_ctx, now)) {
			bpf_map_delete_elem(drop_ctx->stage2_map,
					    drop_ctx->key);
			/*
			 * This SYN is treated as initial SYN. Initial SYNs are
			 * intentionally dropped silently as part of the normal
			 * validation flow.
			 *
			 * This is the expected first step of SYN validation,
			 * not an indication of malicious traffic.
			 */
			return XDP_DROP;
		}

		return XFW_MAKE_CTX_DROP_EXT(ctx, XFW_DROP_SYN_BLOCKED,
					     ": %s", "pending entry"
					     " already exists");
	}

	const XfwRulesCfgTcpSynDrop *syn_cfg = &ctx->cfg->rules.tcp_syn_drop;
	if (entry->jtxtstamp + syn_cfg->min_delay_jiff > now
	    || now > entry->jtxtstamp + entry->max_delay)
	{
	    	/*
		 * A SYN outside the retransmission window is permanently
		 * blocked, as required by the design.
		 */
		entry->blocked_until = XFW_SYN_BLOCKED;
		return XFW_MAKE_CTX_DROP(ctx, XFW_DROP_SYN_BLOCKED);
	}

	entry->retry_count++;
	/*
	 * The SYN that reaches `retry_count` is still passed upstream. At the
	 * same time, put the entry into the blocked state so that every
	 * following SYN is handled by the checks above and never reaches
	 * retry_count++ again.
	 *
	 * Therefore, for a valid stage 2 map entry `retry_count` cannot grow
	 * past syn_cfg->retry_count.
         */

	if (entry->retry_count == syn_cfg->retry_count) {
		/* Treat unlimited or overflowing deadlines as permanent blocks. */
		if (!syn_cfg->block_timeout_jiff
		    || XFW_SYN_BLOCKED - syn_cfg->block_timeout_jiff < now)
			entry->blocked_until = XFW_SYN_BLOCKED;
		else
			entry->blocked_until = now +
				syn_cfg->block_timeout_jiff;

		return XFW_CTX_CONTINUE;
	}

	/*
	 * The protected server may not answer with SYN-ACK, so allow another
	 * retransmission after min_delay and increase the maximum delay using
	 * exponential backoff.
	 */
	entry->max_delay = entry->max_delay * 2;
	entry->jtxtstamp = now;

	return XFW_CTX_CONTINUE;
}

static __always_inline int
xfw_process_syn_drop_state(const XfwGlobalCtx *ctx,
			   const XfwSynDropCtx *drop_ctx)
{
	XFW_ASSERT(drop_ctx->stage1_map && drop_ctx->stage2_map);

	/*
	 * Check the stage 2 map first.
	 *
	 * All tuples that have already passed the initial retransmission
	 * timing validation are promoted from the large stage 1 map to this
	 * smaller map.
 	 *
 	 * This map therefore contains legitimate TCP connection attempts that
 	 * are already in the retransmission tracking stage.
 	 *
	 * If the tuple is found here, all further processing (timing
	 * validation, retry counting and blocking) is performed by
	 * `xfw_process_syn_stage2`.
	 *
	 * Updates of the stage 1 and stage 2 maps are not atomic. The same
	 * SYN-drop key may be seen more than once due to SYN retransmissions
	 * or duplicated packets: a retransmitted SYN keeps the same addresses,
	 * ports and initial sequence number.
	 *
	 * Each CPU has independent maps. Within a CPU's maps, promotion inserts
	 * the stage 2 entry before removing the stage 1 entry.
	 *
	 * Prefer the stage 2 entry in this case, since it represents the more
	 * advanced validation state and avoids processing a stale stage 1
	 * entry.
	 */
	XfwSynStage2Entry *retry = bpf_map_lookup_elem(drop_ctx->stage2_map,
						       drop_ctx->key);
	if (retry)
		return xfw_process_syn_stage2(ctx, drop_ctx, retry);

	/*
	 * The tuple was not found in the stage 2 map, therefore either this is
	 * the first SYN we see for this TCP connection attempt, or the tuple
	 * is still waiting for the initial retransmission validation.
	 *
	 * The stage 1 map stores only the first dropped SYN together with the
	 * timestamp when it was received. A second SYN is accepted only if it
	 * arrives within the configured retransmission window. Otherwise the
	 * tuple is permanently blocked until it is evicted from the LRU map.
	 */
	XfwSynStage1Entry *pending = bpf_map_lookup_elem(drop_ctx->stage1_map,
							 drop_ctx->key);
	if (pending)
		return xfw_process_syn_stage1(ctx, drop_ctx, pending);

	if (!xfw_add_syn_stage1(drop_ctx, ctx->ts_jiff))
		return XFW_MAKE_CTX_DROP_EXT(ctx, XFW_DROP_SYN_BLOCKED,
					     ": %s", "pending entry"
					     " already exists, possibly due"
					     " to a concurrent SYN or hash"
					     " collision");

	/*
	 * Drop the initial SYN silently.
	 *
	 * This is the expected first step of SYN validation, not an indication
	 * of malicious traffic.
	 */
	return XDP_DROP;
}

static __always_inline int
tcp_syn_drop_filter(XfwGlobalCtx *ctx, struct tcphdr *th)
{
	const uint32_t cpu = bpf_get_smp_processor_id();

	if (ctx->ipver == bpf_ntohs(ETH_P_IP)) {
		XfwIpv4SynKey key;
		const XfwSynDropCtx drop_ctx = {
			.stage1_map = bpf_map_lookup_elem(
				&MAP_SYN_STAGE1_IPV4_REF, &cpu),
			.stage2_map = bpf_map_lookup_elem(
				&MAP_SYN_STAGE2_IPV4_REF, &cpu),
			.key = &key,
		};
		struct iphdr *iph4 =
			XFW_PKT_PTR(ctx, ctx->ip_off, struct iphdr);

		XFW_ASSERT((void *)(iph4 + 1) <= ctx->hdr_cur.end);

		key.flow.clnt_ip = iph4->saddr;
		key.flow.srv_ip = iph4->daddr;
		key.flow.clnt_port = th->source;
		key.flow.srv_port = th->dest;
		key.seq = th->seq;

		return xfw_process_syn_drop_state(ctx, &drop_ctx);
	} else if (ctx->ipver == bpf_ntohs(ETH_P_IPV6)) {
		XfwIpv6SynKey key;
		const XfwSynDropCtx drop_ctx = {
			.stage1_map = bpf_map_lookup_elem(
				&MAP_SYN_STAGE1_IPV6_REF, &cpu),
			.stage2_map = bpf_map_lookup_elem(
				&MAP_SYN_STAGE2_IPV6_REF, &cpu),
			.key = &key,
		};
		struct ipv6hdr *iph6 =
			XFW_PKT_PTR(ctx, ctx->ip_off, struct ipv6hdr);

		XFW_ASSERT((void *)(iph6 + 1) <= ctx->hdr_cur.end);

		memcpy(key.flow.clnt_ip, &iph6->saddr,
		       sizeof(key.flow.clnt_ip));
		memcpy(key.flow.srv_ip, &iph6->daddr, sizeof(key.flow.srv_ip));
		key.flow.clnt_port = th->source;
		key.flow.srv_port = th->dest;
		key.seq = th->seq;

		return xfw_process_syn_drop_state(ctx, &drop_ctx);
	}

	return XFW_CTX_CONTINUE;
}

#undef BANNER
#pragma pop_macro("BANNER")
