/**
 *	Tempesta xFW TCP SYN flood protection implementation
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

#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "compiler.h"
#include "filter.h"
#include "syn_hash.h"
#include "ctx.h"

#define XFW_SYN_PENDING_MAX_ENTRIES	10000000
#define XFW_SYN_RETRY_MAX_ENTRIES	1000000

/*
 * The first map stores SYN tuples which have not yet passed the initial
 * retransmission timing check.
 *
 * A blocked entry remains blocked until the LRU map evicts it.
 */
typedef struct XfwSynPending {
	uint64_t	jtxtstamp;
	bool		blocked;
} XfwSynPending;

/*
 * The second map stores tuples which have already passed the first timing
 * check and whose following SYN retransmissions are being tracked.
 */
typedef struct XfwSynRetry {
	uint64_t	jtxtstamp;
	uint64_t	max_delay;
	uint64_t	blocked_until;
	uint32_t	retry_count;
	bool		blocked;
} XfwSynRetry;

/*
 * First-stage map:
 *
 *   first SYN              -> insert and drop
 *   valid retransmission   -> move to retry map and pass
 *   invalid retransmission -> block until LRU eviction
 */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, XFW_SYN_PENDING_MAX_ENTRIES);
	__type(key, uint64_t);
	__type(value, XfwSynPending);
} MAP_SYN_PENDING_REF SEC(".maps");

/*
 * Second-stage map:
 *
 * The smaller map is isolated from the large pending map so that a flood
 * with random tuples cannot directly evict all validated connections.
 */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, XFW_SYN_RETRY_MAX_ENTRIES);
	__type(key, uint64_t);
	__type(value, XfwSynRetry);
} MAP_SYN_RETRY_REF SEC(".maps");

static __always_inline bool
xfw_is_valid_initial_syn(const struct tcphdr *th)
{
	return th->syn && !th->ack && !th->rst && !th->fin;
}

static __always_inline void
xfw_hash_ipv4_syn(const struct iphdr *ipv4, const struct tcphdr *th,
		  uint64_t salt, uint64_t *hash)
{
	XfwIpv4SynTuple tuple;

	tuple.src_ip = ipv4->saddr;
	tuple.dst_ip = ipv4->daddr;
	tuple.seq = th->seq;
	tuple.sport = th->source;
	tuple.dport = th->dest;

	*hash = syn_xxh64_ipv4(&tuple, salt);
}

static __always_inline void
xfw_hash_ipv6_syn(const struct ipv6hdr *ipv6,
		  const struct tcphdr *th,
		  uint64_t salt, uint64_t *hash)
{
	XfwIpv6SynTuple tuple;

	__builtin_memcpy(tuple.src_ip, &ipv6->saddr, sizeof(tuple.src_ip));
	__builtin_memcpy(tuple.dst_ip, &ipv6->daddr, sizeof(tuple.dst_ip));

	tuple.seq = th->seq;
	tuple.sport = th->source;
	tuple.dport = th->dest;

	*hash = syn_xxh64_ipv6(&tuple, salt);
}

/*
 * Return values:
 *
 *   0  - initial SYN was parsed and hashed;
 *   1  - packet is not an initial SYN;
 *  -1  - packet headers are truncated or invalid.
 */


/*
 * Move a tuple from the large pending map to the smaller validated map.
 *
 * The new entry is inserted first. This way a map insertion failure does
 * not remove the only existing protection state.
 */
static __always_inline int
xfw_promote_syn(uint64_t hash, uint64_t now,
		const XfwRulesCfgTcpSynDrop *cfg)
{
	XfwSynRetry retry = {
		.jtxtstamp = now,
		.max_delay = cfg->max_delay_jiff,
		.blocked_until = 0,
		.blocked = false,
	};

	if (bpf_map_update_elem(&MAP_SYN_RETRY_REF, &hash, &retry,
				BPF_ANY))
	{
		XFW_CTX_DBG("Failed to add SYN tuple to the syn retry table");
		return XDP_DROP;
	}

	bpf_map_delete_elem(&MAP_SYN_PENDING_REF, &hash);

	return XFW_CTX_CONTINUE;
}

/**
 * Process a SYN tuple stored in the pending map.
 *
 * A pending-map entry represents a tuple for which the first SYN has
 * already been observed, recorded and deliberately dropped.
 *
 * The purpose of the pending map is to validate the first TCP
 * retransmission before allowing the connection attempt to continue.
 *
 * Processing is performed as follows.
 *
 * First, check whether the tuple has already been permanently blocked.
 * A pending entry becomes blocked when a retransmitted SYN arrives
 * outside the allowed timing window. Such entries remain blocked until
 * they are evicted from the LRU map.
 *
 * The retransmission timing is then validated against the initial
 * retransmission window:
 *
 *      stored_jiffies + time_min <= now <= stored_jiffies + max_delay.
 *
 * If the retransmitted SYN arrives earlier than time_min or later than
 * max_delay, the tuple is permanently blocked and the SYN is dropped.
 *
 * Otherwise the retransmission is considered valid. The tuple is removed
 * from the pending map, promoted to the retry map and the current SYN is
 * passed upstream.
 *
 * Promotion initializes the retry state, allowing further SYN
 * retransmissions to be tracked using exponential backoff and
 * retry_count.
 *
 * Return XFW_CTX_CONTINUE when the retransmitted SYN is valid and the tuple is
 * successfully promoted to the retry map, or XDP_DROP when the tuple is
 * blocked, the retransmission timing is invalid, or promotion fails.
 *
 * SYNs dropped as part of the validation algorithm itself do not represent
 * a rule violation and are returned as plain XDP_DROP.
 *
 * XFW_MAKE_CTX_DROP() is used only when the SYN tuple is actually blocked,
 * so that such drops are registered as tcp_syn_drop incidents.
 */
static __always_inline int
xfw_process_pending(XfwGlobalCtx *ctx, uint64_t hash, XfwSynPending *entry,
		    uint64_t now, const XfwRulesCfgTcpSynDrop *cfg)
{
	if (entry->blocked)
		return XFW_MAKE_CTX_DROP(ctx, XFW_DROP_SYN_BLOCKED);
	/*
	 * The valid retransmission window is:
	 *
	 *     jtxtstamp + time_min <= now <= jtxtstamp + max_delay
	 *
	 * Any SYN outside the window blocks the tuple until LRU eviction.
	 */
	if (entry->jtxtstamp + cfg->time_min_jiff > now
	    || now > entry->jtxtstamp + cfg->max_delay_jiff)
	{
		entry->blocked = true;
		return XFW_MAKE_CTX_DROP(ctx, XFW_DROP_SYN_BLOCKED);
	}

	return xfw_promote_syn(hash, now, cfg);
}

static __always_inline bool
xfw_start_validation(uint64_t hash, uint64_t now)
{
	XfwSynPending pending = {
		.jtxtstamp = now,
		.blocked = false,
	};

	/*
	 * The current SYN becomes the first SYN of a new validation cycle.
	 * Remember it in the pending map and deliberately drop it.
	 */
	if (bpf_map_update_elem(&MAP_SYN_PENDING_REF, &hash,
				&pending, BPF_ANY)) {
		XFW_CTX_DBG("Failed to add SYN tuple to the syn pending table");
		return false;
	}

	return true;
}

/**
 * Process a SYN tuple which has already passed the initial retransmission
 * validation and was promoted from the pending map to the retry map.
 *
 * An entry in the retry map means that:
 *
 *   1. the first SYN was dropped and recorded in the pending map;
 *   2. a retransmitted SYN arrived within the initial valid time window:
 *
 *          stored_jiffies + time_min <= now <= stored_jiffies + max_delay;
 *
 *   3. the tuple was removed from the pending map and promoted to the
 *      retry map;
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
 * stored in the retry entry. Once the timeout expires, the tuple must not
 * immediately become trusted again. Its retry state is removed and the
 * current SYN starts a new validation cycle as a first SYN: it is inserted
 * into the pending map and dropped.
 *
 * For a non-blocked entry, validate the current SYN against the
 * retransmission window:
 *
 *          stored_jiffies + time_min <= now <= stored_jiffies + max_delay.
 *
 * If the SYN arrives earlier than time_min or later than max_delay, the
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
 *          now + time_min <= next_syn <= now + max_delay_with_backoff.
 *
 * @hash:  salted hash of the complete TCP SYN tuple
 *         <src_ip, dst_ip, src_port, dst_port, initial_seqno>.
 * @entry: retry-map state for the tuple.
 * @now:   current jiffies value.
 * @cfg:   TCP SYN drop filter configuration.
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
xfw_process_retry(XfwGlobalCtx *ctx, uint64_t hash, XfwSynRetry *entry,
		  uint64_t now, const XfwRulesCfgTcpSynDrop *cfg)
{
	/*
	 * A timing violation blocks the tuple indefinitely, until LRU
	 * eviction.
	 */
	if (entry->blocked) 
		return XFW_MAKE_CTX_DROP(ctx, XFW_DROP_SYN_BLOCKED);

	/*
	 * `retry_count` may impose a finite block. Once it expires, restart
	 * validation from the current SYN instead of immediately trusting
	 * the tuple again.
	 */
	if (entry->blocked_until) {
		if (now < entry->blocked_until)
			return XFW_MAKE_CTX_DROP(ctx, XFW_DROP_SYN_BLOCKED,
						 "blocking timeout has not expired");

		/*
		 * The finite block has expired. Treat this SYN as the first SYN
		 * of a new validation cycle. Remove the retry state only after
		 * successfully inserting the tuple into the pending map.
		 */
		if (xfw_start_validation(hash, now))
			bpf_map_delete_elem(&MAP_SYN_RETRY_REF, &hash);

		return XDP_DROP;
	}

	if (entry->jtxtstamp + cfg->time_min_jiff > now
	    || now > entry->jtxtstamp + entry->max_delay)
	{
	    	/*
		 * A SYN outside the retransmission window is permanently
		 * blocked, as required by the design.
		 */
		entry->blocked = true;
		return XFW_MAKE_CTX_DROP(ctx, XFW_DROP_SYN_BLOCKED);
	}

	entry->retry_count++;

	/*
	 * The SYN that reaches `retry_count` is still passed upstream. At the
 	 * same time, put the entry into the blocked state so that every
	 * following SYN is handled by the checks above and never reaches
	 * retry_count++ again.
	 *
	 * Therefore, for a valid retry-map entry `retry_count` cannot grow past
	 * cfg->retry_count.
	 */
	if (entry->retry_count == cfg->retry_count) {
		if (cfg->block_timeout_jiff) {
			entry->blocked_until =
				now + cfg->block_timeout_jiff;
		} else {
			entry->blocked = true;	
		}
		return XFW_CTX_CONTINUE;
	}

	/*
	 * The protected server may not answer with SYN-ACK, so allow another
	 * retransmission after time_min and increase the maximum delay using
	 * exponential backoff.
	 */
	entry->max_delay = entry->max_delay * 2;
	entry->jtxtstamp = now;

	return XFW_CTX_CONTINUE;
}


static __always_inline int
tcp_syn_drop_filter(XfwGlobalCtx *ctx)
{
	const XfwRulesCfgTcpSynDrop *syn_cfg = &ctx->cfg->rules.tcp_syn_drop;
	XfwSynPending *pending;
	XfwSynRetry *retry;
	uint64_t hash;
	
	if (!xfw_is_valid_initial_syn(ctx->th))
		return XFW_CTX_CONTINUE;

	if (ctx->ipver == bpf_ntohs(ETH_P_IP)) {
		xfw_hash_ipv4_syn(ctx->iph4, ctx->th, syn_cfg->hash_salt,
				  &hash);
	} else if (ctx->ipver == bpf_ntohs(ETH_P_IPV6)) {
		XFW_ASSERT((void *)(ctx->iph6 + 1) <= ctx->hdr_cur.end);
		xfw_hash_ipv6_syn(ctx->iph6, ctx->th, syn_cfg->hash_salt,
				  &hash);
	} else {
		return XFW_CTX_CONTINUE;
	}

	/*
	 * Check the retry map first.
	 *
	 * All tuples that have already passed the initial retransmission
	 * timing validation are promoted from the large pending map to this
	 * smaller map.
 	 *
 	 * This map therefore contains legitimate TCP connection attempts that
 	 * are already in the retransmission tracking stage. It has higher
 	 * priority than the pending map because an entry must never exist in
 	 * both maps at the same time.
	 *
	 * If the tuple is found here, all further processing (timing
	 * validation, retry counting and blocking) is performed by
	 * `xfw_process_retry`.
	 */
	retry = bpf_map_lookup_elem(&MAP_SYN_RETRY_REF, &hash);
	if (retry)
		return xfw_process_retry(ctx, hash, retry, ctx->ts_jiff,
					 syn_cfg);
	
	/*
	 * The tuple was not found in the retry map, therefore either this is
	 * the first SYN we see for this TCP connection attempt, or the tuple
	 * is still waiting for the initial retransmission validation.
	 *
	 * The pending map stores only the first dropped SYN together with the
	 * timestamp when it was received. A second SYN is accepted only if it
	 * arrives within the configured retransmission window. Otherwise the
	 * tuple is permanently blocked until it is evicted from the LRU map.
	 */
	pending = bpf_map_lookup_elem(&MAP_SYN_PENDING_REF, &hash);
	if (pending)
		return xfw_process_pending(ctx, hash, pending, ctx->ts_jiff,
					   syn_cfg);

	xfw_start_validation(hash, ctx->ts_jiff);

	return XDP_DROP;
}

#undef BANNER
#pragma pop_macro("BANNER")
