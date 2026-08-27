/**
 *	Tempesta xFW TCP connection tracking and authentication filtering
 *
 * SPDX-FileCopyrightText: © 2026 Tempesta Technologies, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * The filter blocks ACK and RST floods for TCP flows, which it didn't observe
 * SYN packets for (authenticated flows).
 *
 * Logic:
 *   - Maintain per-connection state in a shared LRU hash map.
 *   - Provide ingress filtering based on connection state.
 *   - Handle egress connection tracking, including SYN-based trust.
 *   - Manage FIN/RST events and connection expiration.
 *
 * Modes of operation:
 *   - Learning mode (TCP AUTH filter is not active / rules not loaded): TC
 *     temporarily trusts and records all observed connections to avoid breaking
 *     existing flows.
 *   - Normal/trusted mode (TCP AUTH filter is active): TC adds all SYN packets
 *     to the trusted set, covering either locally initiated connections or
 *     connections we respond to with SYN-ACK (which have passed XDP
 *     authentication). XDP handles authentication and direct responses (e.g.,
 *     SYN cookies), and in the specific case of SYN cookies, XDP itself adds
 *     the connection to the trusted set.
  *
 * Notes:
 *   - Whitelisted connections may bypass XDP filters entirely and will still be
 *     added to TC’s trusted set. This is intentional to reduce processing in XDP;
 *     traffic volume from whitelisted connections is expected to be low.
 *   - Expiration is lazy; LRU map handles removal on access.
 *   - TC is less loaded than XDP and is leveraged for trusted connection
 *     tracking whenever possible.
 *   - Thanks to always-on learning mode, even when the filter is inactive, it's
 *     possible to enable the filter during active TCP flows.
 *   - We 'authenticate' connections at the beginning of SYN flood - this case
 *     is handled with SYN cookies/rate limit.
 *   - This file is meant for BPF programs; userspace access is not used.
 */
#pragma once

#include "vmlinux.h"

#pragma push_macro("BANNER")
#undef BANNER
#define BANNER "tcp-auth"
#include "log.h"

#include "filter.h"

/*
 * For TCP Authentication Filter there are only 2 states for a connection:
 * unauthenticated (no XfwTcpConnState entry in the map) and authenticated
 * (a map entry exists).
 *
 * @last_fin_time_jiff	- timestamp in jiffies for the last seen FIN
 */
typedef struct XfwTcpConnState {
	uint64_t		last_fin_time_jiff; /* In jiffies */
} XfwTcpConnState;

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, XfwTcpConnAddr);
	__type(value, XfwTcpConnState);
	/* Pinned so ingress and egress programs share authenticated sockets. */
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, XFW_MAX_CONCURRENT_TCP_CONNECTIONS);
} MAP_TCP_CONN_REF SEC(".maps");

/*
 * Keep a closing connection for one minute after the latest FIN observed from
 * either direction. New traffic for that tuple is still trusted until expiry.
 */
#ifndef TCP_AUTH_CONN_CLOSE_TIMEOUT_JIFF
#define TCP_AUTH_CONN_CLOSE_TIMEOUT_JIFF 60 * JIFFIES_PER_SEC
#endif

#define TCP_AUTH_CONN_MAX_FIN_TIME_JIFF \
	(UINT64_MAX - TCP_AUTH_CONN_CLOSE_TIMEOUT_JIFF) /* Keep timeout math bounded. */

static __always_inline XfwTcpConnState *
tcp_auth_conn_lookup(const XfwTcpConnAddr *addr)
{
	return bpf_map_lookup_elem(&MAP_TCP_CONN_REF, addr);
}

static __always_inline void
tcp_auth_conn_delete(const XfwTcpConnAddr *addr)
{
	bpf_map_delete_elem(&MAP_TCP_CONN_REF, addr);
	XFW_CTX_DBG("Delete TCP AUTH connection");
}

static __always_inline void
tcp_auth_conn_add(const XfwTcpConnAddr *addr)
{
	XfwTcpConnState new_conn = {
		.last_fin_time_jiff = TCP_AUTH_CONN_MAX_FIN_TIME_JIFF
	};

	bpf_map_update_elem(&MAP_TCP_CONN_REF, addr, &new_conn, BPF_ANY);
	XFW_CTX_DBG("Add TCP AUTH connection");
}

static __always_inline void
tcp_auth_conn_set_fin_time(XfwTcpConnState *conn, uint64_t fin_time_jiff)
{
	WRITE_ONCE(conn->last_fin_time_jiff, fin_time_jiff);
	XFW_CTX_DBG("FIN timer updated to %llu", fin_time_jiff);
}

static __always_inline bool
tcp_auth_is_conn_outdated(const XfwGlobalCtx *ctx, const XfwTcpConnState *conn)
{
	return READ_ONCE(conn->last_fin_time_jiff) + TCP_AUTH_CONN_CLOSE_TIMEOUT_JIFF <
	       ctx->ts_jiff;
}

static __always_inline bool
tcp_auth_has_conn_trusted(const XfwGlobalCtx *ctx, const XfwTcpConnAddr *addr)
{
	XfwTcpConnState *conn = tcp_auth_conn_lookup(addr);

	if (!conn || tcp_auth_is_conn_outdated(ctx, conn))
		return false;

	return true;
}

enum XfwTcpAuthEvent {
	TCP_AUTH_EVENT_NORMAL,
	TCP_AUTH_EVENT_RST,
	TCP_AUTH_EVENT_FIN,
};

/**
 * Allows traffic only for TCP flows that are already present in the
 * connection tracking map.
 *
 * The notion of "auth" here is purely state-driven: once a flow is recorded
 * (for example, after observing its initial SYN), it is treated as valid.
 * There is no additional verification — the presence of an entry is enough.
 * This is sufficient to cut off unsolicited packets like random RST/ACK
 * floods that don't match any known flow.
 *
 * If a lookup misses, the packet is dropped right away (fast path for
 * attack traffic). If a match is found but the entry has expired, it is
 * removed and the packet is also rejected.
 *
 * Expiration is handled lazily. Because the map uses LRU semantics, we don't
 * walk and purge old entries proactively. Removals happen only on access,
 * keeping the per-packet cost minimal.
 */
static __always_inline int
tcp_auth_conn_ingress_filter(const XfwGlobalCtx *ctx, enum XfwTcpAuthEvent ev)
{
	if (unlikely(!ctx->cfg->rules.tcp_auth.enabled))
		return XFW_CTX_CONTINUE;

	XfwTcpConnState *conn = tcp_auth_conn_lookup(&ctx->addr);
	if (likely(!(conn))) /* Fast path for unauthenticated flood traffic. */
		return XFW_MAKE_CTX_DROP(ctx, XFW_DROP_TCP_AUTH_FAILED);

	if (unlikely(tcp_auth_is_conn_outdated(ctx, (conn)))) {
		tcp_auth_conn_delete(&ctx->addr);
		return XFW_MAKE_CTX_DROP(ctx, XFW_DROP_TCP_AUTH_TIMEOUT);
	}

	switch (ev) {
	case TCP_AUTH_EVENT_RST:
		/*
		 * Out-of-order traffic: early RST clears the connection,
		 * mirroring TCP stack behavior.
		 */
		tcp_auth_conn_delete(&ctx->addr);
		return XFW_CTX_CONTINUE;

	case TCP_AUTH_EVENT_FIN:
		tcp_auth_conn_set_fin_time(conn, ctx->ts_jiff);
		return XFW_CTX_CONTINUE;

	case TCP_AUTH_EVENT_NORMAL:
	default:
		return XFW_CTX_CONTINUE;
	}
}

static __always_inline void
tcp_auth_conn_egress_learning(const XfwGlobalCtx *ctx)
{
	struct tcphdr *th = ctx->th;
	VERIFY_TRUE_OR_RETURN((void *)(th + 1) <= ctx->hdr_cur.end, (void)0);

	if (unlikely(th->rst)) {
		/* An early RST can safely remove a learned tuple. */
		tcp_auth_conn_delete(&ctx->addr);
		return;
	}

	XfwTcpConnState *conn = tcp_auth_conn_lookup(&ctx->addr);

	/*
	 * Trusted connection tracking in tc.c has two modes:
	 *
	 * 1. Operational mode when TCP AUTH filter is active:
	 *    - All packets containing SYN are added to the trusted set in tc.c.
	 *    - This covers connections initiated locally or connections we
	 *      respond to with SYN-ACK, which have already passed xdp.c.
	 *
	 * 2. Learning mode when TCP AUTH filter is inactive (or rules are not
	 *    loaded):
	 *    - Adds all observed connections to the trusted set regardless of 
	 *      SYN/ACK flags.
	 *    - This ensures that traffic from pre-existing connections is not
	 *      disrupted while the filter is inactive.
	 *
	 * Trade-offs:
	 *    - Whitelisted connections that bypass xdp.c entirely will still be
	 *      added to the trusted set. This can grow the connection cache,
	 *      but is done intentionally to reduce processing time for SYN
	 *      packets. The number of whitelisted connections is expected to be
	 *      low, so cache growth should remain manageable.
	 */
	if (!conn) {
		if (unlikely(!ctx->cfg->rules.tcp_auth.enabled || th->syn))
			tcp_auth_conn_add(&ctx->addr);
		return;
	}

	if (unlikely(th->fin)) {
		tcp_auth_conn_set_fin_time(conn, ctx->ts_jiff);
		return;
	}

	/* If the close grace period expired, clamp the state back to max age. */
	if (unlikely(tcp_auth_is_conn_outdated(ctx, conn)))
		tcp_auth_conn_set_fin_time(conn, TCP_AUTH_CONN_MAX_FIN_TIME_JIFF);
}

#undef BANNER
#pragma pop_macro("BANNER")
