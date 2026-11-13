/**
 *	Tempesta xFW TCP Flows Tracking
 *
 * SPDX-FileCopyrightText: © 2026 Tempesta Technologies, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * The filter tracks observed TCP flows and blocks ACK and RST floods for
 * flows that are not present in the tracking map.
 *
 * Logic:
 *   - Maintain per-connection state in a shared LRU hash map.
 *   - Provide ingress filtering based on connection state.
 *   - Record flows observed on egress, including SYN packets.
 *   - Manage FIN/RST events and connection expiration.
 *
 * Modes of operation:
 *   - Supported only in host and gateway deployments. Scrubbing uses
 *     asymmetric routing and cannot observe the return traffic.
 *   - Learning mode (filter inactive or rules not loaded): TC records all
 *     observed connections to avoid breaking existing flows.
 *   - Filtering mode (filter active): TC records SYN packets, covering locally
 *     initiated connections and connections we respond to with SYN-ACK.
 *     XDP checks ingress packets against the recorded flows. For SYN cookies,
 *     XDP records the flow after successful ACK validation because the
 *     generated SYN-ACK bypasses TC.
 *
 * Notes:
 *   - Whitelisted connections may bypass XDP filters entirely and will still be
 *     added to trusted set. This is intentional to reduce processing in XDP;
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
#define BANNER "tcp-flow"
#include "log.h"

#include "filter.h"
#include "tcp_flow.h"

struct XfwTcpFlowContext {
	void		*map;
	union {
		XfwIpv4TcpFlow	ipv4;
		XfwIpv6TcpFlow	ipv6;
	} key;
};

/*
 * The flow filter distinguishes untracked connections (no XfwTcpConnState
 * entry in the map) and tracked connections (an entry exists).
 *
 * @last_fin_time_jiff	- timestamp in jiffies for the last seen FIN
 */
typedef struct XfwTcpConnState {
	uint64_t		last_fin_time_jiff; /* In jiffies */
} XfwTcpConnState;

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, XfwIpv4TcpFlow);
	__type(value, XfwTcpConnState);
	/* Pinned so ingress and egress programs share tracked TCP flows. */
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, XFW_MAX_CONCURRENT_TCP_CONNECTIONS);
} MAP_TCP_CONN_IPV4_REF SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, XfwIpv6TcpFlow);
	__type(value, XfwTcpConnState);
	/* Pinned so ingress and egress programs share tracked TCP flows. */
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, XFW_MAX_CONCURRENT_TCP_CONNECTIONS);
} MAP_TCP_CONN_IPV6_REF SEC(".maps");

/*
 * Keep a closing connection for one minute after the latest FIN observed from
 * either direction. Traffic for that tuple is still allowed until expiry.
 */
#ifndef TCP_FLOW_CONN_CLOSE_TIMEOUT_JIFF
#define TCP_FLOW_CONN_CLOSE_TIMEOUT_JIFF (60 * JIFFIES_PER_SEC)
#endif

#define TCP_FLOW_CONN_MAX_FIN_TIME_JIFF \
	(UINT64_MAX - TCP_FLOW_CONN_CLOSE_TIMEOUT_JIFF) /* Keep timeout math bounded. */

static __always_inline int
tcp_flow_init_ctx(const XfwGlobalCtx *ctx,
		  struct XfwTcpFlowContext *tcp_flow_ctx,
		  const bool is_upstream_direction)
{
	VERIFY_TRUE_OR_RETURN(ctx->l4_off <= L4_OFF_MAX, -EINVAL);
	struct tcphdr *th = XFW_PKT_PTR(ctx, ctx->l4_off, struct tcphdr);
	VERIFY_TRUE_OR_RETURN((void *)(th + 1) <= ctx->hdr_cur.end, -EINVAL);

	if (ctx->ipver == bpf_ntohs(ETH_P_IP)) {
		struct iphdr *iph4 = XFW_PKT_PTR(ctx, ctx->ip_off,
						 struct iphdr);
		VERIFY_TRUE_OR_RETURN((void *)(iph4 + 1) <= ctx->hdr_cur.end,
				      -EINVAL);

		if (is_upstream_direction) {
			tcp_flow_ctx->key.ipv4.clnt_ip = iph4->saddr;
			tcp_flow_ctx->key.ipv4.srv_ip = iph4->daddr;
			tcp_flow_ctx->key.ipv4.clnt_port = th->source;
			tcp_flow_ctx->key.ipv4.srv_port = th->dest;
		} else {
			tcp_flow_ctx->key.ipv4.clnt_ip = iph4->daddr;
			tcp_flow_ctx->key.ipv4.srv_ip = iph4->saddr;
			tcp_flow_ctx->key.ipv4.clnt_port = th->dest;
			tcp_flow_ctx->key.ipv4.srv_port = th->source;
		}

		tcp_flow_ctx->map = &MAP_TCP_CONN_IPV4_REF;

		return 0;
	} else if (ctx->ipver == bpf_ntohs(ETH_P_IPV6)) {
		struct ipv6hdr *iph6 = XFW_PKT_PTR(ctx, ctx->ip_off,
						   struct ipv6hdr);
		VERIFY_TRUE_OR_RETURN((void *)(iph6 + 1) <= ctx->hdr_cur.end,
				      -EINVAL);

		if (is_upstream_direction) {
			memcpy(tcp_flow_ctx->key.ipv6.clnt_ip, &iph6->saddr,
			       sizeof(tcp_flow_ctx->key.ipv6.clnt_ip));
			memcpy(tcp_flow_ctx->key.ipv6.srv_ip, &iph6->daddr,
			       sizeof(tcp_flow_ctx->key.ipv6.srv_ip));
			tcp_flow_ctx->key.ipv6.clnt_port = th->source;
			tcp_flow_ctx->key.ipv6.srv_port = th->dest;
		} else {
			memcpy(tcp_flow_ctx->key.ipv6.clnt_ip, &iph6->daddr,
			       sizeof(tcp_flow_ctx->key.ipv6.clnt_ip));
			memcpy(tcp_flow_ctx->key.ipv6.srv_ip, &iph6->saddr,
			       sizeof(tcp_flow_ctx->key.ipv6.srv_ip));
			tcp_flow_ctx->key.ipv6.clnt_port = th->dest;
			tcp_flow_ctx->key.ipv6.srv_port = th->source;
		}

		tcp_flow_ctx->map = &MAP_TCP_CONN_IPV6_REF;

		return 0;
	}

	return -EPROTO;
}

static __always_inline XfwTcpConnState *
tcp_flow_conn_lookup(void *map, const void *key)
{
	return bpf_map_lookup_elem(map, key);
}

static __always_inline void
tcp_flow_conn_delete(void *map, const void *key)
{
	bpf_map_delete_elem(map, key);
	XFW_CTX_DBG("Delete tracked TCP flow");
}

static __always_inline void
__tcp_flow_conn_add(void *map, const void *key)
{
	XfwTcpConnState new_conn = {
		.last_fin_time_jiff = TCP_FLOW_CONN_MAX_FIN_TIME_JIFF
	};

	bpf_map_update_elem(map, key, &new_conn, BPF_ANY);
	XFW_CTX_DBG("Add tracked TCP flow");
}

static __always_inline void
tcp_flow_conn_add(const XfwGlobalCtx *ctx)
{
	struct XfwTcpFlowContext flow_ctx;

	if (unlikely(tcp_flow_init_ctx(ctx, &flow_ctx, true)))
		return;

	__tcp_flow_conn_add(flow_ctx.map, &flow_ctx.key);
}

static __always_inline void
tcp_flow_conn_set_fin_time(XfwTcpConnState *conn, uint64_t fin_time_jiff)
{
	WRITE_ONCE(conn->last_fin_time_jiff, fin_time_jiff);
	XFW_CTX_DBG("FIN timer updated to %llu", fin_time_jiff);
}

static __always_inline bool
tcp_flow_is_conn_outdated(const XfwGlobalCtx *ctx, const XfwTcpConnState *conn)
{
	return READ_ONCE(conn->last_fin_time_jiff) + TCP_FLOW_CONN_CLOSE_TIMEOUT_JIFF <
	       ctx->ts_jiff;
}

static __always_inline bool
tcp_flow_has_conn(const XfwGlobalCtx *ctx)
{
	struct XfwTcpFlowContext flow_ctx;

	if (unlikely(tcp_flow_init_ctx(ctx, &flow_ctx, true)))
		return true;

	XfwTcpConnState *conn = tcp_flow_conn_lookup(flow_ctx.map,
						     &flow_ctx.key);

	if (!conn || tcp_flow_is_conn_outdated(ctx, conn))
		return false;

	return true;
}

enum XfwTcpFlowEvent {
	TCP_FLOW_EVENT_NORMAL,
	TCP_FLOW_EVENT_RST,
	TCP_FLOW_EVENT_FIN,
};

/**
 * Allows traffic only for TCP flows that are already present in the
 * connection tracking map.
 *
 * Once a flow is recorded (for example, after observing its initial SYN),
 * it is treated as valid. There is no additional verification - the presence
 * of an entry is enough. This is sufficient to cut off unsolicited packets like
 * random RST/ACK floods that don't match any known flow.
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
tcp_flow_conn_ingress_filter(const XfwGlobalCtx *ctx, enum XfwTcpFlowEvent ev)
{
	struct XfwTcpFlowContext flow_ctx;

	if (deployment_mode == XFW_MODE_SCRUBBER
	    || unlikely(!ctx->cfg->rules.tcp_flow.enabled))
		return XFW_CTX_CONTINUE;

	if (unlikely(tcp_flow_init_ctx(ctx, &flow_ctx, true)))
		return XFW_CTX_CONTINUE;

	XfwTcpConnState *conn = tcp_flow_conn_lookup(flow_ctx.map,
						     &flow_ctx.key);
	if (likely(!(conn))) /* Fast path for untracked flood traffic. */
		return XFW_MAKE_CTX_DROP(ctx, XFW_DROP_TCP_FLOW_FAILED);

	if (unlikely(tcp_flow_is_conn_outdated(ctx, (conn)))) {
		tcp_flow_conn_delete(flow_ctx.map, &flow_ctx.key);
		return XFW_MAKE_CTX_DROP(ctx, XFW_DROP_TCP_FLOW_TIMEOUT);
	}

	switch (ev) {
	case TCP_FLOW_EVENT_RST:
		/*
		 * Out-of-order traffic: early RST clears the connection,
		 * mirroring TCP stack behavior.
		 */
		tcp_flow_conn_delete(flow_ctx.map, &flow_ctx.key);
		return XFW_CTX_CONTINUE;

	case TCP_FLOW_EVENT_FIN:
		tcp_flow_conn_set_fin_time(conn, ctx->ts_jiff);
		return XFW_CTX_CONTINUE;

	case TCP_FLOW_EVENT_NORMAL:
	default:
		return XFW_CTX_CONTINUE;
	}
}

static __always_inline void
tcp_flow_conn_egress_learning(const XfwGlobalCtx *ctx,
			      bool is_upstream_direction)
{
	if (deployment_mode == XFW_MODE_SCRUBBER)
		return;

	struct XfwTcpFlowContext flow_ctx;
	VERIFY_TRUE_OR_RETURN(ctx->l4_off <= L4_OFF_MAX, (void)0);
	struct tcphdr *th = XFW_PKT_PTR(ctx, ctx->l4_off, struct tcphdr);
	VERIFY_TRUE_OR_RETURN((void *)(th + 1) <= ctx->hdr_cur.end, (void)0);

	if (unlikely(tcp_flow_init_ctx(ctx, &flow_ctx, is_upstream_direction)))
		return;

	if (unlikely(th->rst)) {
		/* An early RST can safely remove a learned tuple. */
		tcp_flow_conn_delete(flow_ctx.map, &flow_ctx.key);
		return;
	}

	XfwTcpConnState *conn = tcp_flow_conn_lookup(flow_ctx.map,
						     &flow_ctx.key);

	/*
	 * Flow tracking in tc.c has two modes:
	 *
	 * 1. Operational mode when the flow filter is active:
	 *    - All packets containing SYN are added to the trusted set in tc.c.
	 *    - This covers connections initiated locally or connections we
	 *      respond to with SYN-ACK, which have already passed xdp.c.
	 *
	 * 2. Learning mode when the flow filter is inactive (or rules not loaded):
	 *    - Adds all observed connections to the trusted set regardless of
-        *      SYN/ACK flags.
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
		if (unlikely(!ctx->cfg->rules.tcp_flow.enabled || th->syn))
			__tcp_flow_conn_add(flow_ctx.map, &flow_ctx.key);
		return;
	}

	if (unlikely(th->fin)) {
		tcp_flow_conn_set_fin_time(conn, ctx->ts_jiff);
		return;
	}

	/* If the close grace period expired, clamp the state back to max age. */
	if (unlikely(tcp_flow_is_conn_outdated(ctx, conn)))
		tcp_flow_conn_set_fin_time(conn, TCP_FLOW_CONN_MAX_FIN_TIME_JIFF);
}

#undef BANNER
#pragma pop_macro("BANNER")
