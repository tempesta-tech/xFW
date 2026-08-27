/**
 *	Tempesta xFW ingress eBPF/XDP processing
 *
 * SPDX-FileCopyrightText: © 2026 Tempesta Technologies, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#define BPF_PROGRAM
#define XFW_XDP
#define BANNER "xdp"

#include "vmlinux.h"
#include "../bpf_uapi/supported_protocols.h"

#include "ctx.h"
#include "dns.h"
#include "dst.h"
#include "filter.h"
#include "parsing_helpers.h"
#include "tcp_anomaly_filter.h"
#include "tcp_auth.h"
#include "tcp_syncookies.h"

#define SHADOW_SRC_IP_MAP(basename, key_t)				\
	SHADOW_MAP(basename, BPF_MAP_TYPE_LPM_TRIE, XFW_MAX_SRC_IP_RULES, \
		    key_t, XfwSrcRule, BPF_F_NO_PREALLOC)

/*
 * Keep transport-specific source rule maps. Carrying the L4 protocol in every
 * LPM key would enlarge all entries and make trie lookups harder to audit.
 */
SHADOW_SRC_IP_MAP(MAP_SRC_4_UDP_BASENAME, XfwIpv4LpmKey);
SHADOW_SRC_IP_MAP(MAP_SRC_4_TCP_BASENAME, XfwIpv4LpmKey);
SHADOW_SRC_IP_MAP(MAP_SRC_6_UDP_BASENAME, XfwIpv6LpmKey);
SHADOW_SRC_IP_MAP(MAP_SRC_6_TCP_BASENAME, XfwIpv6LpmKey);

/* Port rule keys are dense enough that an array map may be worth testing. */
SHADOW_MAP(MAP_SRC_P_UDP_BASENAME, BPF_MAP_TYPE_HASH, XFW_MAX_PORTS, XfwPort,
	    XfwSrcRule, 0);
SHADOW_MAP(MAP_SRC_P_TCP_BASENAME, BPF_MAP_TYPE_HASH, XFW_MAX_PORTS, XfwPort,
	    XfwSrcRule, 0);
SHADOW_MAP(MAP_ICMP_BASENAME, BPF_MAP_TYPE_HASH, XFW_MAX_ICMP_RULES, XfwIcmpKey,
	    XfwActionRule, 0);

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, XfwIp); /* IPv4/6 address */
	__type(value, XfwRLimitSlidingWindow);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, XFW_MAX_SRC_RATE_LIMITER_BUCKETS);
} MAP_SRC_RATELIM_REF SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __be16); /* ports */
	__type(value, XfwRLimitSlidingWindow);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, XFW_MAX_PORTS);
} MAP_SRC_PORT_RL_REF SEC(".maps");

#define XFW_MAP_LOOKUP_OR_INIT(m, k, val_t)				\
({									\
	void *r = bpf_map_lookup_elem(m, k);				\
	if (unlikely(!r)) {						\
		val_t _z = {};						\
		bpf_map_update_elem(m, k, &_z, BPF_NOEXIST);		\
		r = bpf_map_lookup_elem(m, k);				\
	}								\
	r;								\
})

static __always_inline bool
is_metadata_creation_necessary(const XfwGlobalCtx *ctx)
{
	return ctx->cfg->rules.dns.enabled;
}

static __always_inline int
create_metadata(XfwGlobalCtx *ctx, struct xdp_md *xdp)
{
	const int pm_sz = sizeof(XfwPacketMetadata);

	if (!is_metadata_creation_necessary(ctx))
		return XFW_CTX_CONTINUE;

	if (unlikely(bpf_xdp_adjust_meta(xdp, -pm_sz)))
		return XFW_MAKE_CTX_PASS(ctx, XFW_METADATA_CREATION_FAILED);

	/* After adjusting of metadata all pointers to packet may be invalidated */
	INIT_CURSOR_FROM_BPF_CONTEXT(xdp, &ctx->hdr_cur);

	return XFW_CTX_CONTINUE;
}

static __always_inline uint8_t
icmp_default_by_proto(uint8_t l4_proto)
{
	if (l4_proto == IPPROTO_ICMP) {
		return XFW_DEFAULT_ICMP_IP4;
	} else {
		/* key->proto == IPPROTO_ICMPV6 */
		return XFW_DEFAULT_ICMP_IP6;
	}
}

static __always_inline int
icmp_filter(const XfwGlobalCtx *ctx, const XfwIcmpKey *key)
{
	XfwActionRule *rule;

	rule = bpf_map_lookup_elem(
		SELECT_SHADOW_MAP(MAP_ICMP_BASENAME, ctx->cfg->amap_icmp), key);
	if (!rule) {
		uint8_t icmp_default = icmp_default_by_proto(key->proto);

		XfwActionRule *default_rule = &ctx->cfg->rules.defaults[icmp_default];
		switch (default_rule->action) {
		case XFW_ACTION_BLOCK:
			return XFW_MAKE_CTX_DROP(ctx, XFW_DROP_ICMP_DEFAULT_BLOCKED);
		case XFW_ACTION_ALLOW:
			return XFW_CTX_CONTINUE;
		default:
			/* XFW_ACTION_RATE_LIMIT */
			XFW_ASSERT(default_rule->action == XFW_ACTION_RATE_LIMIT);
			if (xfw_is_allowed_by_rlimits(ctx, &default_rule->rlimit))
				return XFW_CTX_CONTINUE;

			return XFW_MAKE_CTX_DROP(ctx, XFW_DROP_ICMP_DEFAULT_RATE_LIMITED);
		}
	}

	if (rule->action == XFW_ACTION_BLOCK)
		return XFW_MAKE_CTX_DROP(ctx, XFW_DROP_ICMP_BLOCKED);

	if (rule->action == XFW_ACTION_ALLOW)
		return XFW_CTX_CONTINUE;

	XFW_ASSERT(rule->action == XFW_ACTION_RATE_LIMIT);
	if (xfw_is_allowed_by_rlimits(ctx, &rule->rlimit))
		return XFW_CTX_CONTINUE;

	return XFW_MAKE_CTX_DROP(ctx, XFW_DROP_ICMP_RATE_LIMITED);
}

static __always_inline uint8_t
src_port_default_by_protos(uint16_t ipver, uint8_t l4_proto)
{
	if (ipver == bpf_ntohs(ETH_P_IP)) {
		if (l4_proto == XFW_L4_PROTO_TCP) {
			return XFW_DEFAULT_SRC_PORT_TCP_IP4;
		} else {
			/* XFW_L4_PROTO_UDP */
			return XFW_DEFAULT_SRC_PORT_UDP_IP4;
		}
	} else {
		/* ETH_P_IPV6 */
		if (l4_proto == XFW_L4_PROTO_TCP) {
			return XFW_DEFAULT_SRC_PORT_TCP_IP6;
		} else {
			/* XFW_L4_PROTO_UDP */
			return XFW_DEFAULT_SRC_PORT_UDP_IP6;
		}
	}
}

static __always_inline int
src_filter_port(const XfwGlobalCtx *ctx, XfwPort port)
{
	XfwSrcRule *rule;
	if (ctx->l4_proto == XFW_L4_PROTO_UDP)
		rule = bpf_map_lookup_elem(
			SELECT_SHADOW_MAP(MAP_SRC_P_UDP_BASENAME, ctx->cfg->amap_src), &port);
	else
		rule = bpf_map_lookup_elem(
			SELECT_SHADOW_MAP(MAP_SRC_P_TCP_BASENAME, ctx->cfg->amap_src), &port);

	if (!rule) {
		uint8_t src_default = src_port_default_by_protos(ctx->ipver, ctx->l4_proto);
		XfwActionRule *default_rule = &ctx->cfg->rules.defaults[src_default];
		switch (default_rule->action) {
		case XFW_ACTION_BLOCK:
			return XFW_MAKE_CTX_DROP_EXT(ctx, XFW_DROP_SRC_PORT_DEFAULT_BLOCKED,
						     ": %u", bpf_ntohs(port));
		case XFW_ACTION_ALLOW:
			return XFW_CTX_CONTINUE;
		default:
			/* XFW_ACTION_RATE_LIMIT */
			XFW_ASSERT(default_rule->action == XFW_ACTION_RATE_LIMIT);

			XfwRLimitSlidingWindow *b = XFW_MAP_LOOKUP_OR_INIT(
				&MAP_SRC_PORT_RL_REF, &port, XfwRLimitSlidingWindow);
			XFW_ASSERT(b);

			const XfwRLimitIdx idx = default_rule->rlimit.named_idx;
			XFW_ASSERT(idx < XFW_MAX_NAMED_RATELIMITS);

			if (xfw_is_within_rlimit(ctx, &ctx->cfg->named_rates[idx], b))
				return XFW_CTX_CONTINUE;

			return XFW_MAKE_CTX_DROP(ctx, XFW_DROP_SRC_PORT_DEFAULT_RATE_LIMITED);
		}
	}

	if (rule->action == XFW_ACTION_BLOCK)
		return XFW_MAKE_CTX_DROP_EXT(ctx, XFW_DROP_SRC_PORT_BLOCKED,
					     ": %u", bpf_ntohs(port));

	if (rule->action == XFW_ACTION_ALLOW)
		return XFW_MAKE_CTX_PASS_EXT(ctx, XFW_SRC_PORT_ALLOWED,
					     ": %u", bpf_ntohs(port));

	XFW_ASSERT(rule->action == XFW_ACTION_RATE_LIMIT);

	XfwRLimitSlidingWindow *b = XFW_MAP_LOOKUP_OR_INIT(&MAP_SRC_PORT_RL_REF, &port,
						       XfwRLimitSlidingWindow);
	XFW_ASSERT(b);
	XFW_ASSERT(rule->named_idx < XFW_MAX_NAMED_RATELIMITS);
	if (xfw_is_within_rlimit(ctx, &ctx->cfg->named_rates[rule->named_idx], b))
		return XFW_CTX_CONTINUE;

	return XFW_MAKE_CTX_DROP_EXT(ctx, XFW_DROP_SRC_PORT_RATE_LIMITED,
				     ": %u", bpf_ntohs(port));
}

static __always_inline void
populate_src_info(const XfwGlobalCtx *ctx, void **src_ip_map,
		  XfwIpLpmKey *ip_lpm, uint8_t *src_default)
{
	if (ctx->ipver == bpf_htons(ETH_P_IPV6))
	{
		if (ctx->l4_proto == XFW_L4_PROTO_UDP) {
			*src_default = XFW_DEFAULT_SRC_IP_UDP_IP6;
			*src_ip_map =  SELECT_SHADOW_MAP(MAP_SRC_6_UDP_BASENAME,
							  ctx->cfg->amap_src);
		}
		else { /* XFW_L4_PROTO_TCP */
			*src_default = XFW_DEFAULT_SRC_IP_TCP_IP6;
			*src_ip_map =  SELECT_SHADOW_MAP(MAP_SRC_6_TCP_BASENAME,
							  ctx->cfg->amap_src);
		}
	}
	else { /* ETH_P_IP */
		if (ctx->l4_proto == XFW_L4_PROTO_UDP) {
			*src_default = XFW_DEFAULT_SRC_IP_UDP_IP4;
			*src_ip_map = SELECT_SHADOW_MAP(MAP_SRC_4_UDP_BASENAME,
							 ctx->cfg->amap_src);
		}
		else {  /* XFW_L4_PROTO_TCP */
			*src_default = XFW_DEFAULT_SRC_IP_TCP_IP4;
			*src_ip_map = SELECT_SHADOW_MAP(MAP_SRC_4_TCP_BASENAME,
							 ctx->cfg->amap_src);
		}
	}
}

/*
 * src_filter_ip() performs source IP filtering using LPM key context.
 *
 * NOTE:
 * This function is intended to be called at L4 processing stage, since
 * XfwIpLpmKey contains transport-layer related metadata (e.g. TCP/UDP protocol
 * information) in addition to the IP address.
 */
static __always_inline int
src_filter_ip(const XfwGlobalCtx *ctx, XfwIpLpmKey *ip_lpm)
{
	uint8_t src_default;
	void *src_ip_map;
	populate_src_info(ctx, &src_ip_map, ip_lpm, &src_default);

	XfwSrcRule *rule = bpf_map_lookup_elem(src_ip_map, ip_lpm);

	if (rule) {
		switch (rule->action) {
		case XFW_ACTION_BLOCK:
			return XFW_MAKE_CTX_DROP_EXT(ctx, XFW_DROP_SRC_IP_BLOCKED,
						     ": %pI6", &ctx->ilog_addr.in6);

		case XFW_ACTION_ALLOW:
			return XFW_MAKE_CTX_PASS_EXT(ctx, XFW_SRC_IP_ALLOWED,
						     ": %pI6", &ctx->ilog_addr.in6);
		default:
			/* XFW_ACTION_RATE_LIMIT */
			XFW_ASSERT(rule->action == XFW_ACTION_RATE_LIMIT);

			XfwRLimitSlidingWindow *b = XFW_MAP_LOOKUP_OR_INIT(
							&MAP_SRC_RATELIM_REF,
							&ctx->ilog_addr.in6,
							XfwRLimitSlidingWindow);
			XFW_ASSERT(b);

			XFW_ASSERT(rule->named_idx < XFW_MAX_NAMED_RATELIMITS);
			if (xfw_is_within_rlimit(ctx,
						 &ctx->cfg->named_rates[rule->named_idx],
						 b))
				return XFW_CTX_CONTINUE;
			return XFW_MAKE_CTX_DROP_EXT(ctx, XFW_DROP_SRC_IP_RATE_LIMITED,
						     ": %pI6", &ctx->ilog_addr.in6);
		}
	}

	XfwActionRule *default_rule = &ctx->cfg->rules.defaults[src_default];
	if (default_rule->action == XFW_ACTION_BLOCK)
		return XFW_MAKE_CTX_DROP_EXT(ctx, XFW_DROP_SRC_IP_DEFAULT_BLOCKED,
					     ": %pI6", &ctx->ilog_addr.in6);

	if (default_rule->action == XFW_ACTION_ALLOW)
		return XFW_CTX_CONTINUE;

	XFW_ASSERT(default_rule->action == XFW_ACTION_RATE_LIMIT);

	XfwRLimitSlidingWindow *b = XFW_MAP_LOOKUP_OR_INIT(&MAP_SRC_RATELIM_REF,
						       &ctx->ilog_addr.in6,
						       XfwRLimitSlidingWindow);
	XFW_ASSERT(b);

	const XfwRLimitIdx idx = default_rule->rlimit.named_idx;
	XFW_ASSERT(idx < XFW_MAX_NAMED_RATELIMITS);

	if (xfw_is_within_rlimit(ctx, &ctx->cfg->named_rates[idx], b))
		return XFW_CTX_CONTINUE;

	return XFW_MAKE_CTX_DROP_EXT(ctx, XFW_DROP_SRC_IP_DEFAULT_RATE_LIMITED,
				     ": %pI6", &ctx->ilog_addr.in6);
}

/**
 * It's not optimal to filter source IP addresses on L4.
 * This is consequence of our filtration rules combining addresses and ports,
 * e.g. `src ip4.udp : ...`.
 * We need to change the configuration to be able to split the layers.
 */
static __always_inline int
src_filter(const XfwGlobalCtx *ctx, XfwPort src_port, XfwIpLpmKey* src_ip_key)
{
	CHAIN(src_filter_ip, ctx, src_ip_key);
	CHAIN(src_filter_port, ctx, src_port);

	return XFW_CTX_CONTINUE;
}

static __always_inline int
rst_rlimit(XfwGlobalCtx *ctx)
{
	XfwActionRule *rule = &ctx->cfg->rules.tcp_flags[XFW_FLAGS_FILTER_RST];
	if (rule->action != XFW_ACTION_RATE_LIMIT)
		return XFW_CTX_CONTINUE;

	if (xfw_is_allowed_by_rlimits(ctx, &rule->rlimit))
		return XFW_CTX_CONTINUE;

	return XFW_MAKE_CTX_DROP(ctx, XFW_DROP_RST_RATE_LIMITED);
}

static __always_inline int
syn_rlimit(XfwGlobalCtx *ctx)
{
	XfwActionRule *rule = &ctx->cfg->rules.tcp_flags[XFW_FLAGS_FILTER_SYN];
	if (rule->action != XFW_ACTION_RATE_LIMIT)
		return XFW_CTX_CONTINUE;

	XFW_ASSERT(rule->action == XFW_ACTION_RATE_LIMIT);
	if (xfw_is_allowed_by_rlimits(ctx, &rule->rlimit))
		return XFW_CTX_CONTINUE;

	return XFW_MAKE_CTX_DROP(ctx, XFW_DROP_SYN_RATE_LIMITED);
}

static __always_inline int
in_process_l3(XfwGlobalCtx *ctx, XfwIpLpmKey *src_ip_key)
{
	switch (ctx->ipver) {
	case bpf_ntohs(ETH_P_IP): {
		struct iphdr *iph4;

		count_traffic_stat(ctx, XFW_IP4_TOTAL_INGRESS);
		int proto = parse_iphdr(&ctx->hdr_cur, &iph4);
		if (unlikely(proto < 0))
			return XFW_MAKE_CTX_DROP(ctx, XFW_DROP_IP4_BADHDR_INGRESS);

		ptrdiff_t ip_off = (void *)iph4 - XFW_CTX_DATA_BGN(ctx->ctx);
		if (ip_off < 0 || ip_off > L3_OFF_MAX)
			return XFW_MAKE_CTX_DROP(ctx, XFW_DROP_IP4_BADHDR_INGRESS);

		ctx->ip_off = (uint8_t)ip_off;
		/* Any MF bit or non-zero fragment offset means fragmented IPv4. */
		if ((bpf_htons(iph4->frag_off) & 0x3fff) != 0)
			return XFW_MAKE_CTX_DROP(ctx, XFW_DROP_IP4_FRAGMENTED_INGRESS);

		ctx->l4_proto = (u8)proto;
		xfw_ipv4_to_ipv6_mapped(iph4->saddr, ctx->ilog_addr.addr32);
		ipv4_populate_lpm_key(iph4->saddr, &src_ip_key->addr4);
		return XFW_CTX_CONTINUE;
	}
	case bpf_ntohs(ETH_P_IPV6): {
		struct ipv6hdr	*iph6;

		count_traffic_stat(ctx, XFW_IP6_TOTAL_INGRESS);
		int proto = parse_ip6hdr(&ctx->hdr_cur, &iph6);
		if (unlikely(proto < 0)) {
			if (proto == -EFBIG)
				return XFW_MAKE_CTX_DROP(ctx, XFW_DROP_IP6_FRAGMENTED_INGRESS);
			return XFW_MAKE_CTX_DROP(ctx, XFW_DROP_IP6_BADHDR_INGRESS);
		}
		ptrdiff_t ip_off = (void *)iph6 - XFW_CTX_DATA_BGN(ctx->ctx);
		if (ip_off < 0 || ip_off > L3_OFF_MAX)
			return XFW_MAKE_CTX_DROP(ctx, XFW_DROP_IP6_BADHDR_INGRESS);

		ctx->ip_off = (uint8_t)ip_off;
		ctx->l4_proto = (u8)proto;
		ctx->ilog_addr.in6 = iph6->saddr;
		ipv6_populate_lpm_key(&iph6->saddr, &src_ip_key->addr6);

		return XFW_CTX_CONTINUE;
	}
	case bpf_ntohs(ETH_P_ARP): {
		/* ARP is outside the firewall policy and stays with the host stack. */
		return XFW_MAKE_CTX_PASS(ctx, XFW_ARP_INGRESS);
	}
	default : {
		/* Unknown EtherTypes are not useful to the protected L3 services. */
		return XFW_MAKE_CTX_DROP_EXT(ctx, XFW_DROP_L2_UNKNOWN_INGRESS,
					     ": %x", bpf_htons(ctx->ipver));
	}
	}
}
/**
 * SYN without ACK received: both SYN cookies and SYN rate limiting may be enabled
 * by configuration. In this case, we run both checks before considering the
 * connection trusted.
 */
static __always_inline int
tcp_rcv_syn_filter(XfwGlobalCtx *ctx, struct tcphdr *th)
{
	/* If a SYN cookie was generated, processing stops immediately. */
	if (ctx->cfg->rules.syncookie.enabled)
		CHAIN(tcp_syncookies_syn_filter, ctx, th);

	CHAIN(syn_rlimit, ctx);

	/* We do not add the connection to the trusted set here.
	 * The trusted entry will be created later in tc.c, which is less
	 * loaded than xdp.c, when responding with SYN-ACK.
	 */
	return XFW_CTX_CONTINUE;
}

/**
 * Filter incoming ACK packets.
 *
 * 1. If SYN cookies are disabled or flood mode is inactive → fall back to
 *    the normal TCP auth filter.
 * 2. If a trusted connection already exists → continue.
 * 3. Otherwise, call SYN-cookie-specific check.
 * 4. If valid, trust the connection on ingress side.
 */
static __always_inline int
tcp_rcv_ack_filter(const XfwGlobalCtx *ctx, struct tcphdr *th,
		   const XfwSockAddr *addr)
{
	/* Fast path - no SYN cookies. */
	if (!ctx->cfg->rules.syncookie.enabled)
		return tcp_auth_conn_ingress_filter(ctx, addr, TCP_AUTH_EVENT_NORMAL);

	XfwTcpSynCookieTs *ts = __tcp_get_tcp_syncookie_ts();
	XFW_ASSERT(ts);

	/* Fast path - syncookies flood mode is inactive. */
	if (!tcp_syncookies_flood_mode(ctx, ts))
		return tcp_auth_conn_ingress_filter(ctx, addr, TCP_AUTH_EVENT_NORMAL);

	/* Can rely only on connections that are up-to-date */
	if (ctx->cfg->rules.tcp_auth.enabled && tcp_auth_has_conn_trusted(ctx, addr))
		return XFW_CTX_CONTINUE;

	/* Perform SYN-cookie-specific ACK validation */
	CHAIN(tcp_syncookies_ack_filter, ctx, th);

	/*
	 * This is the scenario where a SYN cookie was issued and successfully
	 * validated. We need to authenticate TCP flows passing through the host
	 * or designated to the local host.
	 *
	 * This is the only case where xdp.c adds a connection to the trusted set.
	 * The SYN arrived on the ingress interface, while the SYN-ACK was
	 * generated and sent directly by xdp.c, bypassing tc.c. This ensures
	 * the connection is correctly tracked without relying on tc.c.
	 */
	tcp_auth_conn_add(addr);
	return XFW_CTX_CONTINUE;
}

/**
 * Combined TCP filter for SYN handling (SYN cookies or rate limiting),
 * authentication, and RST/FIN processing. These mechanisms are tightly
 * coupled, so they are processed together to avoid redundant lookups and
 * state checks.
 *
 * TCP packets may arrive out of order due to network reordering:
 * - An early RST removes the connection state, causing subsequent packets
 *   to be dropped, which mirrors the behavior of the TCP stack.
 * - FIN packets are tracked to support proper connection teardown.
 *
 * Authentication model:
 * - All SYN packets are added to the trusted set in tc.c. This covers connections
 * initiated by the host/gateway or connections we respond to with SYN-ACK.
 * This shifts most trusted connection tracking to tc.c, which is less loaded
 * than XDP.
 * - XDP handles authentication only when the TCP AUTH filter is active. It also
 * validates SYN cookies when required. A SYN cookie connection is the only case
 * where XDP adds a connection to the trusted set, after successful validation on
 * the ACK.
 *
 * This approach ensures that:
 * - all new connections are tracked via SYN handling in tc.c, so here we can
 * rely on all existing connections,
 * - XDP performs filtering based on the trusted set when the TCP AUTH filter
 * is active,
 * - SYN flood protection is enforced when required (xdp.c),
 * - connections using SYN cookies are correctly validated and added to the
 * trusted set in XDP.
 *
 * TODO #19: It may be necessary to move some authentication logic to a separate
 * xdp.c for upstream connections.
 */
static __always_inline int
tcp_flags_filter(XfwGlobalCtx *ctx, struct tcphdr *th,
		 const XfwSockAddr *addr)
{
	/* FIN: track connection for closing. */
	if (th->fin) {
		count_traffic_stat(ctx, XFW_FIN);
		return tcp_auth_conn_ingress_filter(ctx, addr,
						    TCP_AUTH_EVENT_FIN);
	}

	/* RST: clear connection state and apply rate-limiting. */
	if (th->rst) {
		count_traffic_stat(ctx, XFW_RST);
		CHAIN(tcp_auth_conn_ingress_filter, ctx, addr,
		      TCP_AUTH_EVENT_RST);
		return rst_rlimit(ctx);
	}

	/*
	 * SYN+ACK: response from upstream server during handshake.
	 *
	 * At egress (tc.o), when we sent the initial SYN, we added the connection
	 * to the trusted set. Here we only verify that this state exists.
	 */
	if (th->syn && th->ack) {
		count_traffic_stat(ctx, XFW_SYNACK);
		return tcp_auth_conn_ingress_filter(ctx, addr,
						    TCP_AUTH_EVENT_NORMAL);
	}

	/* SYN-only. Authenticate the connection if all checks pass. */
	if (th->syn) {
		count_traffic_stat(ctx, XFW_SYN);
		return tcp_rcv_syn_filter(ctx, th);
	}

	/* ACK-only: validate SYN-ACK cookies or authenticate normally.*/
	if (th->ack) {
		count_traffic_stat(ctx, XFW_ACK);
		return tcp_rcv_ack_filter(ctx, th, addr);
	}

	/* Default: authenticate any remaining TCP packets. */
	return tcp_auth_conn_ingress_filter(ctx, addr, TCP_AUTH_EVENT_NORMAL);
}

static __always_inline int
in_process_l4(XfwGlobalCtx *ctx, XfwIpLpmKey *src_ip_key)
{
	if (!bpf_bitset64_test(ctx->cfg->rules.ip_proto.protocols.data,
			       ctx->l4_proto))
	{
		return XFW_MAKE_CTX_DROP_EXT(ctx, XFW_DROP_L4_UNSUPPORTED_INGRESS,
					     ": %u", ctx->l4_proto);
	}

	switch (ctx->l4_proto) {
	case XFW_L4_PROTO_TCP: {
		struct tcphdr *th;

		count_traffic_stat(ctx, XFW_TCP_TOTAL_INGRESS);
		if (unlikely(parse_tcphdr(&ctx->hdr_cur, &th) <= 0))
			return XFW_MAKE_CTX_DROP(ctx, XFW_DROP_TCP_BADHDR_INGRESS);

		ptrdiff_t l4_off = (void *)th - XFW_CTX_DATA_BGN(ctx->ctx);
		if (l4_off < 0 || l4_off > L4_OFF_MAX)
			return XFW_MAKE_CTX_DROP(ctx, XFW_DROP_TCP_BADHDR_INGRESS);
		ctx->l4_off = (uint16_t)l4_off;

		CHAIN(tcp_anomaly_filter, ctx, th);

		CHAIN(src_filter, ctx, th->source, src_ip_key);

		const XfwSockAddr addr = {
			.addr = ctx->ilog_addr,
			.port = th->source
		};
		return tcp_flags_filter(ctx, th, &addr);
	}
	case XFW_L4_PROTO_UDP: {
		struct udphdr *uh;

		count_traffic_stat(ctx, XFW_UDP_TOTAL_INGRESS);
		if (unlikely(parse_udphdr(&ctx->hdr_cur, &uh) <= 0))
			return XFW_MAKE_CTX_DROP(ctx, XFW_DROP_UDP_BADHDR_INGRESS);

		ptrdiff_t l4_off = (void *)uh - XFW_CTX_DATA_BGN(ctx->ctx);
		if (l4_off < 0 || l4_off > L4_OFF_MAX)
			return XFW_MAKE_CTX_DROP(ctx, XFW_DROP_UDP_BADHDR_INGRESS);
		ctx->l4_off = (uint16_t)l4_off;

		if (uh->source == 0 || uh->dest == 0)
			return XFW_MAKE_CTX_DROP(ctx, XFW_DROP_UDP_ANOM_ZERO_PORT);

		CHAIN(ingress_dns_filter, ctx, uh);
		return src_filter(ctx, uh->source, src_ip_key);
	};
	case XFW_L4_PROTO_ICMP:
	case XFW_L4_PROTO_ICMPV6: {
		count_traffic_stat(ctx, XFW_ICMP_TOTAL_INGRESS);

		XfwICMPCommon *ih;
		if (unlikely(parse_icmphdr_common(&ctx->hdr_cur, &ih) < 0))
			return XFW_MAKE_CTX_DROP(ctx, XFW_DROP_ICMP_BADHDR_INGRESS);

		XFW_CTX_DBG("ICMP header parsed, type=%u", ih->type);

		const XfwIcmpKey key = {
			.proto = ctx->l4_proto,
			.type = ih->type
		};
		CHAIN(icmp_filter, ctx, &key);
		CHAIN(src_filter_ip, ctx, src_ip_key);
		/* ICMP has no destination port, so dst rules cannot refine this path. */
		return XFW_CTX_PASS;
	};
	case XFW_L4_PROTO_GRE:
		return XFW_MAKE_CTX_PASS(ctx, XFW_GRE_INGRESS);
	default:
		return XFW_MAKE_CTX_PASS(ctx, XFW_SUPPORTED_PROTOCOL_INGRESS);
	}
}

#define CHAIN_PASS_ALL(filter, ...)					\
do {									\
	r = filter(__VA_ARGS__);					\
	if (r == XFW_CTX_CONTINUE)					\
		break;							\
	if (r == XFW_CTX_PASS)						\
		goto pass;						\
	return r;							\
} while (0)

static __always_inline int
xfw_xdp_filter(struct XfwGlobalCtx *ctx)
{
	count_traffic_stat(ctx, XFW_TOTAL_DOWNSTREAM_INGRESS);

	XFW_DBG_INIT();

	if (unlikely(!ctx->cfg->rules_active)) {
		count_traffic_stat(ctx, XFW_PASSED_DOWNSTREAM_INGRESS);
		return XFW_MAKE_CTX_PASS(ctx, XFW_PRELOAD_INGRESS);
	}

	int ipver = parse_ethhdr(&ctx->hdr_cur);
	if (unlikely(ipver < 0))
		return XFW_MAKE_CTX_DROP(ctx, XFW_DROP_ETH_BADHDR_INGRESS);
	ctx->ipver = ipver;

	int r;
	/* Helper structure for src filter, filled on L3, used on L4. */
	XfwIpLpmKey src_ip_key = {};
	CHAIN_PASS_ALL(in_process_l3, ctx, &src_ip_key);
	CHAIN_PASS_ALL(in_process_l4, ctx, &src_ip_key);
	CHAIN_PASS_ALL(xfw_dst_filter, ctx);

pass:
	count_traffic_stat(ctx, XFW_PASSED_DOWNSTREAM_INGRESS);
	return XFW_CTX_PASS;
}

/**
 * Program is attached to XDP hook on NIC facing external network.
 */
SEC("xdp")
int
xfw_xdp(struct xdp_md *xdp)
{
	int r;

	XfwGlobalCtx ctx;
	xfw_ctx_init(&ctx, xdp);
	/* We can't use XFW_ASSERT here because ctx.g_stats is not available. */
	VERIFY_TRUE_OR_RETURN(ctx.cfg && ctx.g_stats, XFW_CTX_PASS);

	CHAIN_PASS_ALL(create_metadata, &ctx, xdp);

	r = xfw_xdp_filter(&ctx);

pass:
	return finalize_result(&ctx, r);
}

char LICENSE[] SEC("license") = "GPL v2";
