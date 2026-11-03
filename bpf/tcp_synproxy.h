// SPDX-License-Identifier: LGPL-2.1 OR BSD-2-Clause
/* Copyright (c) 2022, NVIDIA CORPORATION & AFFILIATES. All rights reserved. */
/* SPDX-FileCopyrightText: © 2026 Tempesta Technologies, Inc. */
/*
 * Tempesta xFW gateway SYN proxy. Adapted from Linux's
 * tools/testing/selftests/bpf/progs/xdp_synproxy_kern.c.
 */
#pragma once

#pragma push_macro("BANNER")
#undef BANNER
#define BANNER "synproxy"
#include "log.h"

#include "tcp_auth.h"
#include "tcp_common.h"
#include "../bpf_uapi/synproxy.h"
#include <bpf/bpf_core_read.h>

#ifndef ENOENT
#define ENOENT 2
#endif

const volatile bool synproxy_mode = false;

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, uint32_t);
	__type(value, uint64_t);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, 1);
} MAP_SYNPROXY_GEN_REF SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, uint32_t);
	__type(value, XfwSynproxyMeta);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, 2);
} MAP_SYNPROXY_META_REF SEC(".maps");

SHADOW_MAP(MAP_SYNPROXY_4_BASENAME, BPF_MAP_TYPE_LPM_TRIE,
	   XFW_SYNPROXY_MAX_TARGETS, XfwSynproxyKey4, uint8_t, BPF_F_NO_PREALLOC);
SHADOW_MAP(MAP_SYNPROXY_6_BASENAME, BPF_MAP_TYPE_LPM_TRIE,
	   XFW_SYNPROXY_MAX_TARGETS, XfwSynproxyKey6, uint8_t, BPF_F_NO_PREALLOC);
SHADOW_MAP(MAP_SYNPROXY_RET_4_BASENAME, BPF_MAP_TYPE_LPM_TRIE,
	   XFW_SYNPROXY_MAX_RETIRED, XfwSynproxyKey4, uint8_t, BPF_F_NO_PREALLOC);
SHADOW_MAP(MAP_SYNPROXY_RET_6_BASENAME, BPF_MAP_TYPE_LPM_TRIE,
	   XFW_SYNPROXY_MAX_RETIRED, XfwSynproxyKey6, uint8_t, BPF_F_NO_PREALLOC);

static __always_inline int
tcp_synproxy_scope_lookup(const XfwGlobalCtx *ctx, const struct tcphdr *th,
			 uint32_t slot)
{
	XfwSynproxyMeta *meta = bpf_map_lookup_elem(&MAP_SYNPROXY_META_REF, &slot);
	if (!meta)
		return -EINVAL;
	const bool retired = meta->retired_count && th->ack && !th->syn
		&& !th->fin && !th->rst
		&& bpf_ktime_get_ns() <= meta->retired_until_ns;
	if (!meta->active_count && !retired)
		return false;

	if (ctx->ipver == bpf_htons(ETH_P_IP)) {
		struct iphdr *iph = XFW_PKT_PTR(ctx, ctx->ip_off, struct iphdr);
		VERIFY_TRUE_OR_RETURN((void *)(iph + 1) <= ctx->hdr_cur.end, -EINVAL);
		XfwSynproxyKey4 key = {
			.prefixlen = XFW_SYNPROXY_PORT_BITS + 32,
			.addr = iph->daddr,
		};
		if (meta->active_count) {
			void *map = SELECT_SHADOW_MAP(MAP_SYNPROXY_4_BASENAME, slot);
			if (bpf_map_lookup_elem(map, &key))
				return true;
			key.port = th->dest;
			if (bpf_map_lookup_elem(map, &key))
				return true;
		}
		if (retired) {
			void *map = SELECT_SHADOW_MAP(MAP_SYNPROXY_RET_4_BASENAME, slot);
			key.port = 0;
			if (bpf_map_lookup_elem(map, &key))
				return true;
			key.port = th->dest;
			return bpf_map_lookup_elem(map, &key) != NULL;
		}
	} else {
		struct ipv6hdr *iph = XFW_PKT_PTR(ctx, ctx->ip_off, struct ipv6hdr);
		VERIFY_TRUE_OR_RETURN((void *)(iph + 1) <= ctx->hdr_cur.end, -EINVAL);
		XfwSynproxyKey6 key = {
			.prefixlen = XFW_SYNPROXY_PORT_BITS + 128,
		};
		xfw_ipv6_addr_cpy(key.addr, &iph->daddr);
		if (meta->active_count) {
			void *map = SELECT_SHADOW_MAP(MAP_SYNPROXY_6_BASENAME, slot);
			if (bpf_map_lookup_elem(map, &key))
				return true;
			key.port = th->dest;
			if (bpf_map_lookup_elem(map, &key))
				return true;
		}
		if (retired) {
			void *map = SELECT_SHADOW_MAP(MAP_SYNPROXY_RET_6_BASENAME, slot);
			key.port = 0;
			if (bpf_map_lookup_elem(map, &key))
				return true;
			key.port = th->dest;
			return bpf_map_lookup_elem(map, &key) != NULL;
		}
	}
	return false;
}

static __always_inline int
tcp_synproxy_scope_match(const XfwGlobalCtx *ctx, const struct tcphdr *th)
{
	const uint32_t zero = 0;
	uint64_t *published = bpf_map_lookup_elem(&MAP_SYNPROXY_GEN_REF, &zero);
	if (!published)
		return -EINVAL;

	/* A second publication may already be rewriting the earlier slot. */
#pragma unroll
	for (int i = 0; i < 2; i++) {
		uint64_t generation = READ_ONCE(*published);
		int match = tcp_synproxy_scope_lookup(ctx, th, generation & 1);
		if (generation == READ_ONCE(*published))
			return match;
	}
	/* Never interpret a mixed-generation miss as an unprotected endpoint. */
	return -EINVAL;
}

/* Keep the original twelve-byte ABI usable with modular conntrack. */
struct bpf_ct_opts___xfw {
	int32_t		netns_id;
	int32_t		error;
	uint8_t		l4proto;
	uint8_t		dir;
	uint8_t		reserved[2];
} __attribute__((preserve_access_index));

/* Do not require conntrack types in the build host's vmlinux BTF. */
struct nf_conn;
struct nf_conn___xfw {
	unsigned long status;
	union {
		struct {
			uint8_t state;
		} tcp;
	} proto;
} __attribute__((preserve_access_index));

/* Stable values from the nf_conntrack_common/tcp UAPI headers. */
enum {
	XFW_CT_CONFIRMED = 1 << 3,
	XFW_CT_FIN_WAIT = 4,
	XFW_CT_CLOSE = 8,
};

extern struct nf_conn *bpf_xdp_ct_lookup(struct xdp_md *ctx,
				       struct bpf_sock_tuple *tuple,
				       uint32_t tuple_len,
				       struct bpf_ct_opts___xfw *opts,
				       uint32_t opts_len) __ksym __weak;
extern void bpf_ct_release(struct nf_conn *ct) __ksym __weak;

enum XfwSynproxyConn {
	XFW_SYNPROXY_CONN_ERROR = -1,
	XFW_SYNPROXY_CONN_MISSING,
	XFW_SYNPROXY_CONN_CONFIRMED,
	XFW_SYNPROXY_CONN_CLOSING,
};

static __always_inline int
tcp_synproxy_conn_lookup(const XfwGlobalCtx *ctx, const struct tcphdr *th)
{
	struct bpf_ct_opts___xfw opts = {
		.netns_id = BPF_F_CURRENT_NETNS,
		.l4proto = XFW_L4_PROTO_TCP,
	};
	struct bpf_sock_tuple tuple = {0};
	uint32_t tuple_len;

	if (!bpf_ksym_exists(bpf_xdp_ct_lookup)
	    || !bpf_ksym_exists(bpf_ct_release)
	    || !bpf_core_type_exists(struct nf_conn___xfw))
		return XFW_SYNPROXY_CONN_ERROR;

	if (ctx->ipver == bpf_htons(ETH_P_IP)) {
		struct iphdr *iph = XFW_PKT_PTR(ctx, ctx->ip_off, struct iphdr);
		VERIFY_TRUE_OR_RETURN((void *)(iph + 1) <= ctx->hdr_cur.end,
				      XFW_SYNPROXY_CONN_ERROR);
		tuple.ipv4.saddr = iph->saddr;
		tuple.ipv4.daddr = iph->daddr;
		tuple.ipv4.sport = th->source;
		tuple.ipv4.dport = th->dest;
		tuple_len = sizeof(tuple.ipv4);
	} else {
		struct ipv6hdr *iph = XFW_PKT_PTR(ctx, ctx->ip_off, struct ipv6hdr);
		VERIFY_TRUE_OR_RETURN((void *)(iph + 1) <= ctx->hdr_cur.end,
				      XFW_SYNPROXY_CONN_ERROR);
		xfw_ipv6_addr_cpy(tuple.ipv6.saddr, &iph->saddr);
		xfw_ipv6_addr_cpy(tuple.ipv6.daddr, &iph->daddr);
		tuple.ipv6.sport = th->source;
		tuple.ipv6.dport = th->dest;
		tuple_len = sizeof(tuple.ipv6);
	}

	struct nf_conn *ct = bpf_xdp_ct_lookup(ctx->ctx, &tuple, tuple_len,
					    &opts, sizeof(opts));
	if (!ct)
		return opts.error == -ENOENT
			? XFW_SYNPROXY_CONN_MISSING : XFW_SYNPROXY_CONN_ERROR;

	const struct nf_conn___xfw *view = (const void *)ct;
	unsigned long status = READ_ONCE(view->status);
	uint8_t state = READ_ONCE(view->proto.tcp.state);
	bpf_ct_release(ct);

	if (!(status & XFW_CT_CONFIRMED))
		return XFW_SYNPROXY_CONN_MISSING;
	/* Retain the kernel's closing state until its normal expiry. */
	if (th->syn && !th->ack && state >= XFW_CT_FIN_WAIT
	    && state <= XFW_CT_CLOSE)
		return XFW_SYNPROXY_CONN_CLOSING;
	return XFW_SYNPROXY_CONN_CONFIRMED;
}

/* Validate declared IP lengths, independently of Ethernet padding. */
static __always_inline int
tcp_synproxy_segment_len(const XfwGlobalCtx *ctx, const struct tcphdr *th)
{
	uint32_t ip_len, ip_hdr_len;

	VERIFY_TRUE_OR_RETURN(ctx->l4_off >= ctx->ip_off, -EINVAL);
	ip_hdr_len = ctx->l4_off - ctx->ip_off;
	if (ctx->ipver == bpf_htons(ETH_P_IP)) {
		struct iphdr *iph = XFW_PKT_PTR(ctx, ctx->ip_off, struct iphdr);
		VERIFY_TRUE_OR_RETURN((void *)(iph + 1) <= ctx->hdr_cur.end,
				      -EINVAL);
		ip_len = bpf_ntohs(iph->tot_len);
	} else {
		struct ipv6hdr *iph = XFW_PKT_PTR(ctx, ctx->ip_off, struct ipv6hdr);
		VERIFY_TRUE_OR_RETURN((void *)(iph + 1) <= ctx->hdr_cur.end,
				      -EINVAL);
		ip_len = sizeof(*iph) + bpf_ntohs(iph->payload_len);
	}
	VERIFY_TRUE_OR_RETURN(ip_len >= ip_hdr_len + sizeof(*th), -EINVAL);
	VERIFY_TRUE_OR_RETURN(ctx->ip_off + ip_len <= ctx->pkt_sz, -EINVAL);
	uint32_t len = ip_len - ip_hdr_len;
	VERIFY_TRUE_OR_RETURN(th->doff >= 5 && th->doff * 4 <= len, -EINVAL);
	return len;
}

static __always_inline int64_t
tcp_synproxy_gen_cookie(XfwGlobalCtx *ctx, struct tcphdr *th)
{
	struct {
		struct tcphdr th;
		uint8_t opts[TCP_OPTS_MAX];
	} tcp = {0};
	const uint32_t tcp_len = th->doff * 4;
	int64_t csum;

	VERIFY_TRUE_OR_RETURN(tcp_len >= sizeof(*th) && tcp_len <= TCP_MAXLEN,
			      -EINVAL);
	VERIFY_TRUE_OR_RETURN((void *)th + tcp_len <= ctx->hdr_cur.end, -EINVAL);
	/* The stack copy lets the helper inspect every original TCP option. */
	VERIFY_TRUE_OR_RETURN(!bpf_xdp_load_bytes(ctx->ctx, ctx->l4_off, &tcp,
					       tcp_len), -EINVAL);
	csum = bpf_csum_diff(0, 0, (void *)&tcp, tcp_len, 0);
	VERIFY_TRUE_OR_RETURN(csum >= 0, csum);

	if (ctx->ipver == bpf_htons(ETH_P_IP)) {
		struct iphdr *iph = XFW_PKT_PTR(ctx, ctx->ip_off, struct iphdr);
		VERIFY_TRUE_OR_RETURN((void *)(iph + 1) <= ctx->hdr_cur.end,
				      -EINVAL);
		uint32_t ip_len = iph->ihl * 4;
		VERIFY_TRUE_OR_RETURN(ip_len >= sizeof(*iph)
				      && ip_len <= IPV4_MAXLEN, -EINVAL);
		VERIFY_TRUE_OR_RETURN((void *)iph + ip_len <= ctx->hdr_cur.end,
				      -EINVAL);
		VERIFY_TRUE_OR_RETURN(tcp_ipv4_csum(iph, tcp_len, csum) == 0,
				      -EINVAL);
		csum = bpf_csum_diff(0, 0, (void *)iph, ip_len, 0);
		VERIFY_TRUE_OR_RETURN(csum >= 0 && csum_fold(csum) == 0, -EINVAL);
		return bpf_tcp_raw_gen_syncookie_ipv4(iph, &tcp.th, tcp_len);
	}

	struct ipv6hdr *iph = XFW_PKT_PTR(ctx, ctx->ip_off, struct ipv6hdr);
	VERIFY_TRUE_OR_RETURN((void *)(iph + 1) <= ctx->hdr_cur.end, -EINVAL);
	VERIFY_TRUE_OR_RETURN(tcp_ipv6_csum(iph, tcp_len, csum) == 0, -EINVAL);
	return bpf_tcp_raw_gen_syncookie_ipv6(iph, &tcp.th, tcp_len);
}

static __always_inline uint8_t
tcp_synproxy_write_opts(struct tcphdr *th, const void *data_end,
			uint16_t mss, const XfwTCPOpts *opts, bool ecn)
{
	__be32 *o = (__be32 *)(th + 1);

	if ((void *)(o + 1) > data_end)
		return 0;
	*o++ = bpf_htonl((TCPOPT_MSS << 24) | (TCPOPT_MSS_SZ << 16) | mss);
	if (!opts->ts_present)
		return 1;
	if ((void *)(o + 3) > data_end)
		return 0;
	if (opts->sack_perm)
		*o++ = bpf_htonl((TCPOPT_SACK_PERM << 24)
				 | (TCPOPT_SACK_PERM_SZ << 16)
				 | (TCPOPT_TIMESTAMP << 8) | TCPOPT_TIMESTAMP_SZ);
	else
		*o++ = bpf_htonl((TCPOPT_NOP << 24) | (TCPOPT_NOP << 16)
				 | (TCPOPT_TIMESTAMP << 8) | TCPOPT_TIMESTAMP_SZ);
	uint32_t ts = tcp_clock_ms() & ~0x3fU;
	ts |= opts->wscale_present ? opts->wscale : TCPOPT_WSCALE_MASK;
	ts |= opts->sack_perm ? 1 << 4 : 0;
	ts |= ecn ? 1 << 5 : 0;
	*o++ = bpf_htonl(ts);
	*o++ = opts->ts;
	if (!opts->wscale_present)
		return 4;
	if ((void *)(o + 1) > data_end)
		return 0;
	*o = bpf_htonl((TCPOPT_NOP << 24) | (TCPOPT_WSCALE << 16)
			| (TCPOPT_WSCALE_SZ << 8) | XFW_DEFAULT_WSCALE);
	return 5;
}

static __always_inline int
tcp_synproxy_make_synack(XfwGlobalCtx *ctx, struct tcphdr *th, uint32_t cookie,
			 const XfwTCPOpts *opts)
{
	const bool ipv4 = ctx->ipver == bpf_htons(ETH_P_IP);
	const bool ecn = opts->ts_present && th->ece && th->cwr;
	const uint32_t opt_words = !opts->ts_present ? 1
		: opts->wscale_present ? 5 : 4;
	const uint32_t tcp_len = sizeof(*th) + opt_words * 4;
	struct tcphdr reply = {0};

	tcp_flag_word(&reply) = TCP_FLAG_SYN | TCP_FLAG_ACK;
	if (ecn)
		tcp_flag_word(&reply) |= TCP_FLAG_ECE;
	reply.doff = tcp_len / 4;
	reply.source = th->dest;
	reply.dest = th->source;
	reply.seq = bpf_htonl(cookie);
	reply.ack_seq = bpf_htonl(bpf_ntohl(th->seq) + 1);
	/* The backend handshake must complete before the window opens. */
	reply.window = 0;

	/* Keep Ethernet/VLAN framing and normalize the IP header as upstream does. */
	const uint32_t l4_off = ctx->ip_off
		+ (ipv4 ? sizeof(struct iphdr) : sizeof(struct ipv6hdr));
	const uint32_t new_size = l4_off + tcp_len;
	if (bpf_xdp_adjust_tail(ctx->ctx, (int)new_size - (int)ctx->pkt_sz))
		return -EINVAL;
	/* Packet pointers are invalid after adjusting the tail. */
	ctx->hdr_cur.end = XFW_CTX_DATA_END(ctx->ctx);
	ctx->l4_off = l4_off;
	VERIFY_TRUE_OR_RETURN(ctx->l4_off <= L4_OFF_MAX, -EINVAL);
	th = XFW_PKT_PTR(ctx, ctx->l4_off, struct tcphdr);
	VERIFY_TRUE_OR_RETURN((void *)th + tcp_len <= ctx->hdr_cur.end, -EINVAL);
	*th = reply;
	uint16_t mss = ipv4 ? XFW_SYNPROXY_MSS4 : XFW_SYNPROXY_MSS6;
	VERIFY_TRUE_OR_RETURN(tcp_synproxy_write_opts(th, ctx->hdr_cur.end, mss,
						     opts, ecn) == opt_words,
			      -EINVAL);

	struct ethhdr *eth = XFW_PKT_PTR(ctx, 0, struct ethhdr);
	VERIFY_TRUE_OR_RETURN((void *)(eth + 1) <= ctx->hdr_cur.end, -EINVAL);
	uint8_t mac[sizeof(eth->h_source)];
	memcpy(mac, eth->h_source, sizeof(mac));
	memcpy(eth->h_source, eth->h_dest, sizeof(mac));
	memcpy(eth->h_dest, mac, sizeof(mac));

	int64_t csum = bpf_csum_diff(0, 0, (void *)th, tcp_len, 0);
	VERIFY_TRUE_OR_RETURN(csum >= 0, csum);
	if (ipv4) {
		struct iphdr *iph = XFW_PKT_PTR(ctx, ctx->ip_off, struct iphdr);
		VERIFY_TRUE_OR_RETURN((void *)(iph + 1) <= ctx->hdr_cur.end,
				      -EINVAL);
		SWAP(iph->saddr, iph->daddr);
		iph->ihl = sizeof(*iph) / 4;
		iph->tos = 0;
		iph->id = 0;
		iph->frag_off = bpf_htons(0x4000); /* Don't fragment our SYN-ACK. */
		iph->ttl = XFW_DEFAULT_TTL;
		iph->tot_len = bpf_htons(new_size - ctx->ip_off);
		iph->check = 0;
		th->check = tcp_ipv4_csum(iph, tcp_len, csum);
		csum = bpf_csum_diff(0, 0, (void *)iph, sizeof(*iph), 0);
		VERIFY_TRUE_OR_RETURN(csum >= 0, csum);
		iph->check = csum_fold(csum);
	} else {
		struct ipv6hdr *iph = XFW_PKT_PTR(ctx, ctx->ip_off, struct ipv6hdr);
		VERIFY_TRUE_OR_RETURN((void *)(iph + 1) <= ctx->hdr_cur.end,
				      -EINVAL);
		SWAP(iph->saddr, iph->daddr);
		*(__be32 *)iph = bpf_htonl(0x60000000);
		iph->nexthdr = XFW_L4_PROTO_TCP;
		iph->hop_limit = XFW_DEFAULT_TTL;
		iph->payload_len = bpf_htons(new_size - ctx->ip_off - sizeof(*iph));
		th->check = tcp_ipv6_csum(iph, tcp_len, csum);
	}
	ctx->pkt_sz = new_size;
	return 0;
}

static __always_inline int
tcp_synproxy_ack_filter(const XfwGlobalCtx *ctx, struct tcphdr *th)
{
	if (ctx->ipver == bpf_htons(ETH_P_IP)) {
		struct iphdr *iph = XFW_PKT_PTR(ctx, ctx->ip_off, struct iphdr);
		VERIFY_TRUE_OR_RETURN((void *)(iph + 1) <= ctx->hdr_cur.end,
				      -EINVAL);
		return bpf_tcp_raw_check_syncookie_ipv4(iph, th);
	}
	struct ipv6hdr *iph = XFW_PKT_PTR(ctx, ctx->ip_off, struct ipv6hdr);
	VERIFY_TRUE_OR_RETURN((void *)(iph + 1) <= ctx->hdr_cur.end, -EINVAL);
	return bpf_tcp_raw_check_syncookie_ipv6(iph, th);
}

/* This map is bookkeeping for ordinary TCP auth after removing proxy policy. */
static __always_inline void
tcp_synproxy_auth_close(const XfwGlobalCtx *ctx, const struct tcphdr *th,
			const XfwSockAddr *addr)
{
	if (th->rst)
		tcp_auth_conn_delete(addr);
	else if (th->fin) {
		XfwTcpConnState *conn = tcp_auth_conn_lookup(addr);
		if (conn)
			tcp_auth_conn_set_fin_time(conn, ctx->ts_jiff);
	}
}

static __always_inline int
tcp_synproxy_filter(XfwGlobalCtx *ctx, struct tcphdr *th,
		    const XfwSockAddr *addr)
{
	if (!th->source || !th->dest)
		return XFW_MAKE_CTX_DROP(ctx, XFW_DROP_SYNPROXY_FAILED);
	int r = tcp_synproxy_conn_lookup(ctx, th);
	if (r == XFW_SYNPROXY_CONN_CONFIRMED) {
		tcp_synproxy_auth_close(ctx, th, addr);
		return XFW_CTX_CONTINUE;
	}
	if (r != XFW_SYNPROXY_CONN_MISSING)
		return XFW_MAKE_CTX_DROP(ctx, XFW_DROP_SYNPROXY_FAILED);

	if (th->fin || th->rst || (th->syn ^ th->ack) != 1)
		return XFW_MAKE_CTX_DROP(ctx, XFW_DROP_SYNPROXY_FAILED);
	int len = tcp_synproxy_segment_len(ctx, th);
	if (len < 0)
		return XFW_MAKE_CTX_DROP(ctx, XFW_DROP_SYNPROXY_FAILED);
	if (!th->syn) {
		if (tcp_synproxy_ack_filter(ctx, th))
			return XFW_MAKE_CTX_DROP(ctx, XFW_DROP_SYNPROXY_FAILED);
		tcp_auth_conn_add(addr);
		count_traffic_stat(ctx, XFW_SYNPROXY_RECEIVED);
		/* No packet changes: Linux SYNPROXY owns the backend handshake. */
		return XFW_CTX_CONTINUE;
	}
	if (len != th->doff * 4)
		return XFW_MAKE_CTX_DROP(ctx, XFW_DROP_SYNPROXY_FAILED);

	XfwTCPOpts opts = {0};
	if (tcp_parse_opts(ctx, th, &opts))
		return XFW_MAKE_CTX_DROP(ctx, XFW_DROP_SYNPROXY_FAILED);
	int64_t cookie = tcp_synproxy_gen_cookie(ctx, th);
	if (cookie < 0 || tcp_synproxy_make_synack(ctx, th, (uint32_t)cookie, &opts))
		return XFW_MAKE_CTX_DROP(ctx, XFW_DROP_SYNPROXY_FAILED);
	return MAKE_XDP_TX(ctx, XFW_SYNPROXY_GENERATED);
}

#undef BANNER
#pragma pop_macro("BANNER")
