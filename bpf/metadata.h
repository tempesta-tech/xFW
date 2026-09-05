/**
 *	Tempesta xFW packet metadata description
 *
 * SPDX-FileCopyrightText: © 2026 Tempesta Technologies, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#pragma once

#include "ctx.h"
#include "log.h"
#include "parsing_helpers.h"

/**
 * Packet metadata shared between the main XDP program and tail-called
 * subprograms.
 *
 * @ts_jiff  - Packet processing timestamp in jiffies.
 * @cur_pos  - Offset of the current parser position from the beginning of
 *             packet data.
 * @ipver    - Network-byte-order EtherType: ETH_P_IP or ETH_P_IPV6.
 * @l4_off   - Offset of the transport-layer header from the beginning of
 *             packet data.
 * @ip_off   - Offset of the IP header from the beginning of packet data.
 * @l4_proto - Transport protocol number extracted from the IP header.
 */
typedef struct {
	uint64_t	ts_jiff;
	uint16_t	cur_pos;
	uint16_t	ipver;
	uint16_t	l4_off;
	uint8_t		ip_off;
	uint8_t		l4_proto;
} __attribute__((packed)) XfwPacketMetadata;

STATIC_ASSERT(sizeof(XfwPacketMetadata) <= 32,
	      "Packet metadata must be less than 32 bytes");
STATIC_ASSERT(sizeof(XfwPacketMetadata) % 4 == 0,
	      "XDP metadata size must be 4-byte aligned");
STATIC_ASSERT(L4_OFF_MAX + TCP_MAXLEN <= UINT16_MAX,
	      "Packet cursor offset does not fit into uint16_t");

/*
 * Pass the global packet-processing context to modules by storing its
 * transferable fields in packet metadata. A module uses this metadata to
 * reconstruct the complete XfwGlobalCtx with xfw_ctx_init_from_metadata().
 */
static __always_inline bool
xfw_set_packet_metadata(const XfwGlobalCtx *ctx)
{
	XfwMd *xdp_ctx = ctx->ctx;

	XfwPacketMetadata *md = (void *)(long)xdp_ctx->data_meta;
	if (unlikely((void *)(md + 1) > (void *)(long)xdp_ctx->data)) {
		XFW_CTX_DBG("Logic error: created meta data is incorrect.");
		return false;
	}

	/*
	 * Packet metadata is created only for IPv4 and IPv6 traffic. Tail-call
	 * modules do not process packets with other EtherTypes.
	 */
	if (ctx->ipver != bpf_htons(ETH_P_IP)
	    && ctx->ipver != bpf_htons(ETH_P_IPV6))
	{
		XFW_CTX_DBG("Logic error: packet metadata creation requested for"
			    " unsupported EtherType: 0x%x", bpf_ntohs(ctx->ipver));
		return false;
	}

	md->ts_jiff = ctx->ts_jiff;
	md->cur_pos = ctx->hdr_cur.pos - XFW_CTX_DATA_BGN(xdp_ctx);
	md->ipver = ctx->ipver;
	md->l4_off = ctx->l4_off;
	md->ip_off = ctx->ip_off;
	md->l4_proto = ctx->l4_proto;

	return true;
}

/*
 * Restore the complete global packet-processing context for a module from
 * metadata provided by the main program. Individual modules may use only a
 * subset of its fields, but restoring the entire context here keeps the
 * module interface uniform and avoids module-specific initialization paths.
 */
static __always_inline bool
xfw_ctx_init_from_metadata(XfwGlobalCtx *ctx, XfwMd *pkt_ctx)
{
	xfw_ctx_init(ctx, pkt_ctx);
	VERIFY_TRUE_OR_RETURN(ctx->cfg && ctx->g_stats, false);

	XfwPacketMetadata *md = (void *)(long)pkt_ctx->data_meta;
	/* Limiting is important for verifier */
	VERIFY_TRUE_OR_RETURN((void *)(md + 1) <= ctx->hdr_cur.pos
			       && md->cur_pos <= L4_OFF_MAX + TCP_MAXLEN,
			       false);
	ctx->hdr_cur.pos += md->cur_pos;

	VERIFY_TRUE_OR_RETURN(md->ip_off <= L3_OFF_MAX, false);
	VERIFY_TRUE_OR_RETURN(md->l4_off <= L4_OFF_MAX, false);

	void *ip_hdr = (void *)(long)pkt_ctx->data + md->ip_off;
	if (md->ipver == bpf_htons(ETH_P_IP)) {
		struct iphdr *ipv4 = ip_hdr;
		VERIFY_TRUE_OR_RETURN((void *)(ipv4 + 1) <= ctx->hdr_cur.end,
				      false);
		xfw_ipv4_to_ipv6_mapped(ipv4->saddr, ctx->ilog_addr.addr32);
	}
	else if (md->ipver == bpf_htons(ETH_P_IPV6)) {
		struct ipv6hdr *ipv6 = ip_hdr;
		VERIFY_TRUE_OR_RETURN((void *)(ipv6 + 1) <= ctx->hdr_cur.end,
				      false);
		ctx->ilog_addr.in6 = ipv6->saddr;
	} else {
		return false;
	}

	ctx->ts_jiff = md->ts_jiff;
	ctx->ipver = md->ipver;
	ctx->l4_off = md->l4_off;
	ctx->ip_off = md->ip_off;
	ctx->l4_proto = md->l4_proto;

	return true;
}

/*
 * Determine whether an enabled standalone module requires packet metadata.
 * Extend this predicate for every new standalone module that reconstructs
 * XfwGlobalCtx from metadata; otherwise the main program will not prepare
 * the context required by that module.
 */
static __always_inline bool
is_metadata_creation_necessary(const XfwGlobalCtx *ctx)
{
	return ctx->cfg->rules.dns.enabled ||
	       ctx->cfg->rules.syncookie.enabled;
}
