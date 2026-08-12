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
 * Packet metadata shared between the main XDP program and tail-call
 * subprograms.
 *
 * @ts_jiff - current jiffies timestamp shared by all filters
 * @cur_pos - Current packet offset expected by the called subprogram.
 *            Its exact meaning is module-specific. For the DNS module it
 *            points to the current DNS parsing position; for TCP SYN
 *            protection it points to the TCP header.
 * @ipver   - ETH_P_IP or ETH_P_IPV6.
 * @ip_off  - Offset of the IP header from packet data.
 * @is_ipv4 - Non-zero for IPv4, zero for IPv6.
 */
typedef struct {
	uint64_t	ts_jiff;
	uint16_t	cur_pos;
	uint16_t	ipver;
	uint8_t		ip_off;
	uint8_t		l4_proto;
	uint8_t		is_ipv4;
	uint8_t		unused;
} __attribute__((packed)) XfwPacketMetadata;

STATIC_ASSERT(sizeof(XfwPacketMetadata) <= 32,
	      "Packet metadata must be less than 32 bytes");
STATIC_ASSERT(sizeof(XfwPacketMetadata) % 4 == 0,
	      "XDP metadata size must be 4-byte aligned");

/* IPv4/IPv6 max len is 60, UDP len is 8*/
#define L3_L4_HDRS_MAXLEN		68

static __always_inline bool
xfw_set_packet_metadata(const XfwGlobalCtx *ctx, uint16_t cur_pos)
{
	XfwMd* xdp_ctx = ctx->ctx;
	uint16_t is_ipv4;
	
	switch (ctx->ipver) {
	case bpf_ntohs(ETH_P_IP):
		is_ipv4 = 1;
		break;
	case bpf_ntohs(ETH_P_IPV6):
		is_ipv4 = 0;
		break;
	default:
		return false;
	}

	XfwPacketMetadata *md = (void *)(long)xdp_ctx->data_meta;
	if (unlikely((void *)(md + 1) > (void *)(long)xdp_ctx->data)) {
		XFW_CTX_DBG("Logic error: created meta data is incorrect.");
		return false;
	}

	md->ts_jiff = ctx->ts_jiff;
	md->cur_pos = cur_pos;
	md->ipver = ctx->ipver;
	md->ip_off = ctx->ip_off;
	md->l4_proto = ctx->l4_proto;
	md->is_ipv4 = is_ipv4;
	md->unused = 0;

	return true;
}

static __always_inline bool
xfw_ctx_init_from_metadata(XfwGlobalCtx *ctx, XfwMd *pkt_ctx)
{
	xfw_ctx_init(ctx, pkt_ctx);
	VERIFY_TRUE_OR_RETURN(ctx->cfg && ctx->g_stats, false);

	XfwPacketMetadata *md = (void *)(long)pkt_ctx->data_meta;
	/* Limiting is important for verifier */
	VERIFY_TRUE_OR_RETURN((void *)(md + 1) <= ctx->hdr_cur.pos
			       && md->cur_pos <= L4_OFF_MAX,
			       false);
	ctx->hdr_cur.pos += md->cur_pos;

	VERIFY_TRUE_OR_RETURN(md->ip_off <= L3_L4_HDRS_MAXLEN, false);
	void *ip_hdr = (void *)(long)pkt_ctx->data + md->ip_off;
	if (md->is_ipv4) {
		struct iphdr *ipv4 = ip_hdr;
		VERIFY_TRUE_OR_RETURN((void *)(ipv4 + 1) <= ctx->hdr_cur.end,
				      false);
		xfw_ipv4_to_ipv6_mapped(ipv4->saddr, ctx->ilog_addr.addr32);
	}
	else {
		struct ipv6hdr *ipv6 = ip_hdr;
		VERIFY_TRUE_OR_RETURN((void *)(ipv6 + 1) <= ctx->hdr_cur.end,
				      false);
		ctx->ilog_addr.in6 = ipv6->saddr;
	}

	ctx->ts_jiff = md->ts_jiff;
	ctx->ipver = md->ipver;
	/*
	 * Derive `l4_off` from the already verified packet cursor
	 * instead of copying `md->cur_pos`. Packet bounds checks above
	 * split and merge verifier states and may lose range information
	 * for scalar offsets.
	 *
	 * Do not use XFW_CTX_DATA_BGN(ctx) here. ctx->ctx is a spilled BPF
	 * context pointer stored inside the stack-resident XfwGlobalCtx,
	 * and accessing pkt_ctx->data through it may be compiled as a partial
	 * load from the spilled pointer, which the verifier rejects with
	 * "invalid size of register fill".
	 */
	ctx->l4_off = (uint16_t)(ctx->hdr_cur.pos -
		(void *)(long)pkt_ctx->data);
	ctx->ip_off = md->ip_off;
	ctx->l4_proto = md->l4_proto;

	return true;
}

static __always_inline bool
is_metadata_creation_necessary(const XfwGlobalCtx *ctx)
{
	return ctx->cfg->rules.dns.enabled ||
	       ctx->cfg->rules.tcp_syn_drop.enabled ||
	       ctx->cfg->rules.syncookie.enabled;
}
