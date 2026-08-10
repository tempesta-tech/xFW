/**
 *	Tempesta xFW packet metadata description
 *
 * SPDX-FileCopyrightText: © 2026 Tempesta Technologies, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#pragma once

#include "ctx.h"
#include "log.h"

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
xfw_set_packet_metadata(XfwGlobalCtx *ctx, uint16_t cur_pos)
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
is_metadata_creation_necessary(const XfwGlobalCtx *ctx)
{
	return ctx->cfg->rules.dns.enabled ||
	       ctx->cfg->rules.tcp_syn_drop.enabled;
}
