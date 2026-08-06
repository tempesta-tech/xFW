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
 * @cur_pos - Current packet offset expected by the called subprogram.
 *            Its exact meaning is module-specific. For the DNS module it
 *            points to the current DNS parsing position; for TCP SYN
 *            protection it points to the TCP header.
 * @ip_pos  - Offset of the IP header from packet data.
 * @is_ipv4 - Non-zero for IPv4, zero for IPv6.
 * @unused  - Reserved for future metadata without changing the layout.
 */
typedef struct {
	uint16_t	cur_pos;
	uint16_t	ip_off;
	uint16_t	is_ipv4;
	uint16_t	unused;
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

	md->cur_pos = cur_pos;
	md->ip_off = ctx->ip_off;
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
