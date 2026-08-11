/**
 *	Tempesta xFW separate module filters.
 *
 * SPDX-FileCopyrightText: © 2026 Tempesta Technologies, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#pragma once

#include "ctx.h"
#include "filter.h"
#include "metadata.h"

#include "../bpf_uapi/map_names.h"

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__type(key, __u32);
	__type(value, __u32);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, XFW_PROG_MAX);
} MAP_PROG_ARRAY_REF SEC(".maps");

static __always_inline int
tcp_syn_drop_filter(XfwGlobalCtx *ctx)
{
	if (!xfw_set_packet_metadata(ctx, ctx->l4_off))
		return XFW_CTX_CONTINUE;

	bpf_tail_call(ctx->ctx, &MAP_PROG_ARRAY_REF,
		      XFW_PROG_TCP_SYN_DROP_FILTER);

	/*
	 * Tail call failed, continue normal XDP processing.
	 */
	return XFW_CTX_CONTINUE;
}

static __always_inline int
tcp_syncookies_filter(XfwGlobalCtx *ctx)
{
	if (!xfw_set_packet_metadata(ctx, ctx->l4_off))
		return XFW_CTX_CONTINUE;

	bpf_tail_call(ctx->ctx, &MAP_PROG_ARRAY_REF,
		      XFW_PROG_TCP_SYNCOOKIES_FILTER);

	/*
	 * Tail call failed, continue normal XDP processing.
	 */
	return XFW_CTX_CONTINUE;
}