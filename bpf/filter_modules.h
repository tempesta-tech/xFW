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
	__uint(max_entries, XFW_XDP_PROG_MAX);
} MAP_XDP_PROG_ARRAY_REF SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__type(key, __u32);
	__type(value, __u32);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, XFW_TC_PROG_MAX);
} MAP_TC_PROG_ARRAY_REF SEC(".maps");

#define XDP_MODULE_FILTER(name, index)				\
static __always_inline int					\
xdp_##name##_module_filter(const XfwGlobalCtx *ctx)		\
{								\
	if (!xfw_set_packet_metadata(ctx, ctx->l4_off))		\
		return XFW_CTX_CONTINUE;			\
								\
	bpf_tail_call(ctx->ctx, &MAP_XDP_PROG_ARRAY_REF, index); \
	/*							\
	 * Tail call failed, continue normal XDP processing.	\
	 */							\
	return XFW_CTX_CONTINUE;				\
}

XDP_MODULE_FILTER(tcp_syn_drop, XFW_XDP_PROG_TCP_SYN_DROP_FILTER)
XDP_MODULE_FILTER(tcp_syncookies, XFW_XDP_PROG_TCP_SYNCOOKIES_FILTER)
XDP_MODULE_FILTER(dst, XFW_XDP_PROG_DST_FILTER)

#undef XDP_MODULE_FILTER

#define TC_MODULE_FILTER(name, index)				\
static __always_inline int					\
tc_##name##_module_filter(const XfwGlobalCtx *ctx)		\
{								\
	if (!xfw_set_packet_metadata(ctx, ctx->l4_off))		\
		return XFW_CTX_CONTINUE;			\
								\
	bpf_tail_call(ctx->ctx, &MAP_TC_PROG_ARRAY_REF, index); \
	/*							\
	 * Tail call failed, continue normal XDP processing.	\
	 */							\
	return XFW_CTX_CONTINUE;				\
}

TC_MODULE_FILTER(dst, XFW_TC_PROG_DST_FILTER)

#undef TC_MODULE_FILTER
