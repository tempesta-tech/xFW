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

/**
 * Define a dispatcher for an XDP tail-call module.
 *
 * The caller must reserve packet metadata before parsing and invoke the
 * dispatcher only after the required L3/L4 context fields have been
 * populated. No operation between metadata reservation and this call may
 * invalidate data_meta. Under these preconditions,
 * xfw_set_packet_metadata() must succeed; failure indicates an internal
 * invariant violation.
 *
 * A successful bpf_tail_call() transfers control to the selected module
 * and does not return. Reaching the following code means that the module
 * could not be invoked, for example because its program-array entry is
 * missing. Return a drop decision because continuing would bypass the
 * protection provided by an enabled module.
 *
 * @module_name - Module identifier used to generate the dispatcher name.
 * @index       - Module program index in MAP_PROG_ARRAY_REF.
 */
#define XDP_MODULE_FILTER(module_name, index)				\
static __always_inline int						\
xdp_##module_name##_module_filter(XfwGlobalCtx *ctx)			\
{									\
	XFW_ASSERT(xfw_set_packet_metadata(ctx));			\
									\
	bpf_tail_call(ctx->ctx, &MAP_PROG_ARRAY_REF, index);		\
									\
	return XFW_MAKE_CTX_DROP(ctx, XFW_DROP_TAIL_CALL_FAILED);	\
}									\

XDP_MODULE_FILTER(tcp_syncookies, XFW_PROG_TCP_SYNCOOKIES_FILTER)
