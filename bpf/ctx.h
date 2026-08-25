/**
 *	Tempesta xFW packet context API
 *
 * SPDX-FileCopyrightText: © 2026 Tempesta Technologies, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#pragma once

#include "../bpf_uapi/config.h"
#include "../bpf_uapi/stats.h"
#include "../bpf_uapi/types.h"
#include "../bpf_uapi/map_names.h"
#include "compiler.h"

/* Use type redefinitions instead of typedefs to not to confuse BTF/CO-RE. */
#if defined(XFW_TC)
#define XfwMd				struct __sk_buff
#elif defined(XFW_XDP)
#define XfwMd				struct xdp_md
#else
#error "Undefined program type: should be TC or XDP"
#endif
#define XFW_CTX_MD(ctx)			((XfwMd *)ctx)
#define XFW_CTX_DATA_BGN(ctx)		((void *)(long)XFW_CTX_MD(ctx)->data)
#define XFW_CTX_DATA_END(ctx)		((void *)(long)XFW_CTX_MD(ctx)->data_end)

/*
 * Return code meaning that we should continue the packet processing through
 * all following finters.
 * Should be big enough so as not to match the XDP_* or TC_ACT_* values.
 */
#define XFW_CTX_CONTINUE		128

/**
 * A cursor for packet headers parsing.
 */
typedef struct XfwHdrCursor {
	void		*pos;
	void const	*end;
} XfwHdrCursor;

/**
 * Global processing context.
 * This is required as eBPF has a limit to 5 function arguments.
 *
 * The context is intentionally kept on the stack and passed through the call
 * chain to avoid unnecessary accesses to BPF maps. In some cases, verifier
 * limitations (for example, stack depth restrictions, tail calls, or program
 * splitting) may require moving part of the processing state (scalar values)
 * into a shared BPF map. This approach should be considered as a possible
 * optimization and compatibility strategy if verifier constraints become a
 * limiting factor (see doc/ebpf_verifier.md for more detailes).
 *
 * @ipver      - ETH_P_IP or ETH_P_IPV6
 * @ctx        - xdp_md or __sk_buff, depending on hook
 * @ts_jiff    - current jiffies timestamp shared by all filters
 * @l4_proto   - XFW_L4_PROTO_UDP or XFW_L4_PROTO_TCP if != 0
 */
typedef struct XfwGlobalCtx {
	XfwFilterCfg	*cfg;
	XfwPerCpuStats	*g_stats;
	XfwTcpConnAddr	addr;
	XfwHdrCursor	hdr_cur;
	uint32_t	pkt_sz;
	uint16_t	ipver;
	uint8_t		l4_proto;
	XfwMd		*ctx;
	struct ethhdr	*eth;
	union {
		void		*iph;
		struct iphdr	*iph4;
		struct ipv6hdr	*iph6;
	};
	union {
		struct tcphdr	*th;
		struct udphdr	*uh;
	};
	uint64_t	ts_jiff;
} XfwGlobalCtx;

/* Read-only for eBPF. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, uint32_t);
	__type(value, XfwFilterCfg);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, 1);
} MAP_CFG_REF SEC(".maps");

/* Read-only for the manager, write-only for eBPF. */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, uint32_t);
	__type(value, XfwPerCpuStats);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, 1);
} MAP_GLBL_STAT_REF SEC(".maps");

#define INIT_CURSOR_FROM_BPF_CONTEXT(pkt_ctx, cur)			\
do {									\
	(cur)->pos = XFW_CTX_DATA_BGN(pkt_ctx);				\
	(cur)->end = XFW_CTX_DATA_END(pkt_ctx);				\
} while (0)

static __always_inline void
xfw_ctx_init(XfwGlobalCtx *ctx, XfwMd *pkt_ctx)
{
	const unsigned zero = 0;

	memset(ctx, 0, sizeof(*ctx));
	/*
	 * TODO #224: probably we can merge these 2 maps and even with
	 * the syncookies map.
	 * Consider also libbpf skeleton (e.g. linux-6.12.12-tfw/tools/bpf/runqslower)
	 * to use the configuration as static variables and avoid maps at all.
	 */
	ctx->cfg = bpf_map_lookup_elem(&MAP_CFG_REF, &zero);
	ctx->g_stats = bpf_map_lookup_elem(&MAP_GLBL_STAT_REF, &zero);
	INIT_CURSOR_FROM_BPF_CONTEXT(pkt_ctx, &ctx->hdr_cur);
	ctx->pkt_sz = ctx->hdr_cur.end - ctx->hdr_cur.pos;
	ctx->ctx = pkt_ctx;
	ctx->ts_jiff = bpf_jiffies64();
}
