/**
 *	Tempesta xFW ingress eBPF processing, tcp anomaly part
 *
 * SPDX-FileCopyrightText: © 2026 Tempesta Technologies, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "../generated/vmlinux.h"
#include "../statistics.h"

#pragma push_macro("BANNER")
#undef BANNER
#define BANNER "tcp-anomaly"
#include "log.h"

#include "bitset_tools.h"
#include "filter.h"
#include "parsing_helpers.h"

static __always_inline int
tcp_anomaly_filter(const XfwGlobalCtx *ctx)
{
	if (!ctx->cfg->rules.tcp_anomaly.enabled)
		return XFW_CTX_CONTINUE;

	/* Take correct 8-bit TCP flags from words[3] */
	const uint8_t tcp_flags = (uint8_t)((tcp_flag_word(ctx->th) >> 8) & 0xFF);
	bool r = bpf_bitset64_test(ctx->cfg->rules.tcp_anomaly.bad_flags.data,
				   tcp_flags);
	if (unlikely(r))
		return XFW_MAKE_CTX_DROP_EXT(ctx, XFW_TCP_ANOM_BAD_FLAGS,
					     ": flag_word=%u", tcp_flags);

	/*
	 * TCP port 0 is reserved and MUST NOT be used for normal communication.
	 * Packets with source or destination port 0 are considered invalid.
	 *
	 * RFC 6335, Section 6:
	 *   "Reserved port numbers are not available for regular assignment;
	 *    they are 'assigned to IANA' for special purposes. Reserved port
	 *    numbers include values at the edges of each range, e.g., 0, 1023,
	 *    1024, etc."
	 */
	if (unlikely(ctx->th->source == 0 || ctx->th->dest == 0))
		return XFW_MAKE_CTX_DROP(ctx, XFW_TCP_ANOM_ZERO_PORT);

	if (!ctx->th->syn)
		return XFW_CTX_CONTINUE;

	if (unlikely(ctx->cfg->rules.tcp_anomaly.syn_without_opt_enabled
		     && ctx->th->doff <= 5))
		return XFW_MAKE_CTX_DROP(ctx, XFW_TCP_ANOM_SYN_NO_OPTIONS);

	if (unlikely(ctx->cfg->rules.tcp_anomaly.syn_with_payload_enabled
		     && (void *)ctx->th + ctx->th->doff * 4 < ctx->hdr_cur.end))
		return XFW_MAKE_CTX_DROP(ctx, XFW_TCP_ANOM_SYN_HAS_DATA);

	if (unlikely(ctx->cfg->rules.tcp_anomaly.syn_seqno_enabled
		     && ctx->th->seq == ctx->cfg->rules.tcp_anomaly.syn_seqno_value))
		return XFW_MAKE_CTX_DROP(ctx, XFW_TCP_ANOM_SYN_BAD_SEQ);

	return XFW_CTX_CONTINUE;
}

#undef BANNER
#pragma pop_macro("BANNER")
