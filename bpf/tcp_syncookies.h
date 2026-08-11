/**
 *	Tempesta xFW TCP SYN Cookies implementation
 *
 * The design reference is "Issuing SYN Cookies in XDP" by P.Penkov et al,
 * https://netdevconf.info/0x14/pub/papers/50/0x14-paper50-talk-paper.pdf
 *
 * SPDX-FileCopyrightText: © 2026 Tempesta Technologies, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#pragma once

#include "vmlinux.h"

#pragma push_macro("BANNER")
#undef BANNER
#define BANNER "syncookie"

/*
 * Timestamps used to control SYN cookie generation frequency. These globals are
 * accessed lock-free. In the worst case, cookie generation may temporarily 
 * deviate from the configured rules, but this does not affect correctness.
 *
 * @last_try	- Time of the last SYN cookie attempt
 * @last_gen_ts	- Time of the last SYN cookie successfully generated
 */
typedef struct XfwTcpSynCookieTs {
	uint64_t	last_try_jiff;
	uint64_t	last_gen_jiff;
} XfwTcpSynCookieTs;

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, uint32_t);
	__type(value, XfwTcpSynCookieTs);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, 1);
} MAP_SYNCOOKIES_REF SEC(".maps");

static __always_inline XfwTcpSynCookieTs *
__tcp_get_tcp_syncookie_ts(void)
{
	const uint32_t zero_idx = 0;

	return bpf_map_lookup_elem(&MAP_SYNCOOKIES_REF, &zero_idx);
}

/**
 * Check if SYN cookie flood mode should be active.
 *
 * Flood mode is active if the time since the last SYN cookie
 * generation is less than flood_timer. In this mode, cookie
 * generation/validation is never skipped.
 */
static __always_inline bool
tcp_syncookies_flood_mode(const XfwGlobalCtx *ctx, XfwTcpSynCookieTs *ts)
{
	if (ctx->cfg->rules.syncookie.flood_timer_jiff
	    >= ctx->ts_jiff - ts->last_gen_jiff)
	{
		XFW_CTX_DBG("Flood mode is on");
		ts->last_try_jiff = ctx->ts_jiff;
		return true;
	}
	return false;
}

#undef BANNER
#pragma pop_macro("BANNER")
