/**
 *	Tempesta xFW destination filter
 *
 * This is the last protection layer limiting the overall traffic going to
 * the protected endpoint.
 *
 * SPDX-FileCopyrightText: © 2026 Tempesta Technologies, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#pragma once

#pragma push_macro("BANNER")
#undef BANNER
#define BANNER "dst"
#include "log.h"

#include "filter.h"

SHADOW_MAP(MAP_DST_BASENAME, BPF_MAP_TYPE_HASH, XFW_MAX_DST_RULES, XfwDstKey,
	    XfwActionRule, 0);

static __always_inline uint8_t
xfw_dst_default_by_key(const XfwDstKey *dst_key)
{
	uint8_t dst_default;

	/*
	 * XfwDstKey::ipver uses XFW_IP_VER_4/6. This differs from
	 * XfwGlobalCtx::ipver, which stores ETH_P_IP/ETH_P_IPV6.
	 */
	if (dst_key->ipver == XFW_IP_VER_4) {
		if (dst_key->proto == XFW_L4_PROTO_TCP) {
			dst_default = XFW_DEFAULT_DST_TCP_IP4;
		} else {
			/* XFW_L4_PROTO_UDP */
			dst_default = XFW_DEFAULT_DST_UDP_IP4;
		}
	} else {
		/* ETH_P_IPV6 */
		if (dst_key->proto == XFW_L4_PROTO_TCP) {
			dst_default = XFW_DEFAULT_DST_TCP_IP6;
		} else {
			/* XFW_L4_PROTO_UDP */
			dst_default = XFW_DEFAULT_DST_UDP_IP6;
		}
	}

	return dst_default;
}

static __always_inline int
xfw_dst_filter(const XfwGlobalCtx *ctx, const XfwDstKey *dst_key)
{
	XfwActionRule *rule = bpf_map_lookup_elem(
		SELECT_SHADOW_MAP(MAP_DST_BASENAME, ctx->cfg->amap_dst),
				   dst_key);

	if (!rule) {
		uint8_t dst_default = xfw_dst_default_by_key(dst_key);
		XfwActionRule *default_rule = &ctx->cfg->rules.defaults[dst_default];
		if (default_rule->action == XFW_ACTION_BLOCK)
			return XFW_MAKE_CTX_DROP_EXT(ctx, XFW_DST_BLOCKED, ": %pI6",
						     &dst_key->addr.in6,
						     "(by default action)");
		if (default_rule->action == XFW_ACTION_ALLOW)
			return XFW_CTX_CONTINUE;

		XFW_ASSERT(default_rule->action == XFW_ACTION_RATE_LIMIT);
		if (xfw_is_allowed_by_rlimits(ctx, &default_rule->rlimit))
			return XFW_CTX_CONTINUE;

		return XFW_MAKE_CTX_DROP_EXT(ctx, XFW_DST_RATE_LIMITED,
					     ": %pI6", &dst_key->addr.in6,
					     "(by default action)");
	}

	if (rule->action == XFW_ACTION_BLOCK)
		return XFW_MAKE_CTX_DROP_EXT(ctx, XFW_DST_BLOCKED, ": %pI6",
					     &dst_key->addr.in6);

	if (rule->action == XFW_ACTION_ALLOW)
		return XFW_CTX_CONTINUE;

	XFW_ASSERT(rule->action == XFW_ACTION_RATE_LIMIT);
	if (xfw_is_allowed_by_rlimits(ctx, &rule->rlimit))
		return XFW_CTX_CONTINUE;

	return XFW_MAKE_CTX_DROP_EXT(ctx, XFW_DST_RATE_LIMITED, ": %pI6",
				     &dst_key->addr.in6);
}

#undef BANNER
#pragma pop_macro("BANNER")
