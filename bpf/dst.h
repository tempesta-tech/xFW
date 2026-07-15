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
	    
#define SHADOW_DST_MAP(basename, key_t)					\
	SHADOW_MAP(basename, BPF_MAP_TYPE_HASH, XFW_MAX_DST_RULES,	\
		    key_t, XfwActionRule, 0)

SHADOW_DST_MAP(MAP_DST_4_UDP_BASENAME, XfwDstKey);
SHADOW_DST_MAP(MAP_DST_4_TCP_BASENAME, XfwDstKey);
SHADOW_DST_MAP(MAP_DST_6_UDP_BASENAME, XfwDstKey);
SHADOW_DST_MAP(MAP_DST_6_TCP_BASENAME, XfwDstKey);


static __always_inline void
ipv4_populate_dst_key(const struct iphdr *ip4_hdr, int l4_proto,
	XfwDstKey *dst_key)
{
	dst_key->ipver = XFW_IP_VER_4;
	dst_key->proto = (uint8_t)l4_proto;
	xfw_ipv4_to_ipv6_mapped(ip4_hdr->daddr, dst_key->addr.addr32);
}

static __always_inline void
ipv6_populate_dst_key(const struct ipv6hdr *ip6_hdr, int l4_proto,
	XfwDstKey *dst_key)
{
	dst_key->ipver = XFW_IP_VER_6;
	dst_key->proto = (uint8_t)l4_proto;
	dst_key->addr.in6 = ip6_hdr->daddr;
}

static __always_inline bool
populate_dst_info(const XfwGlobalCtx *ctx, , void **dst_map,
		  XfwDstKey *key, __u8 *default_idx)
{
	if (ctx->th) {
		key->port = ctx->th->dest;
		if (ctx->iph4) {
			ipv4_populate_dst_key(ctx->iph4, ctx->l4_proto, key);
			*dst_map =  SELECT_SHADOW_MAP(MAP_DST_4_TCP_BASENAME,
						      ctx->cfg->amap_dst);
			*default_idx = XFW_DEFAULT_DST_TCP_IP4;
			return true;
		}
		if (ctx->iph6) {
			ipv6_populate_dst_key(ctx->iph6, ctx->l4_proto, key);
			*dst_map =  SELECT_SHADOW_MAP(MAP_DST_6_TCP_BASENAME,
						      ctx->cfg->amap_dst);
			*default_idx = XFW_DEFAULT_DST_TCP_IP6;
			return true;
		}
		return false;
	}
	if (ctx->uh) {
		key->port = ctx->uh->dest;
		if (ctx->iph4) {
			ipv4_populate_dst_key(ctx->iph4, ctx->l4_proto, key);
			*dst_map =  SELECT_SHADOW_MAP(MAP_DST_4_UDP_BASENAME,
						      ctx->cfg->amap_dst);
			*default_idx = XFW_DEFAULT_DST_UDP_IP4;
			return true;
		}
		if (ctx->iph6) {
			ipv6_populate_dst_key(ctx->iph6, ctx->l4_proto, key);
			*dst_map =  SELECT_SHADOW_MAP(MAP_DST_6_UDP_BASENAME,
						      ctx->cfg->amap_dst);
			*default_idx = XFW_DEFAULT_DST_UDP_IP6;
			return true;
		}
		return false;
	}
	return false;
}

static __always_inline int
xfw_dst_filter(const XfwGlobalCtx *ctx)
{
	void *dst_map;
	XfwDstKey dst_key;
	uint8_t dst_default;
	XFW_ASSERT(populate_dst_info(ctx, &dst_map, &dst_key, &dst_default));

	XfwActionRule *rule = bpf_map_lookup_elem(dst_map, &dst_key);
	if (!rule) {
		XfwActionRule *default_rule = &ctx->cfg->rules.defaults[dst_default];
		if (default_rule->action == XFW_ACTION_BLOCK)
			return XFW_MAKE_CTX_DROP_EXT(ctx, XFW_DST_BLOCKED, ": %pI6",
						     &dst_key.addr.in6,
						     "(by default action)");
		if (default_rule->action == XFW_ACTION_ALLOW)
			return XFW_CTX_CONTINUE;

		XFW_ASSERT(default_rule->action == XFW_ACTION_RATE_LIMIT);
		if (xfw_is_allowed_by_rlimits(ctx, &default_rule->rlimit))
			return XFW_CTX_CONTINUE;

		return XFW_MAKE_CTX_DROP_EXT(ctx, XFW_DST_RATE_LIMITED,
					     ": %pI6", &dst_key.addr.in6,
					     "(by default action)");
	}

	if (rule->action == XFW_ACTION_BLOCK)
		return XFW_MAKE_CTX_DROP_EXT(ctx, XFW_DST_BLOCKED, ": %pI6",
					     &dst_key.addr.in6);

	if (rule->action == XFW_ACTION_ALLOW)
		return XFW_CTX_CONTINUE;

	XFW_ASSERT(rule->action == XFW_ACTION_RATE_LIMIT);
	if (xfw_is_allowed_by_rlimits(ctx, &rule->rlimit))
		return XFW_CTX_CONTINUE;

	return XFW_MAKE_CTX_DROP_EXT(ctx, XFW_DST_RATE_LIMITED, ": %pI6",
				     &dst_key.addr.in6);
}

#undef BANNER
#pragma pop_macro("BANNER")
