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
#include "parsing_helpers.h"

SHADOW_MAP(MAP_DST_BASENAME, BPF_MAP_TYPE_HASH, XFW_MAX_DST_RULES, XfwDstKey,
	    XfwActionRule, 0);

/*
 * #VerifierOptimization:
 *
 * A previous implementation populated key->ipver, key->proto and
 * key->addr after selecting ctx->th/ctx->uh. Although slower at runtime,
 * that version resulted in faster verification (smaller verifier state
 * space). The current ordering favors runtime performance.
 *
 * Revisit this ordering if a better verifier/runtime trade-off is found,
 * or if verifier complexity or XDP program load time becomes a more
 * important concern than runtime performance.
 */
static __always_inline bool
populate_dst_info(const XfwGlobalCtx *ctx, XfwDstKey *key, __u8 *default_idx)
{
	VERIFY_TRUE_OR_RETURN(ctx->l4_off <= L4_OFF_MAX, false);
	key->proto = (uint8_t)ctx->l4_proto;
	if (ctx->ipver == bpf_ntohs(ETH_P_IP)) {
		struct iphdr *iph4 =
			XFW_PKT_PTR(ctx, ctx->ip_off, struct iphdr);
		VERIFY_TRUE_OR_RETURN((void *)(iph4 + 1) <= ctx->hdr_cur.end,
				      false);
		key->ipver = XFW_IP_VER_4;
		xfw_assign_ip4_addr(iph4->daddr, key->addr.addr32);
		if (ctx->l4_proto == XFW_L4_PROTO_TCP) {
			struct tcphdr *th =
				XFW_PKT_PTR(ctx, ctx->l4_off, struct tcphdr);
			VERIFY_TRUE_OR_RETURN((void *)(th + 1) <= ctx->hdr_cur.end,
					      false);
			key->port = th->dest;
			*default_idx = XFW_DEFAULT_DST_TCP_IP4;
			return true;
		}
		if (ctx->l4_proto == XFW_L4_PROTO_UDP) {
			struct udphdr *uh =
				XFW_PKT_PTR(ctx, ctx->l4_off, struct udphdr);
			VERIFY_TRUE_OR_RETURN((void *)(uh + 1) <= ctx->hdr_cur.end,
					      false);
			key->port = uh->dest;
			*default_idx = XFW_DEFAULT_DST_UDP_IP4;
			return true;
		}
		return false;
	}
	if (ctx->ipver == bpf_ntohs(ETH_P_IPV6)) {
		struct ipv6hdr *iph6 =
			XFW_PKT_PTR(ctx, ctx->ip_off, struct ipv6hdr);
		VERIFY_TRUE_OR_RETURN((void *)(iph6 + 1) <= ctx->hdr_cur.end,
				      false);
		key->ipver = XFW_IP_VER_6;
		key->addr.in6 = iph6->daddr;
		if (ctx->l4_proto == XFW_L4_PROTO_TCP) {
			struct tcphdr *th =
				XFW_PKT_PTR(ctx, ctx->l4_off, struct tcphdr);
			VERIFY_TRUE_OR_RETURN((void *)(th + 1) <= ctx->hdr_cur.end,
					      false);
			key->port = th->dest;
			*default_idx = XFW_DEFAULT_DST_TCP_IP6;
			return true;
		}
		if (ctx->l4_proto == XFW_L4_PROTO_UDP) {
			struct udphdr *uh =
				XFW_PKT_PTR(ctx, ctx->l4_off, struct udphdr);
			VERIFY_TRUE_OR_RETURN((void *)(uh + 1) <= ctx->hdr_cur.end,
					      false);
			key->port = uh->dest;
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
	XfwDstKey dst_key;
	uint8_t dst_default;

	XFW_ASSERT(populate_dst_info(ctx, &dst_key, &dst_default));

	XfwActionRule *rule = bpf_map_lookup_elem(
		SELECT_SHADOW_MAP(MAP_DST_BASENAME, ctx->cfg->amap_dst), &dst_key);

	if (!rule) {
		XfwActionRule *default_rule = &ctx->cfg->rules.defaults[dst_default];
		if (default_rule->action == XFW_ACTION_BLOCK)
			return XFW_MAKE_CTX_DROP_EXT(ctx, XFW_DROP_DST_BLOCKED, ": %pI6",
						     &dst_key.addr.in6,
						     "(by default action)");
		if (default_rule->action == XFW_ACTION_ALLOW)
			return XFW_CTX_CONTINUE;

		XFW_ASSERT(default_rule->action == XFW_ACTION_RATE_LIMIT);
		if (xfw_is_allowed_by_rlimits(ctx, &default_rule->rlimit))
			return XFW_CTX_CONTINUE;

		return XFW_MAKE_CTX_DROP_EXT(ctx, XFW_DROP_DST_RATE_LIMITED,
					     ": %pI6", &dst_key.addr.in6,
					     "(by default action)");
	}

	if (rule->action == XFW_ACTION_BLOCK)
		return XFW_MAKE_CTX_DROP_EXT(ctx, XFW_DROP_DST_BLOCKED, ": %pI6",
					     &dst_key.addr.in6);

	if (rule->action == XFW_ACTION_ALLOW)
		return XFW_CTX_CONTINUE;

	XFW_ASSERT(rule->action == XFW_ACTION_RATE_LIMIT);
	if (xfw_is_allowed_by_rlimits(ctx, &rule->rlimit))
		return XFW_CTX_CONTINUE;

	return XFW_MAKE_CTX_DROP_EXT(ctx, XFW_DROP_DST_RATE_LIMITED, ": %pI6",
				     &dst_key.addr.in6);
}

#undef BANNER
#pragma pop_macro("BANNER")
