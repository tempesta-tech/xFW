/**
 *	Tempesta xFW logging facilities
 *
 * SPDX-FileCopyrightText: © 2026 Tempesta Technologies, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#pragma once

#include "vmlinux.h"

/*
 * BANNER must be defined before including the file to show the subsystem in
 * the debug messages.
 * The header should be included first to not to confuse the variable definition.
 */
#pragma push_macro("BANNER")
#undef BANNER
#define BANNER "main"

#ifdef XFW_DEBUG

uint32_t pkt_id = 0;
#define XFW_DBG_INIT() pkt_id = bpf_get_prandom_u32()
#define XFW_DBG(fmt, args...)				\
	bpf_printk("[" BANNER "] pkt %x, " fmt, pkt_id, ##args)

#else

#define XFW_DBG_INIT(ctx)
#define XFW_DBG(fmt, ...)

#endif /* XFW_DEBUG */

#if defined(XFW_TC)
#define XFW_CTX_DBG(fmt, args...)	XFW_DBG("[out] " fmt, ##args)

#elif defined(XFW_XDP) || defined(XFW_TCP_SYN_DROP) || defined(XFW_TCP_SYNCOOKIES)
#define XFW_CTX_DBG(fmt, args...)	XFW_DBG("[in] " fmt, ##args)
#endif

/*
 * Prefer to use the macro for the verifier specific checks, not the logic
 * necessary checks, e.g.
 *
 *   VERIFY_TRUE_OR_RETURN(foo, -EINVAL); // just to satisfy the verifier
 *
 *   if (unlikely(bar))			  // normal program logic
 *   	return XFW_MAKE_CTX_DROP(...);
 */
#define VERIFY_TRUE_OR_RETURN(v, r)					\
do {									\
	if (unlikely(!(v))) {						\
		XFW_CTX_DBG("Failed assertion at %s:%d: " #v,		\
			    __func__, __LINE__);			\
		return (r);						\
	}								\
} while (0)

/*
 * In case of failed assertion pass traffic - it's better to pass some DDoS
 * traffic than to have a false positive.
 */
#define XFW_ASSERT(v)							\
	VERIFY_TRUE_OR_RETURN((v), XFW_MAKE_CTX_PASS(ctx, XFW_ASSERT_FAILED))

#undef BANNER
#pragma pop_macro("BANNER")
