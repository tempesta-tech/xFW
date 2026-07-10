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
#ifndef BANNER
#define BANNER "main"
#endif

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

#elif defined(XFW_XDP)
#define XFW_CTX_DBG(fmt, args...)	XFW_DBG("[in] " fmt, ##args)
#endif

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
