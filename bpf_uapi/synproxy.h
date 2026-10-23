/**
 *	Tempesta xFW gateway SYN proxy shared interface
 *
 * SPDX-FileCopyrightText: © 2026 Tempesta Technologies, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#pragma once

#include "types.h"

#define XFW_SYNPROXY_MAX_TARGETS		2000
#define XFW_SYNPROXY_MAX_RETIRED		4000
#define XFW_SYNPROXY_GRACE_NS		120000000000ULL
#define XFW_SYNPROXY_PORT_BITS		32
#define XFW_SYNPROXY_MSS4			536
#define XFW_SYNPROXY_MSS6			1220

/* The port and zero padding form the fixed part of each LPM key. */
typedef struct XfwSynproxyKey4 {
	uint32_t	prefixlen;
	__be16		port;
	uint16_t	reserved;
	__be32		addr;
} XfwSynproxyKey4;

typedef struct XfwSynproxyKey6 {
	uint32_t	prefixlen;
	__be16		port;
	uint16_t	reserved;
	__be32		addr[4];
} XfwSynproxyKey6;

/* One immutable candidate per slot; sp_gen publishes its slot with bit zero. */
typedef struct XfwSynproxyMeta {
	uint64_t	retired_until_ns;
	uint32_t	active_count;
	uint32_t	retired_count;
} XfwSynproxyMeta;

STATIC_ASSERT(sizeof(XfwSynproxyKey4) == 12, "Invalid SYN proxy IPv4 key");
STATIC_ASSERT(sizeof(XfwSynproxyKey6) == 24, "Invalid SYN proxy IPv6 key");
STATIC_ASSERT(sizeof(XfwSynproxyMeta) == 16, "Invalid SYN proxy metadata");
