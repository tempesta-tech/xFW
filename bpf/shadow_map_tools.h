/**
 *	Tempesta xFW tools for shadow maps.
 *
 * SPDX-FileCopyrightText: © 2026 Tempesta Technologies, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Filter updates are staged in a shadow copy of each rule map. The datapath
 * keeps reading the currently selected copy while userspace rewrites the other
 * one, then publishes the new selector in XfwFilterCfg.
 */
#pragma once

#ifndef BPF_PROGRAM
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#else
#include "../generated/vmlinux.h"
#endif

#include "../map_names.h"

#define SHADOW_MAP_SLOT(basename, idx, map_t, max_sz, key_t, val_t, flags)	\
	struct {								\
		__uint(type, map_t);						\
		__type(key, key_t);						\
		__type(value, val_t);						\
		__uint(max_entries, max_sz);					\
		__uint(map_flags, flags);					\
		__uint(pinning, LIBBPF_PIN_BY_NAME);				\
	} SHADOW_MAP_REF(basename, idx) SEC(".maps")

#define SHADOW_MAP(basename, map_t, max_sz, key_t, val_t, flags)		\
	CHECK_MAP_NAME_LEN(SHADOW_MAP_STR(basename, MAP_PRIMARY_IDX));		\
	CHECK_MAP_NAME_LEN(SHADOW_MAP_STR(basename, MAP_SECONDARY_IDX));	\
	SHADOW_MAP_SLOT(basename, MAP_PRIMARY_IDX, map_t, max_sz,		\
			key_t, val_t, flags);					\
	SHADOW_MAP_SLOT(basename, MAP_SECONDARY_IDX, map_t, max_sz,		\
			key_t, val_t, flags)
