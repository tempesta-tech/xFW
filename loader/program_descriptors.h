/**
 *      Tempesta xFW BPF program descriptors
 *
 * SPDX-FileCopyrightText: © 2026 Tempesta Technologies, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#pragma once

#ifndef XFW_LIB_DIR
#error "XFW_LIB_DIR is not defined; check the loader build configuration"
#endif

#define XFW_BPF_LIB_DIR XFW_LIB_DIR "/" "bpf"

#define ARRAY_SIZE(array) \
	(sizeof(array) / sizeof((array)[0]))

/*
 * Add every new standalone BPF module to this file. Keeping all program
 * descriptors in one registry allows the loader implementation to remain
 * independent of the set of modules built into xFW.
 */
typedef struct MapDesc {
	const char *name;
} MapDesc;

typedef struct XfwProgram {
	const char *name;
	const char *obj_path;
	const char *prog_name;
	const char *prog_pin_name;

	/* Expected BPF program type. */
	enum bpf_prog_type prog_type;

	/*
	 * Maps that must be explicitly reused from another BPF object.
	 *
	 * This is intended for modules whose maps are not automatically
	 * reused through LIBBPF_PIN_BY_NAME and pin_root_path.
	 */
	const MapDesc *reuse_maps;
	size_t reuse_maps_cnt;

	/*
	 * Open the BPF object with pin_root_path. Maps declared with
	 * LIBBPF_PIN_BY_NAME will be automatically created or reused there.
	 */
	bool pin_maps;

	/* Register the loaded program in the global tail-call program array. */
	bool register_in_prog_array;
	uint32_t prog_array_idx;
} XfwProgram;

static const MapDesc tcp_syncookies_maps[] = {
	{ .name = MAP_GLBL_STAT_STR },
	{ .name = MAP_CFG_STR },
	{ .name = MAP_LOG_ACTIVE_FD_STR },
	{ .name = MAP_LOG_EVENTS_STR },
	{ .name = MAP_LOG_EV_CNT_STR },
	{ .name = MAP_RATELIMIT_STR },
	{ .name = MAP_TCP_CONN_STR },
	{ .name = MAP_DST_STR(MAP_PRIMARY_IDX) },
	{ .name = MAP_DST_STR(MAP_SECONDARY_IDX) },
};

static const XfwProgram tcp_syncookies_module = {
	.name = "tcp_syncookies",
	.obj_path = XFW_BPF_LIB_DIR "/" "tcp_syncookies.o",
	.prog_name = "xdp_tcp_syncookies",
	.prog_pin_name = "tcp_syncookies",
	.prog_type = BPF_PROG_TYPE_XDP,
	.reuse_maps = tcp_syncookies_maps,
	.reuse_maps_cnt = ARRAY_SIZE(tcp_syncookies_maps),
	.pin_maps = true,
	.register_in_prog_array = true,
	.prog_array_idx = XFW_PROG_TCP_SYNCOOKIES_FILTER,
};
