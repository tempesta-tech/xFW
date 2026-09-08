/**
 *      Tempesta Management custom libbpf loader
 *
 * Loads xFW XDP and TC programs with the required BPF program types and
 * manages shared pinned maps between the program objects.
 *
 * SPDX-FileCopyrightText: © 2026 Tempesta Technologies, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <limits.h>
#include <net/if.h>

#include <linux/bpf.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "../bpf_uapi/map_names.h"

#ifndef XFW_LIB_DIR
#error "XFW_LIB_DIR is not defined; check the loader build configuration"
#endif

#define XFW_BPF_LIB_DIR XFW_LIB_DIR "/" "bpf"

#define ARRAY_SIZE(array) \
	(sizeof(array) / sizeof((array)[0]))

typedef struct MapDesc {
	const char *name;
} MapDesc;

typedef struct XfwProgram {
	const char *name;
	const char *obj_path;
	const char *prog_name;
	const char *prog_pin_name;

	/*
	 * Expected BPF program type.
	 */
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
	 * Open the BPF object with pin_root_path.
	 *
	 * Maps declared with LIBBPF_PIN_BY_NAME will be automatically
	 * created or reused under pin_root.
	 */
	bool pin_maps;
} XfwProgram;

static const XfwProgram main_xdp = {
	.name = "xdp",
	.obj_path = XFW_BPF_LIB_DIR "/" "xdp.o",
	.prog_name = "xfw_xdp",
	.prog_pin_name = "xdp",
	.prog_type = BPF_PROG_TYPE_XDP,
	.reuse_maps = NULL,
	.reuse_maps_cnt = 0,
	/*
	 * The main XDP object creates and owns the shared maps.
	 */
	.pin_maps = true,
};

static const MapDesc tc_maps[] = {
	{ .name = MAP_GLBL_STAT_STR },
	{ .name = MAP_CFG_STR },
	{ .name = MAP_LOG_ACTIVE_FD_STR },
	{ .name = MAP_LOG_EVENTS_STR },
	{ .name = MAP_LOG_EV_CNT_STR },
	{ .name = MAP_RATELIMIT_STR },
	{ .name = MAP_DNS_EGR_FD_STR },
	{ .name = MAP_TCP_CONN_STR },
	{ .name = MAP_DST_STR(MAP_PRIMARY_IDX) },
	{ .name = MAP_DST_STR(MAP_SECONDARY_IDX) },
};

static const XfwProgram main_tc = {
	.name = "tc",
	.obj_path = XFW_BPF_LIB_DIR "/" "tc.o",
	.prog_name = "xfw_tc",
	.prog_pin_name = "tc",
	.prog_type = BPF_PROG_TYPE_SCHED_CLS,
	.reuse_maps = tc_maps,
	.reuse_maps_cnt = ARRAY_SIZE(tc_maps),
	/*
	 * Shared maps are explicitly reused, while TC-specific maps are
	 * created and pinned under the common pin root.
	 */
	.pin_maps = true,
};

static const XfwProgram *programs[] = {
	&main_xdp,
	&main_tc,
};

static void
usage(const char *prog)
{
	fprintf(stderr,
		"Usage:\n"
		"  %s load <program> <pin-root>\n"
		"  %s unload <program> <pin-root>\n"
		"  %s attach tc <pin-root> <device>\n"
		"  %s detach tc <pin-root> <device>\n"
		"\n"
		"Programs:\n"
		"  xdp\n"
		"  tc\n"
		"\n"
		"Examples:\n"
		"  %s load xdp /sys/fs/bpf/xfw\n"
		"  %s load tc /sys/fs/bpf/xfw\n"
		"  %s attach tc /sys/fs/bpf/xfw enp1s0\n"
		"  %s detach tc /sys/fs/bpf/xfw enp1s0\n"
		"  %s unload tc /sys/fs/bpf/xfw\n"
		"  %s unload xdp /sys/fs/bpf/xfw\n",
		prog, prog, prog, prog,
		prog, prog, prog, prog, prog, prog);
}

static const XfwProgram *
find_program(const char *name)
{
	size_t i;

	for (i = 0; i < ARRAY_SIZE(programs); i++) {
		if (!strcmp(programs[i]->name, name))
			return programs[i];
	}

	return NULL;
}

static int
make_pin_path(char *buf, size_t buf_size,
	      const char *pin_root, const char *name)
{
	int n;

	n = snprintf(buf, buf_size, "%s/%s", pin_root, name);
	if (n < 0)
		return -EIO;

	if ((size_t)n >= buf_size) {
		fprintf(stderr, "BPF pin path is too long: '%s/%s'\n",
			pin_root, name);
		return -ENAMETOOLONG;
	}

	return 0;
}

static int
check_path_absent(const char *path)
{
	int err;

	if (access(path, F_OK) == 0) {
		fprintf(stderr, "BPF object is already pinned at '%s'\n", path);
		return -EEXIST;
	}

	if (errno == ENOENT)
		return 0;

	err = -errno;
	fprintf(stderr, "Failed to check '%s': %s\n", path, strerror(-err));

	return err;
}

static int
check_pin_root(const char *path)
{
	int err;

	if (access(path, F_OK) == 0)
		return 0;

	err = -errno;
	fprintf(stderr, "Pin root '%s' is not accessible: %s\n",
		path, strerror(-err));

	return err;
}

static int
make_tc_link_pin_path(char *buf, size_t buf_size, const char *pin_root,
		      const char *device)
{
	int n;

	n = snprintf(buf, buf_size, "%s/tcx-%s-egress", pin_root, device);
	if (n < 0)
		return -EIO;

	if ((size_t)n >= buf_size) {
		fprintf(stderr, "TCX link pin path is too long: "
			"'%s/tcx-%s-egress'\n", pin_root, device);
		return -ENAMETOOLONG;
	}

	return 0;
}

/*
 * Reuse an already pinned map instead of creating a new instance.
 *
 * The main XDP object owns shared maps. Other programs explicitly
 * replace their object-local maps with these pinned instances.
 */
static int
reuse_map(struct bpf_object *obj, const char *map_name, const char *pin)
{
	struct bpf_map *map;
	int fd;
	int err;

	fd = bpf_obj_get(pin);
	if (fd < 0) {
		err = -errno;
		fprintf(stderr, "Cannot open pinned map '%s': %s\n",
			pin, strerror(-err));
		return err;
	}

	map = bpf_object__find_map_by_name(obj, map_name);
	if (!map) {
		err = -ENOENT;
		fprintf(stderr, "Map '%s' was not found in object\n",
			map_name);
		goto out;
	}

	err = bpf_map__reuse_fd(map, fd);
	if (err) {
		fprintf(stderr, "Failed to reuse FD for map '%s': %s\n",
			map_name, strerror(-err));
		goto out;
	}

	/*
	 * The map is owned and pinned by another BPF object.
	 * Do not try to pin it again while loading this object.
	 */
	err = bpf_map__set_pin_path(map, NULL);
	if (err) {
		fprintf(stderr,
			"Failed to disable pinning for map '%s': %s\n",
			map_name, strerror(-err));
	}

out:
	close(fd);

	return err;
}

static int
attach_tc(const XfwProgram *desc, const char *pin_root,
	  const char *device)
{
	LIBBPF_OPTS(bpf_link_create_opts, opts);
	char prog_pin[PATH_MAX];
	char link_pin[PATH_MAX];
	unsigned int ifindex;
	int prog_fd = -1;
	int link_fd = -1;
	int err;

	if (desc->prog_type != BPF_PROG_TYPE_SCHED_CLS) {
		fprintf(stderr, "Program '%s' has type %d, expected TC type %d\n",
			desc->name, desc->prog_type, BPF_PROG_TYPE_SCHED_CLS);
		return -EINVAL;
	}

	err = check_pin_root(pin_root);
	if (err)
		return err;

	ifindex = if_nametoindex(device);
	if (!ifindex) {
		err = errno ? -errno : -ENODEV;
		fprintf(stderr, "Failed to find network interface '%s': %s\n",
			device, strerror(-err));
		return err;
	}

	err = make_pin_path(prog_pin, sizeof(prog_pin), pin_root,
			    desc->prog_pin_name);
	if (err)
		return err;

	err = make_tc_link_pin_path(link_pin, sizeof(link_pin), pin_root, device);
	if (err)
		return err;

	err = check_path_absent(link_pin);
	if (err)
		return err;

	prog_fd = bpf_obj_get(prog_pin);
	if (prog_fd < 0) {
		err = -errno;
		fprintf(stderr, "Failed to open pinned program '%s': %s\n",
			prog_pin, strerror(-err));
		return err;
	}

	link_fd = bpf_link_create(prog_fd, ifindex, BPF_TCX_EGRESS, &opts);
	if (link_fd < 0) {
		err = -errno;
		fprintf(stderr, "Failed to attach TCX egress program '%s' "
			"to device '%s': %s\n", desc->prog_name, device,
			strerror(-err));
		goto out;
	}

	if (bpf_obj_pin(link_fd, link_pin)) {
		err = -errno;
		fprintf(stderr, "Failed to pin TCX link at '%s': %s\n",
			link_pin, strerror(-err));
		goto out;
	}

	printf("Attached TCX egress program '%s' to '%s'\n",
	       desc->prog_name, device);
	printf("TCX link pin: %s\n", link_pin);

	err = 0;

out:
	if (link_fd >= 0)
		close(link_fd);
	if (prog_fd >= 0)
		close(prog_fd);

	return err;
}

static int
detach_tc(const XfwProgram *desc, const char *pin_root,
	  const char *device)
{
	char link_pin[PATH_MAX];
	int err;

	if (desc->prog_type != BPF_PROG_TYPE_SCHED_CLS) {
		fprintf(stderr,
			"Program '%s' has type %d, expected TC type %d\n",
			desc->name, desc->prog_type,
			BPF_PROG_TYPE_SCHED_CLS);
		return -EINVAL;
	}

	err = make_tc_link_pin_path(link_pin, sizeof(link_pin),
				     pin_root, device);
	if (err)
		return err;

	if (unlink(link_pin)) {
		if (errno == ENOENT) {
			printf("TCX egress program '%s' is not attached "
			       "to '%s'\n",
			       desc->prog_name, device);
			return 0;
		}

		err = -errno;
		fprintf(stderr,
			"Failed to unlink TCX link '%s': %s\n",
			link_pin, strerror(-err));
		return err;
	}

	printf("Detached TCX egress program '%s' from '%s'\n",
	       desc->prog_name, device);

	return 0;
}

/*
 * Load and pin a BPF program.
 *
 * Programs opened with pin_root_path automatically create or reuse
 * maps declared with LIBBPF_PIN_BY_NAME under the specified directory.
 */
static int
load_program(const XfwProgram *desc, const char *pin_root)
{
	LIBBPF_OPTS(bpf_object_open_opts, opts);
	struct bpf_object *obj = NULL;
	struct bpf_program *prog;
	char prog_pin[PATH_MAX];
	char map_pin[PATH_MAX];
	size_t i;
	int err;

	err = check_pin_root(pin_root);
	if (err)
		return err;

	err = make_pin_path(prog_pin, sizeof(prog_pin),
			    pin_root, desc->prog_pin_name);
	if (err)
		return err;

	err = check_path_absent(prog_pin);
	if (err)
		return err;

	/*
	 * Programs with pin_maps enabled use pin_root_path for maps declared
	 * with LIBBPF_PIN_BY_NAME.
	 */
	if (desc->pin_maps)
		opts.pin_root_path = pin_root;

	obj = bpf_object__open_file(desc->obj_path,
				    desc->pin_maps ? &opts : NULL);
	if (!obj) {
		err = -errno;
		fprintf(stderr, "Failed to open BPF object '%s': %s\n",
			desc->obj_path, strerror(-err));
		return err;
	}

	/*
	 * Replace module-local maps with already pinned instances created
	 * by the main XDP program.
	 */
	for (i = 0; i < desc->reuse_maps_cnt; i++) {
		err = make_pin_path(map_pin, sizeof(map_pin),
				    pin_root, desc->reuse_maps[i].name);
		if (err)
			goto out;

		err = reuse_map(obj, desc->reuse_maps[i].name, map_pin);
		if (err)
			goto out;
	}

	prog = bpf_object__find_program_by_name(obj, desc->prog_name);
	if (!prog) {
		fprintf(stderr, "Program '%s' was not found in '%s'\n",
			desc->prog_name, desc->obj_path);
		err = -ENOENT;
		goto out;
	}

	if (bpf_program__type(prog) != desc->prog_type) {
		fprintf(stderr, "Program '%s' has type %d, expected type %d\n",
			desc->prog_name, bpf_program__type(prog),
			desc->prog_type);
		err = -EINVAL;
		goto out;
	}

	err = bpf_object__load(obj);
	if (err) {
		fprintf(stderr, "Failed to load '%s': %s\n",
			desc->obj_path, strerror(-err));
		goto out;
	}

	/*
	 * Pin the program so that it can later be attached or referenced
	 * independently of this loader process.
	 */
	err = bpf_program__pin(prog, prog_pin);
	if (err) {
		fprintf(stderr, "Failed to pin '%s' at '%s': %s\n",
			desc->prog_name, prog_pin, strerror(-err));
		goto out;
	}

	printf("Loaded program '%s'\n", desc->prog_name);
	printf("Program pin: %s\n", prog_pin);

out:
	bpf_object__close(obj);

	return err;
}

static int
unload_program(const XfwProgram *desc, const char *pin_root)
{
	char prog_pin[PATH_MAX];
	int err;

	err = make_pin_path(prog_pin, sizeof(prog_pin),
			    pin_root, desc->prog_pin_name);
	if (err)
		return err;

	if (unlink(prog_pin)) {
		if (errno == ENOENT)
			return 0;

		err = -errno;
		fprintf(stderr, "Failed to unlink program pin '%s': %s\n",
			prog_pin, strerror(-err));
		return err;
	}

	printf("Unloaded program '%s'\n", desc->prog_name);
	return 0;
}

int
main(int argc, char **argv)
{
	const XfwProgram *desc;
	const char *command;
	const char *pin_root;
	const char *device = NULL;
	int err;

	if (argc < 4) {
		usage(argv[0]);
		return EXIT_FAILURE;
	}

	command = argv[1];
	desc = find_program(argv[2]);
	pin_root = argv[3];

	if (!desc) {
		fprintf(stderr, "Unknown program: '%s'\n", argv[2]);
		usage(argv[0]);
		return EXIT_FAILURE;
	}

	if (pin_root[0] != '/') {
		fprintf(stderr, "Pin root must be an absolute path: '%s'\n",
			pin_root);
		return EXIT_FAILURE;
	}

	if (!strcmp(command, "load")) {
		if (argc != 4) {
			usage(argv[0]);
			return EXIT_FAILURE;
		}

		err = load_program(desc, pin_root);
	} else if (!strcmp(command, "unload")) {
		if (argc != 4) {
			usage(argv[0]);
			return EXIT_FAILURE;
		}

		err = unload_program(desc, pin_root);
	} else if (!strcmp(command, "attach")) {
		if (argc != 5) {
			usage(argv[0]);
			return EXIT_FAILURE;
		}

		device = argv[4];
		err = attach_tc(desc, pin_root, device);
	} else if (!strcmp(command, "detach")) {
		if (argc != 5) {
			usage(argv[0]);
			return EXIT_FAILURE;
		}

		device = argv[4];
		err = detach_tc(desc, pin_root, device);
	} else {
		fprintf(stderr, "Unknown command: '%s'\n", command);
		usage(argv[0]);
		return EXIT_FAILURE;
	}

	return err ? EXIT_FAILURE : EXIT_SUCCESS;
}
