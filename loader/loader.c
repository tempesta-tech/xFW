// SPDX-License-Identifier: GPL-2.0-or-later

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <bpf/libbpf.h>

#define DEFAULT_PIN_ROOT	"/sys/fs/bpf/tc/globals"
#define DEFAULT_PROG_PIN	"/sys/fs/bpf/tc/globals/xdp"
#define DEFAULT_PROG_NAME	"xfw_xdp"

static void
usage(const char *prog)
{
	fprintf(stderr,
		"Usage:\n"
		"  %s load <object> [program-name] [pin-root] [program-pin]\n"
		"\n"
		"Defaults:\n"
		"  program-name: %s\n"
		"  pin-root:    %s\n"
		"  program-pin: %s\n"
		"\n"
		"Example:\n"
		"  %s load /opt/tempesta/lib/bpf/xdp.o\n",
		prog,
		DEFAULT_PROG_NAME,
		DEFAULT_PIN_ROOT,
		DEFAULT_PROG_PIN,
		prog);
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
check_path_absent(const char *path)
{
	int err;

	if (access(path, F_OK) == 0) {
		fprintf(stderr, "Program is already pinned at '%s'\n", path);
		return -EEXIST;
	}

	if (errno == ENOENT)
		return 0;

	err = -errno;

	fprintf(stderr, "Failed to check '%s': %s\n",
		path, strerror(-err));

	return err;
}

static int
find_xdp_program(struct bpf_object *obj, const char *program_name,
		 struct bpf_program **result)
{
	struct bpf_program *prog;
	enum bpf_prog_type type;

	prog = bpf_object__find_program_by_name(obj, program_name);
	if (!prog) {
		fprintf(stderr, "Program '%s' was not found in BPF object\n",
			program_name);
		return -ENOENT;
	}

	type = bpf_program__type(prog);
	if (type != BPF_PROG_TYPE_XDP) {
		fprintf(stderr, 
			"Program '%s' has type %d, expected XDP type %d\n",
			program_name, type, BPF_PROG_TYPE_XDP);
		return -EINVAL;
	}

	*result = prog;
	return 0;
}

static int
load_xdp(const char *object_path, const char *program_name,
	 const char *pin_root, const char *program_pin)
{
	LIBBPF_OPTS(bpf_object_open_opts, opts,
		.pin_root_path = pin_root
	);

	struct bpf_object *obj = NULL;
	struct bpf_program *prog;
	int err;

	err = check_pin_root(pin_root);
	if (err)
		return err;

	err = check_path_absent(program_pin);
	if (err)
		return err;

	/*
	 * All maps declared with `__uint(pinning, LIBBPF_PIN_BY_NAME)`
	 * will use opts.pin_root_path as their root directory.
	 */
	obj = bpf_object__open_file(object_path, &opts);
	if (!obj) {
		err = -errno;
		fprintf(stderr, "Failed to open BPF object '%s': %s\n",
			object_path, strerror(-err));
		return err;
	}

	err = find_xdp_program(obj, program_name, &prog);
	if (err)
		goto out;

	/*
	 * This code loads both maps and programs.
	 * For maps with LIBBPF_PIN_BY_NAME, libbpf uses pin_root_path.
	 */
	err = bpf_object__load(obj);
	if (err) {
		fprintf(stderr, "Failed to load BPF object '%s': %s\n",
			object_path, strerror(-err));
		goto out;
	}

	err = bpf_program__pin(prog, program_pin);
	if (err) {
		fprintf(stderr, "Failed to pin program '%s' at '%s': %s\n",
			program_name, program_pin, strerror(-err));
		goto out;
	}

	printf("Loaded XDP program '%s'\n", program_name);
	printf("Program pin: %s\n", program_pin);
	printf("Map pin root: %s\n", pin_root);

out:
	bpf_object__close(obj);
	return err;
}

int
main(int argc, char **argv)
{
	const char *command;
	const char *object_path;
	const char *program_name = DEFAULT_PROG_NAME;
	const char *pin_root = DEFAULT_PIN_ROOT;
	const char *program_pin = DEFAULT_PROG_PIN;
	int arg = 1;
	int err;

	if (argc < 3 || argc > 6) {
		fprintf(stderr, "Invalid count of arguments: %d\n", argc);
		usage(argv[0]);
		return EXIT_FAILURE;
	}

	command = argv[arg++];
	object_path = argv[arg++];

	if (strcmp(command, "load") != 0) {
		fprintf(stderr, "Unknown command: %s\n", command);
		usage(argv[0]);
		return EXIT_FAILURE;
	}

	if (arg < argc)
		program_name = argv[arg++];

	if (arg < argc)
		pin_root = argv[arg++];

	if (arg < argc)
		program_pin = argv[arg++];

	err = load_xdp(object_path, program_name, pin_root, program_pin);

	return !err ? EXIT_SUCCESS : EXIT_FAILURE;
}
