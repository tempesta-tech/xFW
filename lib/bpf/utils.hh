/*
 *		Small BPF-related utilities for userspace code.
 *
 * This header provides helpers that align userspace logic with
 * kernel BPF semantics (e.g. CPU indexing for per-CPU maps).
 * 
 * SPDX-FileCopyrightText: © 2026 Tempesta Technologies, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#pragma once

#include <bpf/libbpf.h>

static inline size_t bpf_get_cpu_count()
{
	static const size_t n = []{
		int v = libbpf_num_possible_cpus();
		if (v <= 0)
			throw Except("libbpf_num_possible_cpus() failed: {}", v);
		return static_cast<size_t>(v);
	}();

	return n;
}