/**
 * Tempesta BpfMapVerifier - centralized ABI validation for BPF maps.
 *
 * This helper provides a single place for validating BPF map properties
 * (key size, value size, entry count, etc.) against user-space types.
 *
 * The verifier enforces ABI consistency between kernel and user-space:
 *   - key_size must match sizeof(Key)
 *   - value_size must match sizeof(Value)
 *   - map-specific invariants must hold (e.g. max_entries)
 *
 * Usage:
 *   BpfMapVerifier::verify_array<Key, Value>(map);
 *
 * Important:
 *   - This verifies ABI/layout correctness only.
 *   - It does NOT validate semantic correctness of stored data.
 *
 * SPDX-FileCopyrightText: © 2026 Tempesta Technologies, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#pragma once

#include <bpf/bpf.h>

#include "map.hh"

struct BpfMapVerifier
{
	static bpf_map_info get_info(const BpfMap &map)
	{
		struct bpf_map_info info {};
		uint32_t len = sizeof(info);

		if (bpf_obj_get_info_by_fd(map.fd(), &info, &len) != 0)
			throw Except("Failed to get map info: {}", map.name());

		return info;
	}

	template<typename Key, typename Value>
	static void verify_kv(const BpfMap &map, const bpf_map_info &info)
	{
		if (info.key_size != sizeof(Key))
			throw Except("Key size mismatch: {} (expected {} got {})",
				     map.name(), sizeof(Key), info.key_size);

		if (info.value_size != sizeof(Value))
			throw Except("Value size mismatch: {} (expected {} got {})",
				     map.name(), sizeof(Value), info.value_size);
	}

	// --- specializations ---
	template<typename Key, typename Value>
	static void verify_array(const BpfMap &map)
	{
		auto info = get_info(map);
		verify_kv<Key, Value>(map, info);

		if (info.max_entries == 0)
			throw Except("Array map has invalid max_entries: {}", map.name());
	}

	template<typename Key, typename Value, size_t N>
	static void verify_array_fixed(const BpfMap &map)
	{
		auto info = get_info(map);
		verify_kv<Key, Value>(map, info);

		if (info.max_entries != N)
			throw Except("Array size mismatch: {} (expected {} got {})",
				     map.name(), N, info.max_entries);
	}

	template<typename Key, typename Value>
	static void verify_hash(const BpfMap &map)
	{
		auto info = get_info(map);
		verify_kv<Key, Value>(map, info);
	}
};