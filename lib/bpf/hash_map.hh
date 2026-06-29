/**
 * Tempesta BpfHashMap - wrapper for BPF_MAP_TYPE_HASH and BPF_MAP_TYPE_LRU_HASH.
 *
 * SPDX-FileCopyrightText: © 2026 Tempesta Technologies, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#pragma once

#include "map.hh"
#include "map_verifier.hh"
#include "value_traits.hh"

/**
 * Example:
 *   BpfHashMap<int, uint64_t> map("xfw_map_name");
 *   const int key = 42;
 *   map.update(key, 100);
 *   uint64_t value = 0;
 *   if (map.lookup(key, value) == 0)
 *       printf("value = %lu\n", value);
 */

template<typename Key, typename Value>
class BpfHashMap : public BpfMap
{
public:
	using KernelValue = typename BpfKernelTraits<Value>::Type;

public:
	explicit BpfHashMap(const char *map_name)
		: BpfMap(map_name)
	{
		BpfMapVerifier::verify_hash<Key, KernelValue>(*this);
	}

	explicit BpfHashMap(const char *map_name, FdGuard &&fd)
		: BpfMap(map_name, std::move(fd))
	{}

public:
	/*
	 * Lookup element by key. Returns a negative value on error,
	 * 0 on success or -ENOENT if key has not found.
	 */
	int
	lookup(const Key &key, Value &value, uint64_t flags = BPF_ANY) const noexcept
	{
		return bpf_map_lookup_elem_flags(fd(), &key, GetStorage(value), flags);
	}

	/*
	 * Insert or update element. Returns a negative value on error, 0 on success.
	 */
	int
	update(const Key &key, const Value &value, uint64_t flags = BPF_ANY) noexcept
	{
		return bpf_map_update_elem(fd(), &key, GetStorage(value), flags);
	}

	/*
	 * Delete element by key. Returns a negative value on error, 0 on success.
	 * ENOENT is treated as success to make operation idempotent,
	 * which simplifies diff-based updates.
	 */

	int
	erase(const Key &key, uint64_t flags = BPF_ANY) noexcept
	{
		int ret = bpf_map_delete_elem_flags(fd(), &key, flags);
		if (ret == -ENOENT)
			return 0;
		return ret;
	}

	int clear(size_t batch_size) noexcept
	{
		return drain_by_batch([](auto, auto) noexcept {}, batch_size);
	}

public:
	template<typename Fn>
	requires std::invocable<Fn, std::span<const Key>, std::span<const Value>>
	int drain_by_batch(Fn&& fn, size_t batch_size, uint64_t flags = 0) noexcept
	requires (!IsPerCpu<Value>::value)
	{
		std::vector<Key>   keys;
		std::vector<Value> values;

		try {
			keys.resize(batch_size);
			values.resize(batch_size);
		}
		catch (const std::bad_alloc&) {
			return -ENOMEM;
		}

		bool remaining = true;
		void *in_batch = nullptr;
		void *out_batch = nullptr;
		while (remaining) {
			uint32_t cnt = static_cast<uint32_t>(batch_size);

			int err = bpf_map_lookup_and_delete_batch(fd(),
				&in_batch, &out_batch, keys.data(),
				values.data(), &cnt, nullptr);

			if (err) {
				if (err == -ENOENT)
					remaining = false;
				else
					return err;
			}

			fn(std::span<const Key>(keys.data(), cnt),
			   std::span<const Value>(values.data(), cnt));

			in_batch = out_batch;
		}
		return 0;
	}

	int
	update_batch(std::span<const Key> keys, std::span<const Value> values,
		uint32_t &cnt) noexcept
	requires (!IsPerCpu<Value>::value)
	{
		return bpf_map_update_batch(fd(), keys.data(), values.data(), &cnt, nullptr);
	}

	int
	delete_batch(std::span<const Key> keys, uint32_t &cnt) noexcept
	requires (!IsPerCpu<Value>::value)
	{      
		return bpf_map_delete_batch(fd(), keys.data(), &cnt, nullptr);
	}
};
