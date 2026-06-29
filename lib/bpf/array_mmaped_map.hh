/**
 *  Tempesta Xfw wrapper for BPF_MAP_TYPE_ARRAY map with BPF_F_MMAPABLE property.
 *
 * This class provides a memory-mapped view of a fixed-size BPF array map.
 * BpfMmapedArrayMap uses mmap to map the entire array into user-space memory,
 * allowing direct read/write access to elements without additional syscalls.
 *
 * Why a separate class is needed instead of using BpfMap:
 *    1. Performance: Accessing each element through bpf_map_lookup_elem/
 * bpf_map_update_elem requires a syscall, which is expensive for large arrays
 * or frequent updates.
 *    2. Direct access: mmap gives a contiguous memory block, allowing bulk
 * operations and iteration just like a normal C++ array.
 *    3. Safety: The class enforces RAII for the map file descriptor and mapped
 * memory, preventing accidental leaks or double-unmaps.
 *    4. Type correctness: The class checks that the key size, value size, and
 * number of entries match the expected template parameters, avoiding runtime errors.
 *    5. Move-only semantics: Copying is forbidden to prevent accidental duplication
 * of file descriptors and memory mappings, while moving is allowed for flexible
 * ownership transfer.
 *
 * Example usage:
 *   BpfMmapedArrayMap<XfwRLimitLeakyBckt, XFW_MAX_RATE_LIMITER_BUCKETS> map("map_name");
 *   (*map)[10] = {};              // Directly write to the mapped array
 *   auto val = (*map)[20];        // Directly read
 * 
 * SPDX-FileCopyrightText: © 2026 Tempesta Technologies, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#pragma once

#include <sys/mman.h>
#include <unistd.h>

#include <array>
#include <string>

#include <bpf/bpf.h>

#include "map.hh"
#include "map_verifier.hh"

template<typename Value, size_t N>
class BpfMmapedArrayMap : public BpfMap
{
public:
	static constexpr size_t Size = N;

	using ValueArray = std::array<Value, N>;
	using Key = uint32_t;

	explicit BpfMmapedArrayMap(const char* map_name)
		: BpfMap(map_name)
	{
		BpfMapVerifier::verify_array_fixed<Key, Value, N>(*this);

		void* addr = mmap(nullptr, sizeof(ValueArray),
				  PROT_READ | PROT_WRITE, MAP_SHARED, fd(), 0);
		if (addr == MAP_FAILED)
			throw Except("Unable to mmap BPF array fd {}", fd());

		data_ = static_cast<ValueArray*>(addr);
	}

	~BpfMmapedArrayMap() noexcept
	{
		if (data_)
			munmap(data_, sizeof(ValueArray));
	}

public:
	// Access operators
	ValueArray& operator*() noexcept { return *data_; }
	const ValueArray& operator*() const noexcept { return *data_; }

	ValueArray* operator->() noexcept { return data_; }
	const ValueArray* operator->() const noexcept { return data_; }

private:
	ValueArray* data_ = nullptr;
};
