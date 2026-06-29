/**
 *  Tempesta Xfw user-space wrapper for BPF array maps (BPF_MAP_TYPE_ARRAY).
 * 
 * SPDX-FileCopyrightText: © 2026 Tempesta Technologies, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#pragma once

#include "map.hh"
#include "map_verifier.hh"
#include "value_traits.hh"

template <typename Value>
class BpfArrayMap : public BpfMap
{
public:
	using Key = uint32_t;
	using KernelValue = typename BpfKernelTraits<Value>::Type;
	
	explicit BpfArrayMap(const char *map_name)
		: BpfMap(map_name)
	{
		BpfMapVerifier::verify_array<Key, KernelValue>(*this);
	}

	int
	lookup(const Key &key, Value &value) const noexcept
	{
		return bpf_map_lookup_elem(fd(), &key, GetStorage(value));
	}

	int
	update(const Key &key, const Value &value) noexcept
	{
		return bpf_map_update_elem(fd(), &key, GetStorage(value), BPF_ANY);
	}
};

/*
 * BpfSingleElementMap - wrapper for a BPF_MAP_TYPE_ARRAY with a single element.
 *
 * This map is implemented as a standard ARRAY map with max_entries == 1.
 * The only valid key is 0, which represents the single stored value.
 */
template <typename Value>
class BpfSingleElementMap : public BpfMap
{
private:
	using Key = uint32_t;
	using KernelValue = typename BpfKernelTraits<Value>::Type;

public:
	explicit BpfSingleElementMap(const char *map_name)
		: BpfMap(map_name)
	{
		BpfMapVerifier::verify_array_fixed<Key, KernelValue, 1>(*this);
	}

	int
	get(Value &value) const noexcept
	{
		return bpf_map_lookup_elem(fd(), &ZeroKey, GetStorage(value));
	}

	int
	set(const Value &value) noexcept
	{
		return bpf_map_update_elem(fd(), &ZeroKey, GetStorage(value), BPF_ANY);
	}

private:
	static constexpr Key ZeroKey{0};
};
