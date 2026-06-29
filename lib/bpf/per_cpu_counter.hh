/**
 *   Tempesta Xfw lightweight wrapper for per-CPU values coming from BPF maps.
 *
 * Assumptions:
 *  - One element per CPU
 *  - Kernel rounds value_size up to 8 bytes
 *  - Userspace layout must match kernel layout exactly
 *
 * This class does not modify alignment, only enforces minimal constraints
 * required for safe iteration and aggregation.
 * 
 * SPDX-FileCopyrightText: © 2026 Tempesta Technologies, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#pragma once

#include <vector>
#include <cstddef>
#include <type_traits>
#include <utility>

#include "utils.hh"

template<typename ValueType>
class BpfPerCpuCounter
{
public:
	BpfPerCpuCounter(): data_(bpf_get_cpu_count())
	{
	}

public:
	std::span<ValueType> view() noexcept
	{
		return std::span<ValueType>(data_);
	}

	std::span<const ValueType> view() const noexcept
	{
		return std::span<const ValueType>(data_);
	}

public:
	/* Number of CPU slots (immutable) */
	size_t size() const noexcept { return data_.size(); }

	/*
	 * Direct access to per-CPU element.
	 * Precondition: i < size()
	 */
	const ValueType& cpu(size_t i) const noexcept
	{
		assert(i < data_.size());
		return data_[i];
	}

	/*
	 * Aggregate all per-CPU values.
	 *
	 * This version does not impose any noexcept guarantees
	 * and is intended for general-purpose use.
	 *
	 * It may throw depending on ValueType operations.
	 */
	ValueType sum() const
	{
		ValueType total{};

		for (const auto &v : data_)
			total += v;

		return total;
	}

	/*
	 * Sum selected field across CPUs.
	 */
	template<typename ReturnType>
	ReturnType sum(ReturnType ValueType::* member) const
	{
		ReturnType total{};

		for (const auto &v : data_)
			total += v.*member;

		return total;
	}

private:
	std::vector<ValueType>	data_;
};
