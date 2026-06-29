/**
 *	Tempesta BPF Storage Abstractions for values.
 *
 * This header defines how C++ types map to Linux BPF kernel map values.
 * It is a low-level ABI layer and must not contain business logic.
 *
 * STORAGE LAYOUTS
 *
 * 1. Scalar (T)
 *	- Kernel layout: [T]
 *	- Used for: lookup/update/batch API
 *
 * 2. Per-CPU (BpfPerCpuCounter<T>)
 *	- Kernel layout: CPU-major array [cpu0 T, cpu1 T, cpu2 T, ...]
 *	- Used for: single-element operations only
 *	- NOT compatible with batch API
 *
 * 3. Batch (scalar only)
 *	- Kernel layout: [T0, T1, T2, ...]
 *	- Per-CPU types are explicitly forbidden
 *
 * DESIGN RULES
 * 
 *	- Scalar, per-CPU, and batch layouts are intentionally incompatible
 *	- All violations must fail at compile time (no runtime checks)
 *	- No implicit conversions between layouts
 *
 * CONSTRAINTS
 *
 *	- Per-CPU types MUST NOT be used in batch API
 *	- Batch API operates only on scalar contiguous arrays
 *	- Per-CPU batch layout is intentionally unsupported
 *
 * EXTENSION NOTE
 *
 * If per-CPU batch is ever needed, it must be implemented via a dedicated
 * buffer/view type (GetBatchStorage, not GetStorage extension).
 * 
 * SPDX-FileCopyrightText: © 2026 Tempesta Technologies, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#pragma once

#include "per_cpu_counter.hh"
#include <type_traits>
#include <cstdint>

/*
 * Per-CPU type trait.
 *
 * Acts as compile-time switch for GetStorage() overload selection.
 */
template<typename T>
struct IsPerCpu : std::false_type {};

template<typename T>
struct IsPerCpu<BpfPerCpuCounter<T>> : std::true_type {};

/*
 * Kernel ABI type mapping.
 *
 * Maps C++ value types to kernel BPF map value representation.
 */
template<typename T>
struct BpfKernelTraits
{
	using Type = T;
};

/*
 * Per-CPU specialization:
 *
 * BpfPerCpuCounter<T>
 *	- user-space wrapper
 *	- kernel representation is T[]
 *	- layout is CPU-major (per-CPU storage)
 */
template<typename T>
struct BpfKernelTraits<BpfPerCpuCounter<T>>
{
	using Type = T;
};

/*
 * GetStorage: maps C++ object -> kernel ABI pointer
 *
 * IMPORTANT:
 *	- scalar and per-CPU are handled differently
 *	- batch is NOT part of this abstraction
 */

/* ---------------- scalar ---------------- */
template<typename T>
requires (!IsPerCpu<T>::value)
inline typename BpfKernelTraits<T>::Type*
GetStorage(T &v) noexcept
{
	using K = typename BpfKernelTraits<T>::Type;

	static_assert(std::is_standard_layout_v<T>);
	static_assert(sizeof(T) == sizeof(K));

	return reinterpret_cast<K*>(&v);
}

template<typename T>
requires (!IsPerCpu<T>::value)
inline const typename BpfKernelTraits<T>::Type*
GetStorage(const T &v) noexcept
{
	using K = typename BpfKernelTraits<T>::Type;

	static_assert(std::is_standard_layout_v<T>);
	static_assert(sizeof(T) == sizeof(K));

	return reinterpret_cast<const K*>(&v);
}

/* ---------------- per-cpu ---------------- */
template<typename T>
requires IsPerCpu<T>::value
inline typename BpfKernelTraits<T>::Type*
GetStorage(T &v) noexcept
{
	// Returns CPU-major storage:
	// [cpu0 T, cpu1 T, cpu2 T, ...]
	return v.view().data();
}

template<typename T>
requires IsPerCpu<T>::value
inline const typename BpfKernelTraits<T>::Type*
GetStorage(const T &v) noexcept
{
	// Returns CPU-major storage:
	// [cpu0 T, cpu1 T, cpu2 T, ...]
	return v.view().data();
}
