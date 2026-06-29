/**
 *	Tempesta enum array
 *
 * SPDX-FileCopyrightText: © 2026 Tempesta Technologies, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#pragma once
#include <array>
#include <type_traits>

/**
 * Type-safe array indexed by an enum class
 *
 * @tparam T	   Type of the elements
 * @tparam Enum    Enum class, must contain a last element named Enum::MAX
 *		   which determines the size of the array.
 * @tparam N	   Number of elements in the array
 *
 * Features:
 *  - Indexing via enum without static_cast
 *  - Fully compatible with STL and std::ranges
 *  - Supports constexpr and compile-time initialization
 */
template<typename T, typename Enum, std::size_t N>
class EnumArray
{
	static_assert(std::is_enum_v<Enum>, "EnumArray requires enum type");
public:
	using value_type = T;
	using size_type = std::size_t;
	//TODO: replace UnderlyingType with std::to_underlying when it is possible
	using UnderlyingType = std::underlying_type_t<Enum>;

	using iterator = typename std::array<T, N>::iterator;
	using const_iterator = typename std::array<T, N>::const_iterator;

	constexpr EnumArray() = default;
	constexpr EnumArray(const EnumArray&) noexcept = default;
	constexpr EnumArray(EnumArray&&) noexcept = default;
	constexpr EnumArray& operator=(const EnumArray&) noexcept = default;
	constexpr EnumArray& operator=(EnumArray&&) noexcept = default;

	template <class U>
	requires std::is_same_v<std::remove_cvref_t<U>, std::array<T, N>>
	constexpr EnumArray(U&& arr) : data(std::forward<U>(arr))
	{}

public:
	// ===== Access by enum =====
	constexpr T&
	operator[](Enum idx) noexcept
	{
		return data[UnderlyingType(idx)];
	}

	constexpr const T&
	operator[](Enum idx) const noexcept
	{
		return data[UnderlyingType(idx)];
	}

public:
	// ===== STL-like interface =====
	constexpr size_type size() const noexcept { return data.size(); }
	constexpr iterator begin() noexcept { return data.begin(); }
	constexpr iterator end() noexcept { return data.end(); }
	constexpr const_iterator begin() const noexcept { return data.begin(); }
	constexpr const_iterator end() const noexcept { return data.end(); }
	constexpr const_iterator cbegin() const noexcept { return data.cbegin(); }
	constexpr const_iterator cend() const noexcept { return data.cend(); }

	constexpr T& front() { return data.front(); }
	constexpr const T& front() const { return data.front(); }
	constexpr T& back() { return data.back(); }
	constexpr const T& back() const { return data.back(); }
	constexpr T* data_ptr() noexcept { return data.data(); }
	constexpr const T* data_ptr() const noexcept { return data.data(); }

public:
	// ===== Expose underlying array for ranges =====
	constexpr auto& as_array() noexcept { return data; }
	constexpr const auto& as_array() const noexcept { return data; }

private:
	std::array<T, N> data{};
};
