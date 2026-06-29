/**
 *	Tempesta Client library BitSet
 *
 * SPDX-FileCopyrightText: © 2026 Tempesta Technologies, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#pragma once

#include <algorithm>
#include <array>
#include <cstdint>
#include <type_traits>
#include <ostream>

/**
 * Static BitSet based on enum values as bit positions.
 *
 * EnumType values are bit indices [0..MaxBit]
 * MaxBit = maximum bit index used in enum (same type as EnumType)
 * 
 * Why not std::bitset:
 *  - std::bitset does not guarantee a stable or contiguous memory layout,
 * which makes it unsuitable for serialization or direct use with raw buffers.
 *  - No standard way to construct from external byte buffers.
 *  - No portable access to underlying storage.
 *
 * This implementation provides:
 *  - Explicit and stable byte-level layout.
 *  - Direct access to raw storage for I/O and serialization.
 */
template<typename EnumType, EnumType MaxBit>
class BitSet
{
private:
	static_assert(std::is_enum_v<EnumType>, "EnumType must be an enum");

	using UnderlyingType = std::underlying_type_t<EnumType>;

    static constexpr size_t BitCount  = static_cast<size_t>(MaxBit) + 1;
    static constexpr size_t ByteCount = (BitCount + 7) / 8;

public:
	// Default constructor (zero-initialized)
	constexpr BitSet() = default;

	// Construct from raw byte buffer
	explicit BitSet(const uint8_t* data, size_t size)
	{
		auto copySize = std::min(size, data_.size());
		std::copy_n(data, copySize, data_.begin());
	}

	// Set bit by enum value
	void set(EnumType flag) noexcept
	{
		auto idx = to_index(flag);
		data_[idx / 8] |= (1u << (idx % 8));
	}

	// Clear bit by enum value
	void unset(EnumType flag) noexcept
	{
		auto idx = to_index(flag);
		data_[idx / 8] &= ~(1u << (idx % 8));
	}

	// Reset all bits
	void clear() noexcept
	{
		data_.fill(0);
	}

	// Check bit by enum value
	bool test(EnumType flag) const noexcept
	{
		auto idx = to_index(flag);
		return data_[idx / 8] & (1u << (idx % 8));
	}

	// Access raw data (for serialization)
	constexpr const auto& raw() const noexcept { return data_; }
	constexpr auto& raw() noexcept { return data_; }

	// Returns number of bytes used by this BitSet
	static constexpr size_t byte_size() noexcept { return ByteCount; }
public:
	// Bitwise OR
	BitSet operator|(const BitSet &other) const noexcept
	{
		BitSet result;
		for (size_t i = 0; i < ByteCount; ++i)
			result.data_[i] = data_[i] | other.data_[i];

		return result;
	}

	// Bitwise OR assignment
	BitSet& operator|=(const BitSet &other) noexcept
	{
		for (size_t i = 0; i < ByteCount; ++i)
			data_[i] |= other.data_[i];
		
		return *this;
	}

	// Equality comparison
	bool operator==(const BitSet &other) const noexcept
	{
		return data_ == other.data_;
	}

	// Inequality comparison
	bool operator!=(const BitSet &other) const noexcept
	{
		return !(*this == other);
	}

private:
	// Convert enum value to index
	static constexpr size_t to_index(EnumType flag) noexcept
	{
		return static_cast<size_t>(static_cast<UnderlyingType>(flag));
	}   
	
	friend std::ostream&
	operator<<(std::ostream &os, const BitSet &bs) noexcept
	{
		for (size_t byte = 0; byte < ByteCount; ++byte) {
			uint8_t b = bs.data_[byte];
			for (int bit = 7; bit >= 0; --bit) {
				size_t bitIndex = byte * 8 + (7 - bit);
				if (bitIndex >= BitCount)
					break; // don't print extra bits
				os << ((b >> bit) & 1u);
			}
		}
		return os;
	}

private:
	std::array<uint8_t, ByteCount> data_{};
};
