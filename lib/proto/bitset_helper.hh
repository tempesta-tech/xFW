/**
 *	FlatBuffers-based serialization helpers for BitSet
 *
 * SPDX-FileCopyrightText: © 2026 Tempesta Technologies, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#pragma once

#include <flatbuffers/flatbuffers.h>
#include <cstring>
#include <algorithm>

#include "../bitset.hh"

/**
 * Serialize BitSet into FlatBuffers vector<uint8_t>
 */
template<typename Enum, Enum EnumMax>
flatbuffers::Offset<flatbuffers::Vector<uint8_t>>
bitset_serialize(flatbuffers::FlatBufferBuilder &fbb, const BitSet<Enum, EnumMax> &bs)
{
	return fbb.CreateVector(bs.raw().data(), bs.byte_size());
}

/**
 * Deserialize FlatBuffers vector<uint8_t> into BitSet
 *
 * Contract:
 * - BitSet stores exactly MaxBit+1 bits
 * - Returns true if fully deserialized, false if size mismatch
 */
template<typename Enum, Enum EnumMax>
bool
bitset_deserialize(const flatbuffers::Vector<uint8_t> &vec, BitSet<Enum, EnumMax> &bs)
{
	constexpr size_t ExpectedSize = BitSet<Enum, EnumMax>::byte_size();

	if (vec.size() != ExpectedSize)
		return false; // size mismatch

	std::memcpy(bs.raw().data(), vec.data(), ExpectedSize);
	return true;
}