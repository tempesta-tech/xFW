/**
 *	Tempesta xFW GeoIP interfaces
 *
 * SPDX-FileCopyrightText: © 2026 Tempesta Technologies, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#pragma once
#include <ctype.h>

#include <array>
#include <compare>
#include <cstddef>
#include <cstdint>
#include <fmt/ostream.h>
#include <functional>
#include <ostream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#include <boost/unordered/unordered_flat_map.hpp>

struct IsoCountryId {
	std::array<char, 2> id{};

	explicit
	IsoCountryId(std::string_view code)
	{
		if (code.size() != id.size())
			throw Except("ISO country code must contain two characters");

		if (!isalpha(code[0]) || !isalpha(code[1]))
			throw Except("ISO country code must contain ASCII letters");

		id[0] = tolower(code[0]);
		id[1] = tolower(code[1]);
	}

	auto operator<=>(const IsoCountryId &) const noexcept = default;

	friend std::ostream &
	operator<<(std::ostream &out, const IsoCountryId &country)
	{
		return out << country.id[0] << country.id[1];
	}
};

struct IsoCountryIdHash {
	std::size_t
	operator()(const IsoCountryId &country) const noexcept
	{
		const auto high = static_cast<std::uint8_t>(country.id[0]);
		const auto low = static_cast<std::uint8_t>(country.id[1]);

		return (static_cast<std::size_t>(high) << 8) | low;
	}
};

template<>
struct std::hash<IsoCountryId> : IsoCountryIdHash {};

#if FMT_VERSION >= 90000
template<>
struct fmt::formatter<IsoCountryId> : fmt::ostream_formatter {};
#endif

struct Net4Geo {
	std::uint16_t			prefixlen_ = 0;
	std::uint32_t			addr_ = 0;
};

struct Net6Geo {
	std::uint16_t			prefixlen_ = 0;
	std::array<std::uint32_t, 4>	addr_{};
};

struct GeoCountry {
	std::vector<Net4Geo> ip4;
	std::vector<Net6Geo> ip6;
};

class Country2IpMap {
public:
	using Map = boost::unordered_flat_map<IsoCountryId, GeoCountry,
					      IsoCountryIdHash>;

	Country2IpMap() = default;
	Country2IpMap(Country2IpMap &&) noexcept = default;
	Country2IpMap &operator=(Country2IpMap &&) noexcept = default;

	// Copying is disabled because the map may be large. Move the object or
	// reload it from a database instead.
	Country2IpMap(const Country2IpMap &) = delete;
	Country2IpMap &operator=(const Country2IpMap &) = delete;

	void reload(const std::string &fname);

	[[nodiscard]] bool
	empty() const noexcept
	{
		return map_.empty();
	}

	[[nodiscard]] const GeoCountry *
	lookup(const IsoCountryId &country) const noexcept
	{
		const auto it = map_.find(country);
		return it == map_.end() ? nullptr : &it->second;
	}

private:
	std::string	db_path_;
	Map		map_;
};
