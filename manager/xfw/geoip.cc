/**
 *	Tempesta xFW GeoIP database importer
 *
 * SPDX-FileCopyrightText: © 2026 Tempesta Technologies, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include <algorithm>
#include <array>
#include <bit>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <netinet/in.h>
#include <optional>
#include <ranges>
#include <string_view>
#include <tuple>
#include <type_traits>
#include <utility>

#include <boost/container_hash/hash.hpp>
#include <boost/unordered/unordered_flat_map.hpp>
#include <maxminddb.h>

#include "../../lib/log.hh"
#include "geoip.hh"

namespace {

template<typename Addr>
constexpr unsigned
addr_bits() noexcept
{
	return static_cast<unsigned>(std::tuple_size_v<Addr> * 8);
}

template<std::size_t N>
using IpAddr = std::array<std::uint8_t, N>;

using Ip4Addr = IpAddr<4>;
using Ip6Addr = IpAddr<16>;

template<typename Addr>
struct IpAddrHash {
	std::size_t
	operator()(const Addr &addr) const noexcept
	{
		return boost::hash_range(addr.begin(), addr.end());
	}
};

template<typename Addr>
using PrefixMap = boost::unordered_flat_map<Addr, IsoCountryId, IpAddrHash<Addr>>;

template<typename Addr>
using PrefixBuckets = std::array<PrefixMap<Addr>, addr_bits<Addr>() + 1>;

using Ip4PrefixBuckets = PrefixBuckets<Ip4Addr>; // /0 through /32
using Ip6PrefixBuckets = PrefixBuckets<Ip6Addr>; // /0 through /128

class MmdbHndl {
public:
	explicit MmdbHndl(const std::string &path)
	{
		const int r = MMDB_open(path.c_str(), MMDB_MODE_MMAP, &mmdb_);
		if (r != MMDB_SUCCESS)
			throw Except("Failed to open GeoIP database at {}: {}",
				     path, MMDB_strerror(r));
	}

	~MmdbHndl()
	{
		MMDB_close(&mmdb_);
	}

	MmdbHndl(const MmdbHndl &) = delete;
	MmdbHndl &operator=(const MmdbHndl &) = delete;

	[[nodiscard]] MMDB_s &
	get() noexcept
	{
		return mmdb_;
	}

private:
	MMDB_s	mmdb_{};
};

template<typename Addr>
void
set_prefix_bit(Addr &addr, unsigned bit, bool value) noexcept
{
	const auto octet = bit >> 3;
	const auto mask = static_cast<std::uint8_t>(0x80U >> (bit & 7));

	if (value)
		addr[octet] |= mask;
	else
		addr[octet] &= static_cast<std::uint8_t>(~mask);
}

/**
 * Convert @addr inside a network into the network’s canonical base address by
 * clearing all bits after @prefixlen (zeroize the host portition).
 */
template<typename Addr>
void
canonicalize_prefix(Addr &addr, unsigned prefixlen)
{
	constexpr unsigned bits = addr_bits<Addr>();
	if (prefixlen > bits)
		throw Except("Invalid prefix length {} for a {}-bit address",
			     prefixlen, bits);
	if (prefixlen == bits)
		return;

	std::size_t octet = prefixlen >> 3;
	const unsigned rem = prefixlen & 7;
	if (rem != 0) {
		const auto mask = static_cast<std::uint8_t>(0xffU << (8 - rem));
		addr[octet] &= mask;
		++octet;
	}
	std::ranges::fill(addr.begin() + octet, addr.end(), std::uint8_t{0});
}

/**
 * Insert a prefix into the bucket for its prefix length and merge it with
 * adjacent sibling prefixes that belong to the same country.
 *
 * E.g. for 192.0.2.129/25 → country US and if the @buckets already contain
 * 192.0.2.0/25 → country US: the two /25 prefixes differ only in the last
 * network bit 25. The function works as:
 * 1. canonicalize 192.0.2.129 → 192.0.2.128
 * 2. flips bit 24 to construct its sibling 192.0.2.0/25
 * 3. finds that sibling in buckets[25]
 * 4. confirms that both prefixes belong to US
 * 5. removes the sibling
 * 6. clears bit 24 and decrements the prefix length → 192.0.2.0/24
 * 7. tries to merge the resulting /24 with its /24 sibling
 * 8. if no matching sibling exists, inserts buckets[24][192.0.2.0] = US
 *
 * Merging may cascade, e.g. four /26 prefixes can become two /25 prefixes and
 * then one /24.
 */
template<typename Addr>
void
merge_prefix(PrefixBuckets<Addr> &buckets, const IsoCountryId &country,
	     Addr addr, unsigned prefixlen)
{
	canonicalize_prefix(addr, prefixlen);

	while (prefixlen > 0) {
		const unsigned bit = prefixlen - 1;
		Addr sibling = addr;
		const auto octet = bit >> 3;
		const auto mask = static_cast<std::uint8_t>(0x80U >> (bit & 7));
		// Flip the last network bit to obtain the sibling prefix.
		sibling[octet] ^= mask;

		auto &bucket = buckets[prefixlen];
		const auto it = bucket.find(sibling);
		if (it == bucket.end() || it->second != country)
			break;

		bucket.erase(it);

		// Convert either sibling into their common parent prefix.
		set_prefix_bit(addr, bit, false);
		--prefixlen;
	}

	const auto [it, inserted] = buckets[prefixlen].try_emplace(addr, country);
	if (!inserted && it->second != country)
		throw Except("Conflicting countries for the same GeoIP prefix");
}

std::optional<IsoCountryId>
read_iso_code(MMDB_entry_s entry, const char *const *path,
	      std::string_view field_name)
{
	MMDB_entry_data_s data{};
	const int r = MMDB_aget_value(&entry, &data, path);
	if (r == MMDB_LOOKUP_PATH_DOES_NOT_MATCH_DATA_ERROR)
		return std::nullopt;
	if (r != MMDB_SUCCESS)
		throw Except("Failed to read {} from MMDB entry {}: {}",
			     field_name, entry.offset, MMDB_strerror(r));
	if (!data.has_data)
		return std::nullopt;
	if (data.type != MMDB_DATA_TYPE_UTF8_STRING)
		throw Except("{} in MMDB entry {} is not a UTF-8 string",
			     field_name, entry.offset);
	if (data.data_size != 2)
		throw Except("{} in MMDB entry {} has invalid length {}",
			     field_name, entry.offset, data.data_size);

	return IsoCountryId(std::string_view(data.utf8_string, data.data_size));
}

/**
 * Return the geolocation country for an MMDB entry.
 *
 * `registered_country.iso_code` is used only as an explicit fallback when the
 * geolocation country is absent.
 *
 * Continent codes are not accepted because their two-letter namespace overlaps
 * with ISO country codes, e.g. "AS" for Asio and American Samoa.
 */
std::optional<IsoCountryId>
read_country(MMDB_entry_s entry)
{
	static constexpr const char *country_path[] = {
		"country", "iso_code", nullptr
	};
	static constexpr const char *registered_country_path[] = {
		"registered_country", "iso_code", nullptr
	};

	if (auto country = read_iso_code(entry, country_path,
					 "country.iso_code"))
		return country;

	return read_iso_code(entry, registered_country_path,
			     "registered_country.iso_code");
}

MMDB_search_node_s
read_node(const MMDB_s &mmdb, std::uint32_t node_number)
{
	MMDB_search_node_s node{};
	const int r = MMDB_read_node(&mmdb, node_number, &node);
	if (r != MMDB_SUCCESS)
		throw Except("Failed to read MMDB node {}: {}", node_number,
			     MMDB_strerror(r));
	return node;
}

template<typename Addr, typename AddData>
void
walk_search_tree(const MMDB_s &mmdb, std::uint32_t node_number,
		 Addr prefix, unsigned depth, AddData &add_data,
		 std::optional<std::uint32_t> skipped_search_node = std::nullopt)
{
	constexpr unsigned bits = addr_bits<Addr>();
	if (depth >= bits)
		throw Except("MMDB search tree exceeds the {}-bit address width",
			     bits);

	const auto node = read_node(mmdb, node_number);

	auto visit_rec = [&](std::uint8_t rec_type, std::uint64_t rec,
			     MMDB_entry_s entry, bool right)
	{
		Addr child_prefix = prefix;
		set_prefix_bit(child_prefix, depth, right);

		switch (rec_type) {
		case MMDB_RECORD_TYPE_EMPTY:
			return;

		case MMDB_RECORD_TYPE_DATA:
			add_data(entry, child_prefix, depth + 1);
			return;

		case MMDB_RECORD_TYPE_SEARCH_NODE:
			if (rec > std::numeric_limits<std::uint32_t>::max())
				throw Except("MMDB search too large node number {}",
					     rec);
			if (skipped_search_node && rec == *skipped_search_node)
				return;
			walk_search_tree(mmdb, static_cast<std::uint32_t>(rec),
					 child_prefix, depth + 1, add_data,
					 skipped_search_node);
			return;

		default:
			throw Except("MMDB node {} has an invalid record type {}",
				     node_number, rec_type);
		}
	};

	visit_rec(node.left_record_type, node.left_record,
		  node.left_record_entry, false);
	visit_rec(node.right_record_type, node.right_record,
		  node.right_record_entry, true);
}

template<typename Addr>
void
add_country_prefix(PrefixBuckets<Addr> &buckets, MMDB_entry_s entry,
		   const Addr &addr, unsigned prefixlen)
{
	const auto country = read_country(entry);
	if (country)
		merge_prefix(buckets, *country, addr, prefixlen);
}

void
import_ipv4_tree(MMDB_s &mmdb, Ip4PrefixBuckets &prefixes)
{
	auto add_data = [&prefixes](MMDB_entry_s entry, const Ip4Addr &addr,
				    unsigned prefixlen)
	{
		add_country_prefix(prefixes, entry, addr, prefixlen);
	};

	if (mmdb.metadata.ip_version == 4) {
		walk_search_tree(mmdb, 0, Ip4Addr{}, 0, add_data);
		return;
	}

	/*
	 * MaxmindDB represents IPv4 addresses in an IPv6 128-bit trie, i.e.
	 * 96 leading zeros, so we check the prefix depth as 96.
	 */
	const auto &start = mmdb.ipv4_start_node;
	if (start.node_value < mmdb.metadata.node_count) {
		if (start.netmask == 96) {
			walk_search_tree(mmdb, start.node_value, Ip4Addr{},
					 0, add_data);
			return;
		}
		throw Except("Unexpected IPv4 subtree depth {} in an IPv6 MMDB",
			     start.netmask);
	}

	if (start.node_value == mmdb.metadata.node_count)
		return; // The database has no IPv4 data.

	/*
	 * A data record at the IPv4 subtree root covers the whole IPv4 address
	 * space. Use the public lookup API to obtain its MMDB entry.
	 */
	sockaddr_in addr{};
	addr.sin_family = AF_INET;
	int mmdb_error = MMDB_SUCCESS;
	const auto result = MMDB_lookup_sockaddr(&mmdb,
			reinterpret_cast<const sockaddr *>(&addr), &mmdb_error);
	if (mmdb_error != MMDB_SUCCESS)
		throw Except("Failed to look up the IPv4 root entry: {}",
			     MMDB_strerror(mmdb_error));
	if (result.found_entry)
		add_country_prefix(prefixes, result.entry, Ip4Addr{}, 0);
}

static bool
xfw_is_ipv4_embedded_ipv6(const Ip6Addr &addr) noexcept
{
	if (!std::ranges::all_of(addr.begin(), addr.begin() + 10,
				 [](std::uint8_t b) { return b == 0; }))
		return false;

	return (addr[10] == 0 && addr[11] == 0)
		|| (addr[10] == 0xff && addr[11] == 0xff);
}

void
import_ipv6_tree(MMDB_s &mmdb, Ip6PrefixBuckets &prefixes)
{
	if (mmdb.metadata.ip_version != 6)
		return;

	std::optional<std::uint32_t> ipv4_subtree;
	if (mmdb.ipv4_start_node.netmask == 96 &&
	    mmdb.ipv4_start_node.node_value < mmdb.metadata.node_count)
		ipv4_subtree = mmdb.ipv4_start_node.node_value;

	auto add_data = [&prefixes](MMDB_entry_s entry, const Ip6Addr &addr,
				    unsigned prefixlen)
	{
		if (xfw_is_ipv4_embedded_ipv6(addr))
			throw Except("Unexpected IPv4-embedded prefix in IPv6 "
				     "search tree");

		add_country_prefix(prefixes, entry, addr, prefixlen);
	};

	/*
	 * Skip every alias of the IPv4 subtree. IPv4 ranges are imported once,
	 * separately, through libmaxminddb's computed IPv4 start node.
	 */
	walk_search_tree(mmdb, 0, Ip6Addr{}, 0, add_data, ipv4_subtree);
}

std::array<std::uint8_t, 4>
net4_bytes(const Net4Geo &network) noexcept
{
	return std::bit_cast<std::array<std::uint8_t, 4>>(network.addr_);
}

std::array<std::uint8_t, 16>
net6_bytes(const Net6Geo &network) noexcept
{
	return std::bit_cast<std::array<std::uint8_t, 16>>(network.addr_);
}

void
sort_country_prefixes(Country2IpMap::Map &map)
{
	for (auto &[country, networks] : map) {
		(void)country;
		std::ranges::sort(networks.ip4, [](const Net4Geo &a,
						   const Net4Geo &b)
		{
			const auto a_bytes = net4_bytes(a);
			const auto b_bytes = net4_bytes(b);
			if (a_bytes != b_bytes)
				return a_bytes < b_bytes;
			return a.prefixlen_ < b.prefixlen_;
		});
		std::ranges::sort(networks.ip6, [](const Net6Geo &a,
						   const Net6Geo &b)
		{
			const auto a_bytes = net6_bytes(a);
			const auto b_bytes = net6_bytes(b);
			if (a_bytes != b_bytes)
				return a_bytes < b_bytes;
			return a.prefixlen_ < b.prefixlen_;
		});
	}
}

Country2IpMap::Map
build_country_map(const Ip4PrefixBuckets &ip4_prefixes,
		  const Ip6PrefixBuckets &ip6_prefixes)
{
	Country2IpMap::Map map;

	// We store addresses in host byte order here, but later convert
	// to network byte order.
	for (std::size_t plen = 0; plen < ip4_prefixes.size(); ++plen)
		for (const auto &[addr, country] : ip4_prefixes[plen])
			map[country].ip4.push_back({
				static_cast<std::uint16_t>(plen),
				std::bit_cast<std::uint32_t>(addr)
			});

	for (std::size_t plen = 0; plen < ip6_prefixes.size(); ++plen)
		for (const auto &[addr, country] : ip6_prefixes[plen])
			map[country].ip6.push_back({
				static_cast<std::uint16_t>(plen),
				std::bit_cast<std::array<std::uint32_t, 4>>(addr)
			});

	sort_country_prefixes(map);
	return map;
}

Country2IpMap::Map
import_maxmind_geodata(MMDB_s &mmdb)
{
	Ip4PrefixBuckets ip4_prefixes;
	Ip6PrefixBuckets ip6_prefixes;

	import_ipv4_tree(mmdb, ip4_prefixes);
	import_ipv6_tree(mmdb, ip6_prefixes);

	return build_country_map(ip4_prefixes, ip6_prefixes);
}

} // anonymous namespace

void
Country2IpMap::reload(const std::string &fname)
{
	MmdbHndl mmdb(fname);
	auto start = std::chrono::steady_clock::now();
	Map new_map = import_maxmind_geodata(mmdb.get());
	auto end = std::chrono::steady_clock::now();

	std::size_t subnet_count = 0;
	for (const auto &[_, networks] : new_map)
		subnet_count += networks.ip4.size() + networks.ip6.size();

	map_.swap(new_map);
	std::string new_path = fname;
	db_path_.swap(new_path);

	auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
	TE_INF("Loaded {} countries and {} subnets from {} in {}ms",
	       map_.size(), subnet_count, db_path_, ms.count());
}
