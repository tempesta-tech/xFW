/**
 *	Tempesta Xfw configuration
 *
 * SPDX-FileCopyrightText: © 2026 Tempesta Technologies, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#pragma once
#include <stdint.h>

#include <array>
#include <cstring>
#include <functional>
#include <optional>
#include <linux/types.h>
#include <map>
#include <set>
#include <span>
#include <string_view>
#include <string>
#include <queue>

#include "../../bpf_uapi/default_index.h"
#include "../../bpf_uapi/supported_protocols.h"
#include "../../bpf_uapi/tcp_control_bits.h"

#include "../../lib/bitset.hh"
#include "../../lib/enum_array.hh"

/*
 * The in-memory structure differs from the one used in the BPF program for
 * several reasons:
 *  1) We need to store geo-names to enable reloads when necessary, whereas the
 * BPF program does not require them.
 *  2) We also need to keep aliases to correctly merge the old configuration with
 * updates; the BPF program does not need these either.
 *  3) The BPF structure must be minimized because it operates within the kernel.
 *
 * It also differs from the proto structure for the same reasons, and for several
 * others:
 *  4) we don't need add/delete/replace information.
 *  5) It's better to keep the information in a format as close as possible to
 * the BPF structure, to allow applying it as efficiently as possible.
 *
 * Important: We are reapplying the entire configuration to eliminate possible
 * errors that may have occurred during the last BPF structure update.
 */
class XfwConfig
{
public:
	using RatelimitIndex = uint8_t;
	using AliasToIndexMap = std::map<std::string, RatelimitIndex, std::less<>>;
	struct SynCookieFilter
	{
		uint64_t	passive_timer_sec_ = 1;
		uint64_t	flood_timer_sec_ = 1;
	};

	struct TcpSynDropFilter {
		uint64_t	hash_salt_ = 0;
		uint64_t	time_min_ms_ = 0;
		uint64_t	max_delay_ms_ = 0;
		uint64_t	block_timeout_ms_ = 0;
		uint32_t	retry_count_ = 0;
	};

	struct TcpFlagFilter
	{
		RatelimitIndex ratelimit_index_ = -1;
	};

	struct TcpAnomalyFilter
	{
		// All features are off. Ignore other values.
		bool	enabled_ = false;

		bool	syn_without_opt_enabled_ = false;
		bool	syn_with_payload_enabled_ = false;
		
		// By default: only rfc-prohibited flags are set,
		// but user can extend them.
		BitSet<TcpControlBits, XFW_BIT_CONTROL_MAX>	bad_flags_;
		std::optional<__be32>				syn_with_seqno_;
	};

	struct EvaluationMode
	{
		bool	enabled_ = false;
	};
	
	struct IpProtoFilter
	{
		BitSet<XfwSupportedProtocols, XFW_SUPPORTED_PROTOCOL_MAX> protocols_;
	};

	struct TcpAuthFilter
	{
		bool	enabled_ = false;
	};

	struct DnsFilter
	{
		bool	enabled_ = false;
	};

	using NetPort = __be16;

	struct Net4Key
	{
		//we never use prefix and port in the same time
		union {
			uint16_t		prefixlen_ = 0;	//for src
			NetPort		port_;		//for dst
		};
		__be32		addr_ = 0;

		bool operator<(const Net4Key &o) const
		{
			if (addr_ != o.addr_)
				return addr_ < o.addr_;
			return prefixlen_ < o.prefixlen_;
		}
	};

	struct Net6Key
	{
		//we never use prefix and port in the same time
		union {
			uint16_t		prefixlen_ = 0;	//for src
			NetPort		port_;		//for dst
		};
		__be32		addr_[4] {0, 0, 0, 0};

		bool operator<(const Net6Key &o) const
		{
			if (prefixlen_ != o.prefixlen_)
				return prefixlen_ < o.prefixlen_;
			return std::memcmp(addr_, o.addr_, sizeof(addr_)) < 0;
		}
	};

	struct NetGeo
	{
		union {
			uint16_t		code_ = 0;
			char			code_str_[2];
		};

		std::vector<Net4Key>		net4s_;
		std::vector<Net6Key>		net6s_;

		NetGeo() = default;
		NetGeo(uint16_t code);

		NetGeo(const NetGeo &) = default;
		NetGeo& operator=(const NetGeo &) = default;

		NetGeo(NetGeo &&) = default;
		NetGeo& operator=(NetGeo &&) = default;

		std::string_view code() const noexcept
		{
			return std::string_view(code_str_, sizeof(code_str_));
		}
	};

	/* Helper class for flag's calculation caching. */
	struct Flags
	{
		bool isProcNet_ = false;
		bool isSrc_ = false;
		bool isAllowed_ = false;
		bool isTcp_ = false;
		bool isIpv6_ = false;
	};

	struct NetIp
	{
		NetIp() = default;

		NetIp(const NetIp &o) = default;
		NetIp& operator=(const NetIp &o) = default;

		NetIp(NetIp &&o) = default;
		NetIp& operator=(NetIp &&o) = default;

		std::optional<RatelimitIndex>	ratelimit_index_ ;
		Flags				flags_;
		std::set<Net4Key>		net4s_;
		std::set<Net6Key>		net6s_;
		std::vector<NetGeo>		nets_;	//only for src
		std::vector<NetPort>		ports_;	//only for src
	};
	using NetIps = std::map<std::string, NetIp, std::less<>>;

	struct IcmpRule
	{
		bool				isAllowed_ = false;
		bool				isIpv6_ = false;
		std::optional<RatelimitIndex>	ratelimit_index_;
		std::vector<uint8_t>		types_;
	};
	using IcmpRules = std::map<std::string, IcmpRule, std::less<>>;

	struct Ratelimit
	{
		enum class State : uint8_t {
			Active,
			Inactive,
			ReadyToUse
		};

		std::string	alias_;
		uint64_t	pps_ = 0;
		uint64_t	bps_ = 0;
		State		state_ = State::ReadyToUse;
	};

	// A class that manages a collection of Ratelimit objects.
	class Ratelimits
	{
	public:
		static const RatelimitIndex MaxEntries = 255;

		Ratelimits();
		~Ratelimits() = default;

		/*
		 * Returns a view over the entire array of Ratelimit entries.
		 * The returned span includes every slot in any state.
		 */
		std::span<const Ratelimit, MaxEntries> get_all() const noexcept;

		/*
		 * Returns the index of the active Ratelimit by name.
		 *
		 * Throws an exception if the name is not found
		 * or if the Ratelimit is not in the `Active` state.
		 */
		RatelimitIndex get_active_index(std::string_view name);

		/*
		 * Inserts a new Ratelimit or updates an existing one (as `Active`).
		 */
		void upsert(std::string_view name, uint64_t pps, uint64_t bps);

		/*
		 * Marks the Ratelimit with the given name as inactive (even `ReadyToUse`).
		 * This does not immediately remove the entry.
		 *
		 * Throws if no Ratelimit with the specified name exists.
		 */
		void inactivate(std::string_view name);

		/*
		 * Marks all active Ratelimits as inactive (except `ReadyToUse`).
		 */
		void inactivate_all();

		/*
		 * Scans all Ratelimit `Inactive` entries and reclaims resources
		 * (`ReadyToReuse`). This allows slots to be reused in future insertions.
		 */
		void free_inactive();

		Ratelimits(const Ratelimits &other) = default;
		Ratelimits &operator=(const Ratelimits &other) = default;
		Ratelimits(Ratelimits &&other);
		Ratelimits &operator=(Ratelimits &&other);

	private:
		void refill_name_to_index();

		// indices are used in XfwFilterCfg::named_rates (that's why we need
		// two separate structures: ratelimits_ and name_to_index_).
		std::array<Ratelimit, MaxEntries>			ratelimits_;
		std::unordered_map<std::string_view, RatelimitIndex>	name_to_index_;
		// indices from ratelimits_ that are in `ReadyToUse`
		std::queue<RatelimitIndex>				free_indices_;
	};

	struct Action
	{
		bool				allow_ = false;
		std::optional<RatelimitIndex>	ratelimit_index_;
	};
	using Defaults = EnumArray<std::optional<Action>, DefaultIndex,
		DefaultIndex::XFW_DEFAULT_MAX>;

public:
	EvaluationMode			evaluation_mode_;
	std::optional<IpProtoFilter>	ip_proto_filter_;
	std::optional<SynCookieFilter>	syncookie_filter_;
	std::optional<TcpSynDropFilter> tcp_syn_drop_filter_;
	std::optional<TcpFlagFilter>	tcp_syn_flag_filter_;
	std::optional<TcpFlagFilter>	tcp_rst_flag_filter_;
	TcpAnomalyFilter		anomaly_filter_;
	TcpAuthFilter			auth_filter_;
	DnsFilter			dns_filter_;
	NetIps				src_rules_;
	IcmpRules			icmp_rules_;
	NetIps				dst_rules_;
	NetIps				prot_net_;
	Ratelimits			ratelimits_;
	Defaults			defaults_;
};

static_assert(std::is_move_constructible<XfwConfig>::value,
	      "XfwConfig has to be move constructable!");
static_assert(std::is_move_assignable<XfwConfig>::value,
	      "XfwConfig has to be move assignable!");
static_assert(std::is_move_assignable<XfwConfig::Ratelimits>::value,
	      "XfwConfig has to be move assignable!");
static_assert(std::is_move_assignable<XfwConfig::Ratelimits>::value,
	      "XfwConfig has to be move assignable!");
