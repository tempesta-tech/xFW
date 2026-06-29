/**
 *	API for section with name "Defaults"
 *
 * SPDX-FileCopyrightText: © 2026 Tempesta Technologies, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#pragma once

#include "tcl_private.hh"
#include "section.hh"

struct DefaultsSection final: public Section
{
public:
	DefaultsSection(XfwConf &conf);
	virtual ~DefaultsSection() override = default;

private:
	virtual void commit() override;
	virtual std::pair<bool, std::shared_ptr<LineConsumer>> process_body() override;
	virtual std::string get_path() const override;

protected:
	enum class DataType: size_t
	{
		SRC_IP,
		SRC_PORT,
		DST,
		ICMP
	};

	static const char*
	type_to_name(DataType type);

protected:
	struct TcpIpDefaultSection final: public Section
	{
	public:
		TcpIpDefaultSection(DataType type, DefaultsSection &parent);
		virtual ~TcpIpDefaultSection() override = default;

	private:
		virtual void commit() override;
		virtual std::string get_path() const override;
		virtual bool process_attributes() override;

	private:
		void set_flag(DefaultIndex flag);

	private:
		const DefaultIndex	ip4_tcp_;
		const DefaultIndex	ip6_tcp_;
		const DefaultIndex	ip4_udp_;
		const DefaultIndex	ip6_udp_;

	private:
		DefaultsSection&					parent_;
		BitSet<DefaultIndex, XFW_DEFAULT_MAX>	flags_;
	};

	struct IpProtoDefaultSection final: public Section
	{
	public:
		IpProtoDefaultSection(DataType type, DefaultsSection &parent);
		virtual ~IpProtoDefaultSection() override = default;

	private:
		virtual void commit() override;
		virtual std::string get_path() const override;
		virtual bool process_attributes() override;

	private:
		void set_flag(DefaultIndex flag);

	private:
		const DefaultIndex	ip4_;
		const DefaultIndex	ip6_;

	private:
		DefaultsSection&					parent_;
		BitSet<DefaultIndex, XFW_DEFAULT_MAX>	flags_;
	};

protected:
	enum class IPVersion: size_t
	{
		IP4,
		IP6
	};

	enum class TransportProtocol: size_t
	{
		NONE,
		TCP = NONE,
		UDP
	};

	static constexpr DefaultIndex
	get_index(DataType type, TransportProtocol tp, IPVersion ipv)
	{
		return static_cast<DefaultIndex>((static_cast<size_t>(type) << 2)
			| (static_cast<size_t>(tp) << 1) | static_cast<size_t>(ipv));
	}
	friend struct StaticGetIndexTests;

	void set_presence_or_throw(DefaultIndex flag);

private:
	XfwConf&			xfw_conf_;
	std::vector<DefaultAction>	defaults_;
	/**
	 * In the default section, shorthand rules can be used, for example
	 * 'dst: allow;'. Such a rule applies to a group of protocols:
	 * ip4.tcp, ip4.udp, ip6.tcp, and ip6.udp. A user may also define
	 * explicit rules, for example 'dst ip4.tcp: block;'.
	 *
	 * However, using a shorthand rule together with a specific rule
	 * for a protocol it covers is prohibited, as this creates ambiguity
	 * in behavior and interpretation. To enforce this restriction,
	 * presence_flags_ are used to track which rules have already been
	 * processed during the reading of the default section.
	 *
	 * Each rule, whether shorthand or explicit, also sets its own flags_
	 * when it is read. For example, IpProtoDefaultSection::flags_ and
	 * TcpIpDefaultSection::flags_ contain only the flags corresponding
	 * to the single rule being processed (e.g., 'dst: allow;' sets four
	 * flags). These local flags do not detect overlaps between rules;
	 * such conflicts are checked exclusively via presence_flags_.
	 */
	BitSet<DefaultIndex, XFW_DEFAULT_MAX>	presence_flags_;
};
