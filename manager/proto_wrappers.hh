/**
 *	Tempesta Wrapper for proto structs
 *
 * SPDX-FileCopyrightText: © 2026 Tempesta Technologies, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#pragma once
#include "../lib/bitset.hh"
#include "../lib/proto/bitset_helper.hh"
#include "generated/proto_generated.hh"
#include "xfw_update_error.hh"

enum EditAction {
	ADD	= 0,
	DELETE	= 1,
	REPLACE	= 2
};

// TODO #187: Refactor ProtoWrapper to use virtual functions instead of templates
//       This should be done after the CR 187 is completed, because now we don't
// have unified type for flags.
//       Goals:
//       - Provide a common interface for action(), alias(), has_matchers(), flags()
//       - Allow different ProtoType wrappers to be used polymorphically
//       - Keep FlagsType unified or convertible for interface use

template<typename ProtoType>
struct ProtoFlags
{
	static_assert(sizeof(ProtoType) == 0, "ProtoFlags not defined for this ProtoType");
};

/**
 * ProtoWrapper is a wrapper around a FlatBuffers proto structure.
 * It provides convenient access to the proto's fields, flags, alias,
 * and allows querying for edit actions and matchers.
 */
template<typename ProtoType>
class ProtoWrapper
{
public:
	// Type of flags associated with this ProtoType, resolved via ProtoFlags trait
	using FlagsType = typename ProtoFlags<ProtoType>::Type;
	using FlagsBitset = BitSet<FlagsType, ProtoFlags<ProtoType>::MaxBit>;

	// Name of the proto type, for logging or error messages
	inline static const char* TypeName = typeid(ProtoType).name();

	explicit ProtoWrapper(const ProtoType *rule):
		rule_(read_rule(rule)), alias_(read_alias(rule)), flags_(read_flags(rule))
	{
	}

public:
	/**
	 * Get the edit action defined by this protocol rule.
	 */
	EditAction action() const;

	/**
	 * Check whether this protocol rule contains any matchers.
	 */
	bool has_matchers() const;

public:
	/**
	 * Get the alias associated with this proto rule.
	 */
	std::string_view alias() const
	{
		return alias_;
	}

	/**
	 * Access the flags associated with this proto rule.
	 */
	const FlagsBitset &flags() const
	{
		return flags_;
	}

	/**
	 * Access the underlying proto rule structure.
	 */
	const ProtoType &rule() const
	{
		return rule_;
	}

private:
	static const ProtoType&
	read_rule(const ProtoType *rule)
	{
		verify(!!rule, "Null '{}' field is not allowed in proto data.", TypeName);
		return *rule;
	}

	static std::string_view
	read_alias(const ProtoType *rule)
	{
		assert(!!rule);
		const uint32_t MaxAliasSize = 100;
		verify(rule->alias(), "Null '{}::alias' field is not allowed in "
			"proto data.", TypeName);
		verify(rule->alias()->size() < MaxAliasSize, "Size of {}::alias "
			"is too big.", TypeName);
		return rule->alias()->string_view();
	}

	static FlagsBitset
	read_flags(const ProtoType *rule)
	{
		assert(!!rule);
		verify(rule->flags(), "Null '{}::flags' field is not allowed in "
			"proto data.", TypeName);

		FlagsBitset flags;
		verify(bitset_deserialize(*rule->flags(), flags),
		       "Unexpected bytes count at flags");
		return flags;
	}

private:
	const ProtoType		&rule_;
	const std::string_view	alias_;
	const FlagsBitset	flags_;
};

template<>
struct ProtoFlags<TempestaRPC::NetRule>
{
	using Type = TempestaRPC::NetRuleOpt;
	static constexpr Type MaxBit = TempestaRPC::NetRuleOpt_MAX;
};

template<>
EditAction
ProtoWrapper<TempestaRPC::NetRule>::action() const
{
	using namespace TempestaRPC;

	if (flags_.test(NetRuleOpt::NetRuleOpt_REPLACE)) {
		verify(!flags_.test(NetRuleOpt::NetRuleOpt_DELETE), "Flags "
			"REPLACE and DELETE can't be set together.");
		return EditAction::REPLACE;
	}
	else if (flags_.test(NetRuleOpt::NetRuleOpt_DELETE)) {
		return EditAction::DELETE;
	}
	return EditAction::ADD;
}

template<>
inline bool
ProtoWrapper<TempestaRPC::NetRule>::has_matchers() const
{
	return (rule_.net4s() && rule_.net4s()->size()) ||
	       (rule_.net6s() && rule_.net6s()->size()) ||
	       (rule_.nets() && rule_.nets()->size()) ||
	       (rule_.ports() && rule_.ports()->size());
}

template<>
struct ProtoFlags<TempestaRPC::IcmpRule>
{
	using Type = TempestaRPC::IcmpRuleOpt;
	static constexpr Type MaxBit = TempestaRPC::IcmpRuleOpt_MAX;
};

template<>
EditAction
ProtoWrapper<TempestaRPC::IcmpRule>::action() const
{
	using namespace TempestaRPC;

	if (flags_.test(IcmpRuleOpt::IcmpRuleOpt_REPLACE)) {
		verify(!flags_.test(IcmpRuleOpt::IcmpRuleOpt_DELETE), "Flags "
			"REPLACE and DELETE can't be set together.");
		return EditAction::REPLACE;
	}
	else if (flags_.test(IcmpRuleOpt::IcmpRuleOpt_DELETE)) {
		return EditAction::DELETE;
	}
	return EditAction::ADD;
}

template<>
inline bool
ProtoWrapper<TempestaRPC::IcmpRule>::has_matchers() const
{
	return rule_.types() && rule_.types()->size() != 0;
}

using ProtoNetRule = ProtoWrapper<TempestaRPC::NetRule>;
using ProtoIcmpRule = ProtoWrapper<TempestaRPC::IcmpRule>;