/**
 *	Tempesta XFW configuration management
 *
 * SPDX-FileCopyrightText: © 2026 Tempesta Technologies, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include <string>
#include <sstream>

#include "tcl_private.hh"

std::ostream& operator<<(std::ostream &os, const Ratelimit &obj) noexcept
{
	os << "obj.alias_=" << obj.alias_ << " obj.flags_=" << obj.flags_
	   << " obj.bps_.size()=" << obj.bps_.value_or(0)
	   << " obj.pps_.size()=" << obj.pps_.value_or(0);
	return os;
}

std::ostream& operator<<(std::ostream &os, const NetRule &obj) noexcept
{
	os << "obj.alias_=" << (obj.alias_.empty()? "default": obj.alias_)
	   << " obj.flags_=" << obj.flags_ << " obj.nets_.size()=" << obj.nets_.size()
	   << " obj.net4s_.size()=" << obj.net4s_.size()
	   << " obj.net6s_.size()=" << obj.net6s_.size()
	   << " obj.ports_.size()=" << obj.ports_.size();
	if (!obj.ratelimit_.empty())
		os << " obj.ratelimit_=" << obj.ratelimit_;
	return os;
}

std::ostream& operator<<(std::ostream &os, const IcmpRule &obj) noexcept
{
	os << "obj.alias_=" << (obj.alias_.empty()? "default": obj.alias_);
	if (!obj.ratelimit_.empty())
		os << " obj.ratelimit_=" << obj.ratelimit_;
	os << " obj.flags_=" << obj.flags_
	   << " obj.types_.size()=" << obj.types_.size();
	return os;
}

std::ostream& operator<<(std::ostream &os, const DefaultAction &obj) noexcept
{
	os << "obj.allow_=" << obj.allow_;
	if (!obj.ratelimit_.empty())
		os << " obj.ratelimit_=" << obj.ratelimit_;
	os << " obj.flags_=" << obj.flags_;
	return os;
}

std::ostream& operator<<(std::ostream &os, const XfwConf &obj) noexcept
{
	if (obj.syncookie_.has_value()) {
		os << "tcp_syncookies: passive_timer="
		   << obj.syncookie_.value().passive_timer_
		   << " flood_timer=" << obj.syncookie_.value().flood_timer_ << "\n";
	}

	os << "flags: " << obj.flags_ << "\nnet_rules_={\n";
	for (auto it = obj.net_rules_.begin(); it != obj.net_rules_.end(); ++it) {
		bool is_last = std::next(it) == obj.net_rules_.end();
		os << "\t{" <<  *it << (is_last? "}\n" : "},\n");
	}
	os << "}\nicmp_rules_={\n";
	for (auto it = obj.icmp_rules_.begin(); it != obj.icmp_rules_.end(); ++it) {
		bool is_last = std::next(it) == obj.icmp_rules_.end();
		os << "\t{" <<  *it << (is_last? "}\n" : "},\n");
	}
	os << "}\n";

	os << "ratelimits: \n";
	for (auto it = obj.ratelimits_.begin(); it != obj.ratelimits_.end(); ++it) {
		bool is_last = std::next(it) == obj.ratelimits_.end();
		os << "\t{" <<  *it << (is_last? "}\n" : "},\n");
	}

	os << "defaults: \n";
	for (auto it = obj.defaults_.begin(); it != obj.defaults_.end(); ++it) {
		bool is_last = std::next(it) == obj.defaults_.end();
		os << "\t{" << *it << (is_last? "}\n" : "},");
	}
	return os;
}
