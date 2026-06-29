/**
 *	Tempesta Xfw configuration implementation
 *
 * SPDX-FileCopyrightText: © 2026 Tempesta Technologies, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <assert.h>

#include "../../lib/error.hh"
#include "configuration.hh"

//===========================XfwConfig::NetGeo==================================
XfwConfig::NetGeo::NetGeo(uint16_t code): code_(code)
{
}

//===========================XfwConfig::Ratelimits==============================
XfwConfig::Ratelimits::Ratelimits()
{
	for (XfwConfig::RatelimitIndex i = 0; i < MaxEntries; ++i)
		// i.e. on object instantiation all ratelimits_ entries are `ReadyToUse`
		free_indices_.push(i);
}

std::span<const XfwConfig::Ratelimit, XfwConfig::Ratelimits::MaxEntries>
XfwConfig::Ratelimits::get_all() const noexcept
{
	return ratelimits_;
}

XfwConfig::RatelimitIndex
XfwConfig::Ratelimits::get_active_index(std::string_view name)
{
	if (auto it = name_to_index_.find(name); it != name_to_index_.end()) {
		RatelimitIndex index = it->second;
		if (ratelimits_[index].state_ == Ratelimit::State::Active)
			return index;
	}

	throw Except("Active ratelimit with name {} is not found", name);
}

void
XfwConfig::Ratelimits::upsert(std::string_view name, uint64_t pps, uint64_t bps)
{
	if (auto it = name_to_index_.find(name); it != name_to_index_.end()) {
		auto& ratelimit = ratelimits_[it->second];
		ratelimit.pps_ = pps;
		ratelimit.bps_ = bps;
		ratelimit.state_ = Ratelimit::State::Active;
		return;
	}

	if (free_indices_.empty())
		throw Except("No free slots for ratelimits. Can't insert '{}'", name);

	const RatelimitIndex index = free_indices_.front();
	free_indices_.pop();

	ratelimits_[index] = Ratelimit{
		.alias_ = std::string(name),
		.pps_ = pps,
		.bps_ = bps,
		.state_ = Ratelimit::State::Active
	};
	// string_view is safe because refers to ratelimits_[index].alias_.
	name_to_index_[ratelimits_[index].alias_] = index;
}

void
XfwConfig::Ratelimits::inactivate(std::string_view name)
{
	if (auto it = name_to_index_.find(name); it != name_to_index_.end())
		ratelimits_[it->second].state_ = Ratelimit::State::Inactive;
	else
		throw Except("Ratelimit with name '{}' not found", name);
}

void
XfwConfig::Ratelimits::inactivate_all()
{
	for (auto& entry : ratelimits_) {
		if (entry.state_ == Ratelimit::State::Active)
			entry.state_ = Ratelimit::State::Inactive;
	}
}

void
XfwConfig::Ratelimits::free_inactive()
{
	for (RatelimitIndex i = 0; i < MaxEntries; ++i) {
		if (ratelimits_[i].state_ != Ratelimit::State::Inactive)
			continue;

		ratelimits_[i].state_ = Ratelimit::State::ReadyToUse;
		name_to_index_.erase(ratelimits_[i].alias_);
		free_indices_.push(i);
	}
}

XfwConfig::Ratelimits::Ratelimits(Ratelimits &&other)
	: ratelimits_(std::move(other.ratelimits_)),
	free_indices_(std::move(other.free_indices_))
{
	refill_name_to_index();
}

XfwConfig::Ratelimits &
XfwConfig::Ratelimits::operator=(Ratelimits &&other)
{
	if (this == &other)
		return *this;

	ratelimits_ = std::move(other.ratelimits_);
	free_indices_ = std::move(other.free_indices_);
	refill_name_to_index();
	return *this;
}


void
XfwConfig::Ratelimits::refill_name_to_index()
{
	name_to_index_.clear();
	for (XfwConfig::RatelimitIndex i = 0; i < MaxEntries; ++i) {
		if (ratelimits_[i].state_ == Ratelimit::State::ReadyToUse)
			continue;
		name_to_index_.emplace(ratelimits_[i].alias_, i);
	}
}
