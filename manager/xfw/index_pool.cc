/**
 *	Tempesta XFW index pool implementation.
 *
 * SPDX-FileCopyrightText: © 2026 Tempesta Technologies, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include <algorithm>
#include <numeric>

#include "../../lib/error.hh"
#include "index_pool.hh"

//=================================IndexPool====================================
IndexPool::IndexPool(size_t size, ReleaseCallback cb)
	: cb_on_release_(std::move(cb))
{
	free_indices_.resize(size);
	std::iota(free_indices_.begin(), free_indices_.end(), 0);
}

IndexPool::Index
IndexPool::allocate()
{
	if (free_indices_.empty())
		throw Except("IndexPool has no free indices");

	Index index = free_indices_.back();
	free_indices_.pop_back();
	return index;
}

void
IndexPool::release(Index index) noexcept
{
	cb_on_release_(index);
	free_indices_.push_back(index);
}

//=================================IndexPoolTransaction=========================
IndexPoolTransaction::IndexPoolTransaction(IndexPool& pool) : pool_(pool)
{
}

IndexPoolTransaction::~IndexPoolTransaction() noexcept
{
	rollback();
}

IndexPoolTransaction::Index
IndexPoolTransaction::allocate()
{
	Index index = pool_.allocate();
	allocated_.push_back(index);
	return index;
}

void
IndexPoolTransaction::release(Index index) noexcept
{
	released_.push_back(index);
}

void
IndexPoolTransaction::commit() noexcept
{
	for (Index index : released_)
		pool_.release(index);

	// Successfully allocated indices now belong to the caller.
	allocated_.clear();
	released_.clear();
}

void
IndexPoolTransaction::rollback() noexcept
{
	for (Index index : allocated_)
		pool_.release(index);

	allocated_.clear();
	released_.clear();
}
