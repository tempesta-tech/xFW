/**
 *	Tempesta XFW index pool with transactional semantics.
 *
 * Designed to work with array-backed storage, including:
 *
 *   - BPF_MAP_TYPE_ARRAY (Linux eBPF map array)
 *   - fixed-size C++ arrays / std::array
 *
 * The pool itself does not own or store elements. It only manages index
 * allocation and reuse, while the actual storage is maintained externally.
 *
 * All operations are mediated by IndexPoolTransaction to ensure
 * transactional consistency (commit / rollback semantics).

 * Not thread-safe.
 *
 * SPDX-FileCopyrightText: © 2026 Tempesta Technologies, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#pragma once
#include <functional>
#include <vector>

class IndexPoolTransaction;

/*
 * Pool of reusable indices.
 *
 * Direct access to allocate/release is intentionally restricted.
 * All modifications must go through IndexPoolTransaction to ensure
 * transactional semantics.
 *
 * This class is not thread-safe. It assumes transactions are applied
 * sequentially, so no internal synchronization is provided.
 */
class IndexPool
{
public:
	using Index = uint32_t;
	using Indices = std::vector<Index>;
	using ReleaseCallback = std::function<void(Index)>;

public:
	explicit IndexPool(size_t size, ReleaseCallback cb);

private:
	Index allocate();
	void release(Index index) noexcept;

private:
	friend class IndexPoolTransaction;

	Indices		free_indices_;
	ReleaseCallback	cb_on_release_;
};

/*
 * RAII transaction guard for IndexPool. If destroyed without a prior commit(),
 * all allocated indices are returned to the pool.
 */
class IndexPoolTransaction
{
public:
	using Index = IndexPool::Index;
	using PendingIndices = std::vector<Index>;

public:
	explicit IndexPoolTransaction(IndexPool& pool);
	~IndexPoolTransaction() noexcept;

	IndexPoolTransaction(const IndexPoolTransaction &) = delete;
	IndexPoolTransaction &operator=(const IndexPoolTransaction &) = delete;

	IndexPoolTransaction(IndexPoolTransaction &&) = delete;
	IndexPoolTransaction &operator=(IndexPoolTransaction &&) = delete;

public:
	/* Allocate an index within the transaction. */
	Index allocate();

	/* Mark an index to be released when the transaction is committed. */
	void release(Index index) noexcept;

	/* Commit the transaction. */
	void commit() noexcept;

private:
	void rollback() noexcept;

private:
	IndexPool&	pool_;
	PendingIndices	allocated_;
	PendingIndices	released_;
};
