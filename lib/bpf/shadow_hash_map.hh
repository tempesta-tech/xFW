/**
 *	Tempesta xFW eBPF shadow maps
 *
 * Userspace shadow state for incremental synchronization of a kernel BPF map.
 *
 * The class maintains:
 *	1. userspace snapshot_      - last successfully synchronized state
 *	2. kernel BPF hash map      - actual kernel-side storage
 *
 * Failure semantics:
 *	- partial batch failures are not recovered incrementally
 *	- map is marked as requiring full resynchronization
 *	- next replace() performs clear + full replay
 *
 * Design goals:
 *	- minimize syscalls via batch operations
 *	- avoid unnecessary kernel rewrites
 *	- preserve userspace view of synchronized state
 *
 * Notes:
 *	- snapshot_ is authoritative only after successful synchronization
 *   	 replace() may consume moved-in state
 *	- optimized for large hash maps with incremental updates
 *
 * SPDX-FileCopyrightText: © 2026 Tempesta Technologies, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#pragma once

#include "hash_map.hh"
#include "../log.hh"

/*
 * TODO #5:
 * BpfShadowHashMap currently recomputes update/delete diffs by comparing
 * synthesized kernel snapshots.
 *
 * However, the original user configuration is already stored in XfwConfig,
 * and configuration updates are received as semantic diffs from userspace
 * (even when representing a full config replacement).
 *
 * This means that kernel map mutations may be derived directly from the
 * higher-level configuration diff, without maintaining an additional
 * shadow-snapshot layer for generated BPF maps.
 *
 * Investigate removing BpfShadowHashMap entirely and applying incremental
 * map updates directly during config-to-map materialization.
 */
template<typename Key, typename Value, typename Hash = std::hash<Key>>
class BpfShadowHashMap
{
public:
	using Snapshot = std::unordered_map<Key, Value, Hash>;
	using BpfMap = BpfHashMap<Key, Value>;

	explicit BpfShadowHashMap(const char *name)
		: bpf_map_(name)
	{
	}

public:
	/*
	 * Replace current kernel state with new_state.
	 *
	 * new_state may be consumed (moved-from) to avoid unnecessary copies.
	 *
	 * If batch operations fail, we do NOT attempt partial recovery.
	 * Instead we mark the state as requiring a full resync on the next call.
	 */
	bool replace(Snapshot new_state)
	{
		// If previous batch operation failed, we defer consistency repair
		// and fully resynchronize from provided state.
		if (resync_required_)
			return full_resync(std::move(new_state));
	
		std::vector<Key>   delete_keys;
		std::vector<Key>   upsert_keys;
		std::vector<Value> upsert_values;

		const size_t hint = std::min<size_t>(
			std::max(snapshot_.size(), new_state.size()),
			1024
		);

		delete_keys.reserve(hint);
		upsert_keys.reserve(hint);
		upsert_values.reserve(hint);

		/*
		 * Diff is computed directly from moved-in state.
		 * This avoids an extra copy when caller passes rvalue.
		 */
		build_diff(new_state, delete_keys, upsert_keys, upsert_values);

		/*
		 * Apply deletes first to free kernel map slots early.
		 *
		 * This reduces pressure on BPF map capacity during updates,
		 * especially when update set overlaps heavily with existing keys.
		 */
		if (!apply_delete(delete_keys))
			return false;

		/*
		 * Apply inserts/updates after deletion phase.
		 * This ensures we do not temporarily exceed map capacity.
		 */
		if (!apply_upsert(upsert_keys, upsert_values))
			return false;

		/*
		 * Commit successful state.
		 * Move semantics avoids redundant copy if Snapshot is large.
		 */
		snapshot_ = std::move(new_state);
		return true;
	}

	//TODO: it would be good to hide it in private members
	const Snapshot & snapshot() const noexcept
	{
		return snapshot_;
	}

private:
	template<typename T>
	static std::span<const T>
	make_span(const std::vector<T> &v, size_t off, size_t cnt)
	{
		return std::span<const T>(v.data() + off, cnt);
	}

	/*
	 * Build diff between current snapshot and desired state.
	 */
	void build_diff(const Snapshot &new_state, std::vector<Key> &del,
		std::vector<Key> &upd_keys, std::vector<Value> &upd_values)
	{
		for (const auto &[k, old_v] : snapshot_) {
			auto it = new_state.find(k);

			if (it == new_state.end()) {
				del.emplace_back(k);
			}
			else if (it->second != old_v) {
				upd_keys.emplace_back(k);
				upd_values.emplace_back(it->second);
			}
		}

		for (const auto &[k, v] : new_state) {
			if (!snapshot_.contains(k)) {
				upd_keys.emplace_back(k);
				upd_values.emplace_back(v);
			}
		}
	}

	/*
	 * Batch delete with failure -> triggers full resync later.
	 */
	bool apply_delete(const std::vector<Key> &keys)
	{
		if (keys.empty())
			return true;

		for (size_t i = 0; i < keys.size(); i += BatchSize) {
			uint32_t cnt = static_cast<uint32_t>(
				std::min(BatchSize, keys.size() - i));

			if (bpf_map_.delete_batch(make_span(keys, i, cnt), cnt)) {
				TE_ERR("replace: batch delete failed, scheduling resync");
				resync_required_ = true;
				return false;
			}
		}

		return true;
	}

	/*
	 * Batch update with failure -> triggers full resync later.
	 */
	bool
	apply_upsert(const std::vector<Key> &keys, const std::vector<Value> &values)
	{
		if (keys.empty())
			return true;

		for (size_t i = 0; i < keys.size(); i += BatchSize) {
			uint32_t cnt = static_cast<uint32_t>(
				std::min(BatchSize, keys.size() - i));

			auto kspan = make_span(keys, i, cnt);
			auto vspan = make_span(values, i, cnt);

			if (bpf_map_.update_batch(kspan, vspan, cnt)) {
				TE_ERR("replace: batch update failed, scheduling resync");
				resync_required_ = true;
				return false;
			}
		}

		return true;
	}

	/*
	 * Full resync: rebuild entire map.
	 */
	bool full_resync(Snapshot state)
	{
		if (bpf_map_.clear(BatchSize)) {
			TE_ERR("full_resync: clear failed");
			return false;
		}

		std::vector<Key>   keys;
		std::vector<Value> values;

		keys.reserve(state.size());
		values.reserve(state.size());

		for (const auto &[k, v] : state) {
			keys.emplace_back(k);
			values.emplace_back(v);
		}

		if (!apply_upsert(keys, values)) {
			TE_ERR("full_resync: upsert failed");
			return false;
		}

		snapshot_ = std::move(state);
		resync_required_ = false;

		return true;
	}

private:
	static constexpr size_t BatchSize = 1024;

	Snapshot	snapshot_;
	BpfMap		bpf_map_;
	bool		resync_required_ = false;
};
