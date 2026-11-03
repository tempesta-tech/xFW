/**
 *	Tempesta xFW gateway SYN proxy runtime configuration
 *
 * SPDX-FileCopyrightText: © 2026 Tempesta Technologies, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#pragma once

#include "configuration.hh"

class BpfMapsManager;

class SynproxyManager {
public:
	explicit SynproxyManager(BpfMapsManager &maps);
	void validate(const XfwConfig::SynproxyFilter &scope) const;
	void set_config(const XfwConfig::SynproxyFilter &scope);
	const XfwConfig::SynproxyFilter &config() const noexcept { return active_; }

private:
	struct Snapshot {
		uint64_t generation = 0;
		uint64_t retired_until_ns = 0;
		XfwConfig::SynproxyFilter active, retired;
	};
	void recover();
	void finish(const Snapshot &snapshot);
	void install_nft(const XfwConfig::SynproxyFilter &scope) const;
	static Snapshot read_snapshot(const std::string &path);
	static void save_snapshot(const std::string &path, const Snapshot &snapshot);

	BpfMapsManager &maps_;
	bool available_ = false;
	uint64_t generation_ = 0;
	uint64_t retired_until_ns_ = 0;
	XfwConfig::SynproxyFilter active_, retired_;
};
