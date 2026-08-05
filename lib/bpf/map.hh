/**
 *	Tempesta BpfMap - base class for BPF map wrappers using FdGuard.
 *
 * SPDX-FileCopyrightText: © 2026 Tempesta Technologies, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#pragma once

#include <bpf/bpf.h>

#include <string>

#include "../fd_guard.hh"
#include "../error.hh"

/**
 * This class owns an FdGuard and exposes a common interface for all BPF maps.
 *
 * Example:
 * 	BpfMap map("xfw_map_name");
 *	int fd = map.fd();
 */
class BpfMap
{
public:
	explicit BpfMap(const char *map_name)
		: name_(map_name), fd_(open_bpf_map_fd(name_))
	{}

	/**
	 * Constructor from existing FdGuard with human-readable map name for
	 * diagnostics.
	 */
	explicit BpfMap(const char *map_name, FdGuard &&fd)
		: name_(map_name), fd_(std::move(fd))
	{}

public:
	BpfMap(const BpfMap&) = delete;
	BpfMap& operator=(const BpfMap&) = delete;

	BpfMap(BpfMap&&) = delete;
	BpfMap& operator=(BpfMap&&) = delete;

public:
	int fd() const noexcept { return fd_.get(); }

	const char *name() const noexcept { return name_.c_str(); }

private:
	static FdGuard
	open_bpf_map_fd(const std::string &map_name)
	{
		const std::string path =
			std::string("/sys/fs/bpf/xfw/") + map_name;

		int fd = bpf_obj_get(path.c_str());
		if (fd < 0)
			throw Except("Failed to get BPF map: {}", path);

		return FdGuard(fd);
	}
protected:
	const std::string	name_;
	FdGuard			fd_;
};
