/**
 *	Tempesta guard for file descriptor
 *
 * SPDX-FileCopyrightText: © 2026 Tempesta Technologies, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#pragma once
#include "error.hh"

class FdGuard
{
public:
	explicit FdGuard(int fd, std::string_view desc = {}) : fd_(fd)
	{
		if (fd_ < 0)
			throw Except("Failed to create file descriptor: {}", desc);
	}

	~FdGuard() noexcept
	{
		if (fd_ >= 0)
			close(fd_);
	}

public:
	FdGuard(const FdGuard&) = delete;
	FdGuard& operator=(const FdGuard&) = delete;

public:
	FdGuard(FdGuard&& other) noexcept : fd_(other.fd_)
	{
		other.fd_ = -1;
	}

	FdGuard& operator=(FdGuard&& o) noexcept
	{
		if (this == &o)
			return *this;

		if (fd_ >= 0)
			close(fd_);

		fd_ = o.fd_;
		o.fd_ = -1;
		return *this;
	}

public:
	int get() const noexcept { return fd_; }

public:
	friend void swap(FdGuard& a, FdGuard& b) noexcept
	{
		std::swap(a.fd_, b.fd_);
	}

private:
	int fd_ = -1;
};