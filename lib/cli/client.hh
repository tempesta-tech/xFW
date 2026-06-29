/**
 *	Tempesta Client library API
 *
 * SPDX-FileCopyrightText: © 2026 Tempesta Technologies, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#pragma once

#include <boost/core/noncopyable.hpp>
#include <boost/program_options/variables_map.hpp>
#include <grpcpp/grpcpp.h>

#include "tempesta_client.hh"

class Client : private boost::noncopyable {
public:
	Client() =delete;
	Client(const Client &) =delete;
	Client &operator=(const Client &) =delete;

	explicit Client(const boost::program_options::variables_map &vm);
	~Client() = default;

	int send_reload();
	int send_configuration(const TlProgConf &conf);

private:
	std::shared_ptr<grpc::Channel>		channel_;
};
