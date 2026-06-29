/**
 *	Tempesta Management server
 *
 * SPDX-FileCopyrightText: © 2026 Tempesta Technologies, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#pragma once
#include "xfw/xfw.hh"
#include "../lib/error.hh"

#include <grpcpp/grpcpp.h>
#include <boost/core/noncopyable.hpp>
#include <boost/program_options/variables_map.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/awaitable.hpp>

namespace po = boost::program_options;
namespace net = boost::asio;

using tcp = boost::asio::ip::tcp;

/**
 * The server is single-threaded for now.
 */
class TMServer: private boost::noncopyable, public std::enable_shared_from_this<TMServer>
{
public:
	TMServer() =delete;

	explicit TMServer(net::any_io_executor executor, const po::variables_map &vm);
	~TMServer();

	void start();
	void stop();

private:
	void grpc_thread_function(std::stop_token stoken);
	void grpc_start();
	void grpc_stop();
	void http_start();
	void http_stop();
	net::awaitable<void> http_corouting();

private:
	const std::string			grpc_address_;
	const net::ip::address			http_address_;
	const uint16_t				http_port_;
	Xfw					xfw_;
	std::unique_ptr<grpc::Server>		grpc_server_;
	std::jthread				grpc_thread_;
	const net::any_io_executor		executor_;
	tcp::acceptor				acceptor_;
};
