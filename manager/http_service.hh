/**
 *      Tempesta Management HTTP service
 *
 * SPDX-FileCopyrightText: © 2026 Tempesta Technologies, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#pragma once

#include <memory>
#include <string>

#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/asio/awaitable.hpp>

#include "../lib/log.hh"

namespace beast = boost::beast;
namespace http = beast::http;
namespace net = boost::asio;
using tcp = boost::asio::ip::tcp;

class ManagerHttpService : public std::enable_shared_from_this<ManagerHttpService>
{

public:
	explicit ManagerHttpService(tcp::socket&& socket);

	net::awaitable<void> session();

private:
	net::awaitable<bool> handle_request(http::request<http::string_body>&& req);

	net::awaitable<bool> send_response(http::response<http::string_body>&& res);

private:
	tcp::socket socket_;
};

