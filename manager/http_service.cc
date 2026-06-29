/**
 *      Tempesta Management HTTP service
 *
 * SPDX-FileCopyrightText: © 2026 Tempesta Technologies, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <exception>
#include <memory>
#include <string>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/buffer.hpp>
#include <boost/asio/error.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/version.hpp>

#include "http_service.hh"
#include "xfw/stats.hh"

namespace beast = boost::beast;
namespace http = beast::http;
namespace net = boost::asio;

using tcp = net::ip::tcp;

static http::response<http::string_body>
create_plain_response(bool keep_alive, unsigned version, std::string_view body = {})
{
	http::response<http::string_body> res{http::status::ok, version};

	res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
	res.keep_alive(keep_alive);
	res.set(http::field::content_type, "text/plain");

	if (body.size()) {
		res.body() = body;
		res.prepare_payload();
        }

	return res;
}

static http::response<http::string_body>
handle_metrics_request(http::request<http::string_body>&& req)
{
	// We make syscall to get map descriptor on every request.
	// Idea is to getting it only when needed. Stats retriving is not
	// performance critical part. For performance critical part we have tfw_logger.
	BpfStats bpf_stats;

	auto stats = bpf_stats.load_global_stats_prometheus();
	auto res = create_plain_response(req.keep_alive(), req.version(), stats);

	return res;
}

ManagerHttpService::ManagerHttpService(tcp::socket&& socket)
	: socket_(std::move(socket))
{
}

net::awaitable<void>
ManagerHttpService::session()
{
	try {
		beast::flat_buffer buffer;
		for (;;) {
			http::request_parser<http::string_body> parser;
			parser.body_limit(10000);

			try {
				co_await http::async_read(socket_, buffer, parser,
							  net::use_awaitable);
			}
			catch (const boost::system::system_error& e) {
				if (e.code() ==  http::error::end_of_stream) {
					TE_INF("Client closed connection");
					break;
				}
				throw;
			}

			bool close = co_await handle_request(parser.release());
			if (close)
				break;
		}
	}
	catch (const boost::system::system_error& e) {
		TE_ERR("Error while processing request: {}", e.what());
	}
	catch (const std::exception& e) {
		TE_ERR("Exception while processing request: {}", e.what());
	}

	beast::error_code ec;
	socket_.shutdown(tcp::socket::shutdown_send, ec);
}

net::awaitable<bool>
ManagerHttpService::handle_request(http::request<http::string_body>&& req)
{
	unsigned version = req.version();
	bool keep_alive = req.keep_alive();
	std::exception_ptr ep = nullptr;

	if(req.method() != http::verb::get) {
		auto res = create_plain_response(keep_alive, version, "Method not Allowed");
		res.result(http::status::method_not_allowed);
		co_return co_await send_response(std::move(res));
	}

	try {
		if(req.target() == "/metrics") {
			auto res = handle_metrics_request(std::move(req));
			co_return co_await send_response(std::move(res));
		}
	}
	catch (const std::bad_alloc& e) {
		throw;
	}
	catch (...) {
		ep = std::current_exception();
	}

	if (ep) {
		auto res = create_plain_response(keep_alive, version, "Exception caught while processing request");
		res.result(http::status::internal_server_error);
		co_return co_await send_response(std::move(res));
	}

	auto res = create_plain_response(keep_alive, version, "The resource '" + std::string(req.target()) + "' was not found");
	res.result(http::status::not_found);
	co_return co_await send_response(std::move(res));
}

net::awaitable<bool>
ManagerHttpService::send_response(http::response<http::string_body>&& res)
{
	bool close = !res.keep_alive() || res.need_eof();

	co_await http::async_write(socket_, std::move(res), net::use_awaitable);
	co_return close;
}
