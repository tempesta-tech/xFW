/**
 *	Tempesta management server
 *
 * SPDX-FileCopyrightText: © 2026 Tempesta Technologies, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "server.hh"

#include "grpc_service.hh"
#include "http_service.hh"
#include "shutdown.hh"
#include "../lib/error.hh"
#include "../lib/log.hh"

#include <boost/asio.hpp>

namespace net = boost::asio;
namespace beast = boost::beast;
using tcp = boost::asio::ip::tcp;

static std::string
get_grpc_server_address(const po::variables_map &vm)
{
	//Address validation with boost::asio. Throw on error.
	(void) net::ip::address::from_string(vm["listen"].as<std::string>());

	return vm["listen"].as<std::string>() + ":"
		+ std::to_string(vm["port"].as<uint16_t>());
}

static net::ip::address
get_http_server_address(const po::variables_map &vm)
{
	return net::ip::address::from_string(vm["listen"].as<std::string>());
}

static uint16_t
get_http_server_port(const po::variables_map &vm)
{
	return vm["http-port"].as<uint16_t>();
}

static std::optional<std::string>
get_geoip(const po::variables_map &vm)
{
	if (vm.count("geoip"))
		return vm["geoip"].as<std::string>();
	return {};
}

TMServer::TMServer(net::any_io_executor executor, const po::variables_map &vm) try
	: grpc_address_(get_grpc_server_address(vm))
	, http_address_(get_http_server_address(vm))
	, http_port_(get_http_server_port(vm)), xfw_{get_geoip(vm)}
	, executor_(executor), acceptor_{executor_, {http_address_, http_port_}}
{
	TE_INF("Http server listening on {}:{}", vm["listen"].as<std::string>(),
		http_port_);
} catch (const boost::system::system_error& e) {
	TE_ERR("Http server creation failed: {}", e.what());
	throw;
} catch (std::exception& e) {
	TE_ERR("Http server creation failed: {}", e.what());
	throw;
} catch (...) {
	TE_ERR("Http server creation failed: {}", "Unexpected error.");
	throw;
}

TMServer::~TMServer()
{
	TE_INF("Tempesta Management Server: shut down\n");
}

void
TMServer::grpc_thread_function(std::stop_token stoken)
try
{
	ManagerGrpcService service(xfw_);
	grpc::ServerBuilder builder;
	builder.AddListeningPort(grpc_address_, grpc::InsecureServerCredentials());
	builder.RegisterService(&service);
	grpc_server_ = builder.BuildAndStart();
	if (!grpc_server_)
		throw Except("Can't start grpc server.");
	TE_INF("Grpc server is listening on {}", grpc_address_);

	if (stoken.stop_requested()) {
		// TODO: #415 research why we need these two deadlines for shutdowns
		grpc_server_->Shutdown(std::chrono::system_clock::now() + std::chrono::seconds(1));
		return;
	}
	grpc_server_->Wait();
}
catch (...) {
	TE_ERR("Exception in grpc thread.");
	request_shutdown();
}

void
TMServer::grpc_start()
{
	grpc_thread_ = std::jthread(std::bind_front(&TMServer::grpc_thread_function, this));
}

void
TMServer::grpc_stop()
{
	grpc_thread_.request_stop();
	if (grpc_server_)
		grpc_server_->Shutdown(std::chrono::system_clock::now() + std::chrono::seconds(1));

	if (grpc_thread_.joinable())
		grpc_thread_.join();
}

net::awaitable<void>
TMServer::http_corouting()
{
	for (;;) {
		try {
			tcp::socket socket = co_await acceptor_.async_accept(net::use_awaitable);
			auto http_session = std::make_shared<ManagerHttpService>(std::move(socket));
			co_spawn(executor_, [http_session]() -> net::awaitable<void> {
				co_await http_session->session();
			}, net::detached);
		}
		catch (const boost::system::system_error& e) {
			if (e.code() == net::error::operation_aborted)
				break;
			TE_ERR("Accept failed: {}", e.what());
		}
		catch (const std::exception& e) {
			TE_ERR("Unrecoverable listener exception: {}", e.what());
			break;
		}
	}
}

void
TMServer::http_start()
{
	auto self = shared_from_this();
	co_spawn(executor_, [self]() -> net::awaitable<void> {
		co_await self->http_corouting();
	}, net::detached);
}

void
TMServer::http_stop()
{
	TE_INF("Submit acceptor closing");
	net::post(executor_, [this] {
		TE_INF("Closing acceptor");
		acceptor_.close();
	});
}

void
TMServer::start()
{
	grpc_start();
	http_start();

	TE_INF("Tempesta Management Server: ready");
}

void
TMServer::stop()
{
	http_stop();
	grpc_stop();
}
