/**
 *	Tempesta Client library
 *
 * SPDX-FileCopyrightText: © 2026 Tempesta Technologies, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include <boost/asio/ip/address.hpp>

#include "client.hh"
#include "log.hh"
#include "../error.hh"
#include "../proto/serialize.hh"
#include "generated/proto_generated.hh"
#include "generated/proto.grpc.fb.h"

std::string get_server_address(const boost::program_options::variables_map &vm)
{
	//Address validation with boost::asio. Throw on error.
	(void) boost::asio::ip::address::from_string(vm["server"].as<std::string>());

	return vm["server"].as<std::string>() + ":"
		+ std::to_string(vm["port"].as<uint16_t>());
}

int
process_response(const grpc::Status& status,
	const flatbuffers::grpc::Message<TempestaRPC::Response>& response) noexcept
{
	if (!status.ok()) {
		std::cerr << "RPC error [" << status.error_code() << "]: "
			  << status.error_message() << std::endl;
		return -1;
	}

	if (!response.data() || response.size() == 0) {
		std::cerr << "Empty response";
		return -1;

	}

	const auto data = response.GetRoot();
	if (data->proto_ver() != ProtoVersion) {
		std::cerr << "Unsupported protocol version in server response: "
			  << data->proto_ver();
		return -1;
	}

	const auto message_status = data->code();
	const auto message = data->message() ? data->message()->str() : "<no message>";

	if (message_status == grpc::StatusCode::OK) {
		std::cout << "Request successfully processed by server." << std::endl;
		return 0;
	}

	std::cerr << "Server returned error (code " << message_status << "): "
		  << message << std::endl;
	return -1;
}

Client::Client(const boost::program_options::variables_map &vm)
{
	const std::string address = get_server_address(vm);
	tcl::dbg << "Connecting to server " << address << "..." << std::endl;
	channel_ = grpc::CreateChannel(address, grpc::InsecureChannelCredentials());
}

int
Client::send_reload()
{
	auto stub = TempestaRPC::ManagerService::NewStub(channel_);
	auto request = build_reload_request();

	grpc::ClientContext context;
	flatbuffers::grpc::Message<TempestaRPC::Response> response;
	auto status = stub->send(&context, request, &response);
	return process_response(status, response);
}

int
Client::send_configuration(const TlProgConf &conf)
{
	auto stub = TempestaRPC::ManagerService::NewStub(channel_);
	auto request = build_set_config_request(conf);

	grpc::ClientContext context;
	flatbuffers::grpc::Message<TempestaRPC::Response> response;
	auto status = stub->send(&context, request, &response);
	return process_response(status, response);
}
