/**
 *	Tempesta Management GRPC service
 *
 * SPDX-FileCopyrightText: © 2026 Tempesta Technologies, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "grpc_service.hh"
#include "xfw_config_updater.hh"
#include "../lib/error.hh"
#include "../lib/log.hh"
#include "generated/proto.grpc.fb.h"
#include "../lib/proto/serialize.hh"
#include "xfw_update_error.hh"

class Response
{
public:
	int status_code = grpc::StatusCode::OK;
	std::string message = "";

	void set_status(int code, std::string &&msg)
	{
		status_code = code;
		message = std::move(msg);
	}

	void handle_error(const UpdateError &e)
	{
		// When we will be able to extract concrete error from e, we also
		// will be able to make some error mapping inside: for example,
		// return InvalidArgment.
		set_status(grpc::StatusCode::INTERNAL,
			   std::string("Internal server error: ") + e.what());
	}

	void handle_error(const Exception &e)
	{
		// We can't pass details about lines, so we don't use e.what() here.
		set_status(grpc::StatusCode::INTERNAL, "Internal server error.");
	}

	void handle_error(const std::exception &e)
	{
		// This error doesn't contain any valuable information for clients.
		set_status(grpc::StatusCode::INTERNAL, "Internal server error.");
	}
};

::grpc::Status
ManagerGrpcService::send(::grpc::ServerContext* context,
		     const flatbuffers::grpc::Message<TempestaRPC::Request>* req,
		     flatbuffers::grpc::Message<TempestaRPC::Response>* response)
{
	Response rs;
	try {
		const auto data = req->GetRoot();
		if (data->proto_ver() != ProtoVersion)
			throw Except("Unsupported protocol version: {}",
				     data->proto_ver());

		auto records = data->records();
		for (auto i = 0; i < records->size(); i++) {
			auto rec = records->Get(i);
			TE_INF("Record {} Type: {}", i, uint32_t(rec->type()));

			switch (rec->type()) {
			case TempestaRPC::ReqRecType_RRT_TL_OBJ: {
				const TempestaRPC::TLProg* tl_prog =
					rec->data_as_tl_prog();
				TE_INF("TLProg Text Size: {}", tl_prog->text()->size());
				break;
			}
			case TempestaRPC::ReqRecType_RRT_XFW_CFG: {
				const TempestaRPC::XFWCfg* xfw_cfg =
					rec->data_as_xfw_cfg();
				update_xfw_config(*xfw_cfg, xfw_);
				TE_INF("XFWCfg: received.");
				break;
			}
			case TempestaRPC::ReqRecType_RRT_TFW_CFG: {
				const TempestaRPC::TFWCfg* fw_cfg =
					rec->data_as_tfw_cfg();
				TE_INF("FWCfg Text: {}", fw_cfg->text()->c_str());
				break;
			}
			case TempestaRPC::ReqRecType_RRT_STATUS: {
				const TempestaRPC::StatusReq* stat_req =
					rec->data_as_stat_req();
				TE_INF("StatusReq Type: {}",
					static_cast<int>(stat_req->type()));
				break;
			}
			case TempestaRPC::ReqRecType_RRT_TFW_CFG_RLD: {
				TE_INF("Reload request received.");
				// The order is important: we will use the GeoDB
				// during configuration reload.
				xfw_.reload_geodb_if_present();
				xfw_.reload_config_if_present();
				break;
			}
			default:
				rs.set_status(grpc::StatusCode::NOT_FOUND,
					      "Request type has not found");
				break;
			}
		}
	}
	catch (const UpdateError &e) {
		rs.handle_error(e);
		TE_ERR("Request processing finished with error: {}", e.what());
	}
	catch (const Exception &e) {
		rs.handle_error(e);
		TE_ERR("Request processing finished with error: {}", e.what());
	}
	catch (const std::exception &e) {
		rs.handle_error(e);
		TE_ERR("Request processing finished with error: {}", e.what());
	}
	catch(...)
	{
		rs.handle_error({});
		TE_ERR("Request processing finished with unknown error.");
	}

	flatbuffers::grpc::MessageBuilder builder;
	auto resp = TempestaRPC::CreateResponse(builder, ProtoVersion,
		rs.status_code, builder.CreateString(rs.message));
	builder.Finish(resp);
	*response = builder.ReleaseMessage<TempestaRPC::Response>();

	return grpc::Status::OK;
}
