/**
 *	Tempesta Management GRPC service
 *
 * SPDX-FileCopyrightText: © 2026 Tempesta Technologies, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "xfw/xfw.hh"
#include "generated/proto.grpc.fb.h"

class ManagerGrpcService final: public TempestaRPC::ManagerService::Service
{
public:
	ManagerGrpcService(Xfw &xfw): xfw_(xfw)
	{}

	virtual ::grpc::Status send(::grpc::ServerContext* context,
		const flatbuffers::grpc::Message<TempestaRPC::Request>* req,
		flatbuffers::grpc::Message<TempestaRPC::Response>* response) override;

private:
	Xfw&				xfw_;
};
