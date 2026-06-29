/**
 *	FlatBuffers-based serialization API for gRPC communication
 *
 * SPDX-FileCopyrightText: © 2026 Tempesta Technologies, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#pragma once

#include "../cli/tempesta_client.hh"
#include "generated/proto.grpc.fb.h"

const uint32_t ProtoVersion = 0;

flatbuffers::grpc::Message<TempestaRPC::Request>
build_set_config_request(const TlProgConf &conf);

flatbuffers::grpc::Message<TempestaRPC::Request>
build_reload_request();
