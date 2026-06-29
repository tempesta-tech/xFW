/**
 *	Tempesta Xfw configuration updater
 *
 * SPDX-FileCopyrightText: © 2026 Tempesta Technologies, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "generated/proto_generated.hh"
#include "xfw/xfw.hh"

void
update_xfw_config(const TempestaRPC::XFWCfg &cfg, Xfw &xfw);