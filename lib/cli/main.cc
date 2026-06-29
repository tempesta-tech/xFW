/**
 *	Tempesta utility logic for the client library
 *
 * SPDX-FileCopyrightText: © 2026 Tempesta Technologies, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "../error.hh"

#include "tcl_private.hh"
#include "tempesta_client.hh" // for extern "C" API
#include "log.hh"

namespace tcl {
tcl::DbgStream dbg;

const size_t ERR_BUF_SZ = 1024;
thread_local char err_buf[ERR_BUF_SZ] = {};

}; // tcl

void
tcl_debug(bool enable)
{
	if (enable)
		tcl::dbg.enable();
	else
		tcl::dbg.disable();
}

void
tcl::dump_except(Exception &e)
{
	snprintf(tcl::err_buf, tcl::ERR_BUF_SZ, "%s", e.what());
}

void
tcl::dump_unknown_except()
{
	snprintf(tcl::err_buf, tcl::ERR_BUF_SZ, "unknown error");
}

const char *
tcl_error_str()
{
	return tcl::err_buf;
}

void
tcl_prog_conf_init(TlProgConf *conf)
{
	memset(conf, 0, sizeof(*conf));

	conf->prvt = new TlProgPrvt;
}

void
tcl_free_conf(TlProgConf *conf)
{
	if (!conf)
		return;

	// Destructor from c++ code will clear the rest of the data.
	delete conf;
}
