/**
 *	Tempesta Language compiler routines
 *
 * At the moment this executes bpftrace-tfw, a bpftrace fork tought to speak TL.
 *
 * SPDX-FileCopyrightText: © 2026 Tempesta Technologies, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "../error.hh"

#include "tcl_private.hh"
#include "tempesta_client.hh" // for extern "C" API
#include "log.hh"

int
tcl_tl_compile(TlProgConf *conf)
{
	// TODO
	return 0;
}
