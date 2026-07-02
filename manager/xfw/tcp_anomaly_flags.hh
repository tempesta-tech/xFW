/**
 *	Tempesta Xfw prohibited by rfc and suspecious flags.
 *
 * SPDX-FileCopyrightText: © 2026 Tempesta Technologies, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#pragma once

#include "../../bpf_uapi/tcp_control_bits.h"
#include "../../lib/bitset.hh"

extern const BitSet<TcpControlBits, XFW_BIT_CONTROL_MAX> xfw_prohibited_rules;
extern const BitSet<TcpControlBits, XFW_BIT_CONTROL_MAX> xfw_suspicious_rules;
