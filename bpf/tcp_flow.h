/**
 *	Tempesta xFW Tcp Flow engine
 *
 * SPDX-FileCopyrightText: © 2026 Tempesta Technologies, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#pragma once

typedef struct XfwIpv4TcpFlow {
	uint32_t clnt_ip;
	uint32_t srv_ip;
	uint16_t clnt_port;
	uint16_t srv_port;
} XfwIpv4TcpFlow;

typedef struct XfwIpv6TcpFlow {
	uint8_t	clnt_ip[16];
	uint8_t srv_ip[16];
	uint16_t clnt_port;
	uint16_t srv_port;
} XfwIpv6TcpFlow;
