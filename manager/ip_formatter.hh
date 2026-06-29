/**
 *	Tempesta formatters uint32_t[4] -> ipv6, uint32_t -> ipv4
 *
 * SPDX-FileCopyrightText: © 2026 Tempesta Technologies, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <arpa/inet.h>
#include <string>

inline std::string ipv6_to_string(const uint32_t addr[4])
{
	char str[INET6_ADDRSTRLEN];  // it is enought for all ipv6
	if (inet_ntop(AF_INET6, addr, str, sizeof(str)) != nullptr)
		return std::string(str);

	return "<invalid IPv6>";
}

inline std::string ipv4_to_string(uint32_t addr)
{
	char str[INET_ADDRSTRLEN]; // it is enought for "255.255.255.255"
	if (inet_ntop(AF_INET, &addr, str, sizeof(str)) != nullptr)
		return std::string(str);

	return "<invalid IPv4>";
}
