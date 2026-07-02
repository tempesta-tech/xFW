/**
 *	Tempesta xFW network protocols constants
 *
 * Mostly copied from linux/include/linux/if_ether.h.
 *
 * SPDX-FileCopyrightText: © 2026 Tempesta Technologies, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#pragma once

#ifdef BPF_PROGRAM
#include "vmlinux.h"
#else
#include <arpa/inet.h>
#endif

#define ETH_P_8021AD		0x88A8 /* Provider VLAN tag */
#define ETH_P_8021Q		0x8100 /* Customer VLAN tag */
#define ETH_P_IP		0x0800 /* IPv4 EtherType */
#define ETH_P_IPV6		0x86DD /* IPv6 over bluebook */
#define ETH_P_ARP		0x0806 /* ARP EtherType */

#ifndef IPPROTO_ICMP
#define IPPROTO_ICMP		1
#endif
#ifndef IPPROTO_ICMPV6
#define IPPROTO_ICMPV6		58
#endif
#ifndef IPPROTO_TCP
#define IPPROTO_TCP		6
#endif
#ifndef IPPROTO_UDP
#define IPPROTO_UDP		17
#endif
#ifndef IPPROTO_GRE
#define IPPROTO_GRE		47
#endif
#ifndef ETH_P_IP
#define ETH_P_IP		0x0800 /* IPv4 header type */
#endif
#ifndef ETH_P_IPV6
#define ETH_P_IPV6		0x86DD /* IPv6 header type */
#endif

