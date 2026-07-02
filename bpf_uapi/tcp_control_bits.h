/**
 *	Tcp control bits
 *
 * SPDX-FileCopyrightText: © 2026 Tempesta Technologies, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#pragma once
#ifdef BPF_PROGRAM
#include "vmlinux.h"
#else
#include <cstdint>
#endif

/*
 * TCP control flags are stored in an 8-bit field inside the TCP header(FIN, SYN,
 * RST, PSH, ACK, URG, ECE, CWR).
 * 
 * Since this field is 8 bits wide, it can represent 2^8 = 256 different flag 
 * combinations, with numeric values ranging from 0 to 255 (0x00 to 0xFF).
 * 
 * We use the raw 8-bit flags value as a direct index into the bitsets.
 * Therefore, the highest possible index is 255.
 * 
 * Example:
 * 	SYN		= 0x02  → bit 2   is used
 * 	ACK		= 0x10  → bit 16  is used
 * 	SYN + ACK		= 0x12  → bit 18  is used
 * 	FIN + PSH + ACK	= 0x19  → bit 25  is used
 * 
 * In other words, the bit index is equal to the numeric value of the TCP flags
 * byte. This allows O(1) lookup with no decoding or branching — just direct 
 * indexing by th->tcp_flags in bpf.
 */	
enum TcpControlBits : uint8_t {
	XFW_BIT_NONE			= 0x00,	// no tcp flags
	XFW_BIT_FIN			= 0x01,	// only bit 0 is set
	XFW_BIT_SYN			= 0x02,	// only bit 1 is set
	//XFW_BIT_SYN+XFW_BIT_FIN	= 0x03,	// two bits are set, so we setup only bit 3.
	XFW_BIT_RST			= 0x04,	// only bit 2 is set
	XFW_BIT_PSH			= 0x08,	// only bit 3 is set
	XFW_BIT_ACK			= 0x10,	// only bit 4 is set
	XFW_BIT_URG			= 0x20,	// only bit 5 is set
	XFW_BIT_ECE			= 0x40,	// only bit 6 is set
	XFW_BIT_CWR			= 0x80,	// only bit 7 is set
	//...
	XFW_BIT_CONTROL_MAX		= 0xFF
};
