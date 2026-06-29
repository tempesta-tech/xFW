/**
 *	Tempesta Xfw prohibited by rfc and suspecious flags.
 *
 * SPDX-FileCopyrightText: © 2026 Tempesta Technologies, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "tcp_anomaly_flags.hh"

// Returns true if all bits in 'mask' are set in 'value'
constexpr bool
flags_match(uint8_t value, uint8_t mask)
{
	return (value & mask) == mask;
}

/**
 * Forbidden TCP flags according to RFC 9293: monotonically forbidden combinations
 * – SYN+FIN, SYN+RST, and RST+FIN. Any superset of these combinations remains
 * invalid. See RFC 9293 §3.1–3.2 for details.
 */
constexpr bool
is_rfc_prohibited_combination(TcpControlBits c)
{
	return flags_match(c, XFW_BIT_SYN | XFW_BIT_FIN) || 
	       flags_match(c, XFW_BIT_SYN | XFW_BIT_RST) || 
	       flags_match(c, XFW_BIT_RST | XFW_BIT_FIN);
}

/**
 * Suspicious TCP flag combinations (heuristic, not RFC-prohibited).
 *
 * These patterns are commonly associated with port scanning techniques
 * and abnormal traffic behavior, rather than violations of RFC 9293.
 *
 * References:
 * - Nmap Network Scanning (TCP scan techniques: NULL, FIN, XMAS)
 *
 * Heuristics:
 * - FIN only (FIN scan)
 * - NULL flags (no flags set)
 * - FIN+PSH+URG ("XMAS scan")
 * - SYN+PSH / SYN+URG (SYN combined with data/urgent bits)
 * - RST+PSH / RST+URG (RST combined with data/urgent bits)
 */
constexpr bool is_suspicious_combination(TcpControlBits flag)
{
	return (flag == XFW_BIT_FIN) /* FIN scan*/ ||
	       (flag == XFW_BIT_NONE) /*NULL scan*/ ||
	       flags_match(flag, XFW_BIT_FIN | XFW_BIT_PSH | XFW_BIT_URG) /* XMAS*/ ||
	       flags_match(flag, XFW_BIT_SYN | XFW_BIT_PSH) ||
	       flags_match(flag, XFW_BIT_SYN | XFW_BIT_URG) ||
	       flags_match(flag, XFW_BIT_RST | XFW_BIT_PSH) ||
	       flags_match(flag, XFW_BIT_RST | XFW_BIT_URG);
}

template<typename Pred>
constexpr BitSet<TcpControlBits, XFW_BIT_CONTROL_MAX>
make_rules_bitset(Pred check)
{
	BitSet<TcpControlBits, XFW_BIT_CONTROL_MAX> bs{};
	for (size_t i = 0; i < XFW_BIT_CONTROL_MAX; ++i) {
		const TcpControlBits flag = static_cast<TcpControlBits>(i);
		if (check(flag))
			bs.set(flag);
	}
	return bs;
}

const BitSet<TcpControlBits, XFW_BIT_CONTROL_MAX> xfw_prohibited_rules =
	make_rules_bitset(is_rfc_prohibited_combination);
const BitSet<TcpControlBits, XFW_BIT_CONTROL_MAX> xfw_suspicious_rules =
	make_rules_bitset(is_suspicious_combination);
