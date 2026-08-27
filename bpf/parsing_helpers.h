/*
 *	Tempesta xFW L2-L4 protocols parsing
 *
 * The L2-L3 part is derived from xdp-tutorial/bpf_uapi/parsing_helpers.h
 *
 * SPDX-FileCopyrightText: © 2026 Tempesta Technologies, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#pragma once

/* This file is included by many subsustems having their own banners. */
#pragma push_macro("BANNER")
#undef BANNER
#define BANNER "parse"
#include "log.h"

#include "compiler.h"

#define IPPROTO_HOPOPTS		0 /* IPv6 hop-by-hop extension */
#define IPPROTO_ROUTING		43 /* IPv6 routing header */
#define IPPROTO_FRAGMENT	44 /* IPv6 fragment extension */
#define IPPROTO_DSTOPTS		60 /* IPv6 destination-options extension */
#define IPPROTO_MH		135 /* IPv6 mobility extension */

/**
 * Supported TCP Options kinds,
 * https://www.iana.org/assignments/tcp-parameters/tcp-parameters.xhtml
 */
#define TCPOPT_EOL		0
#define TCPOPT_NOP		1

#define TCPOPT_MSS		2
#define TCPOPT_MSS_SZ		4

#define TCPOPT_WSCALE		3
#define TCPOPT_WSCALE_SZ	3
/* See linux/net/ipv4/syncookies.c */
#define TCPOPT_WSCALE_MASK	0xf
#define TCPOPT_WSCALE_MAX	14U

#define TCPOPT_SACK_PERM	4
#define TCPOPT_SACK_PERM_SZ	2

#define TCPOPT_TIMESTAMP	8
#define TCPOPT_TIMESTAMP_SZ	10

#define IPV4_MAXLEN		60
#define TCP_MAXLEN		60

#ifndef tcp_flag_word
#define tcp_flag_word(tp)	(((union tcp_word_hdr *)(tp))->words[3])
#endif

/* From linux/include/linux/unaligned.h */
#define __get_unaligned_t(type, p)					\
({									\
	const struct { type x; } __packed *_p = (typeof(_p))(p);	\
	_p->x;								\
})
#define get_unaligned(p)	__get_unaligned_t(typeof(*(p)), (p))

/**
 * The common part of the icmphdr and icmp6hdr.
 */
typedef struct {
	uint8_t		type;
	uint8_t		code;
	__sum16		cksum;
} XfwICMPCommon;

/* Projects may override how many VLAN headers are walked. */
#ifndef VLAN_MAX_DEPTH
#define VLAN_MAX_DEPTH		2
#endif

/* Upper bound for IPv6 extension-header traversal. */
#ifndef IPV6_EXT_MAX_CHAIN
#define IPV6_EXT_MAX_CHAIN	6
#endif

#define VLAN_VID_MASK 0x0fff /* VLAN Identifier */

/*
 * Maximum size of an IPv6 extension header supported by the parser.
 *
 * The Hdr Ext Len field limits an extension header to 2048 bytes.
 * See RFC 8200, Sections 4.3, 4.4 and 4.6.
 */
#define IPV6_EXT_HDR_MAXLEN	((UINT8_MAX + 1) * 8)

#define L3_OFF_MAX						\
	(sizeof(struct ethhdr)					\
	 + VLAN_MAX_DEPTH * sizeof(struct vlan_hdr))

STATIC_ASSERT(L3_OFF_MAX <= UINT8_MAX,
	      "L3 offset does not fit into uint8_t");


/*
 * Maximum supported offset of an L4 header from the beginning of
 * the Ethernet frame.
 *
 * The offset consists of the maximum L3 header offset, the IPv6
 * header, and the maximum supported chain of IPv6 extension headers.
 *
 * The bound is derived from the parser limits VLAN_MAX_DEPTH and
 * IPV6_EXT_MAX_CHAIN and is also used to constrain packet pointer
 * arithmetic for the BPF verifier.
 */
#define L4_OFF_MAX						\
	(L3_OFF_MAX						\
	 + sizeof(struct ipv6hdr)				\
	 + IPV6_EXT_MAX_CHAIN * IPV6_EXT_HDR_MAXLEN)

STATIC_ASSERT(L4_OFF_MAX <= UINT16_MAX,
	      "L4 offset does not fit into uint16_t");

#define CUR_CHECK(cur, len, bad_retval)					\
do {									\
	if (unlikely((cur)->pos + (len) > (cur)->end))			\
		return (bad_retval);					\
} while (0)

/**
 * Advance a cursor for inline (__always_inline) functions).
 * This macro should be used in main context, where all functions
 * manipulating the packet are inlined (except entrypoint).
 *
 * TODO: Many places could be refactored to this macro.
 */
#define CUR_ADVANCE(cur, len, bad_retval)				\
do {									\
	CUR_CHECK((cur), (len), (bad_retval));				\
	(cur)->pos += (len);						\
} while (0)

/**
 * Declare parsing function with simple logic: read struct
 * and shift the packet pointer ahead.
 *
 * Use it carefully with flexible array members structures.
 */
#define SIMPLE_PARSE_FUNC_DECL(FUNC_NAME, STRUCT)			\
static __always_inline struct STRUCT *					\
FUNC_NAME (XfwHdrCursor *c)						\
{									\
	struct STRUCT *ret = c->pos;					\
	CUR_ADVANCE(c, sizeof(struct STRUCT), NULL);			\
	return ret;							\
}

static __always_inline bool
proto_is_vlan(uint16_t pn)
{
	return pn == bpf_htons(ETH_P_8021Q) || pn == bpf_htons(ETH_P_8021AD);
}

/* Parse Ethernet and advance past supported VLAN tags; *ethhdr remains L2. */
static __always_inline int
parse_ethhdr(XfwHdrCursor *cur)
{
	struct ethhdr *eth = cur->pos;
	int hdrsize = sizeof(*eth);
	struct vlan_hdr *vlh;
	uint16_t h_proto;
	int i;

	/* Make sure the fixed Ethernet header is inside packet bounds. */
	CUR_ADVANCE(cur, hdrsize, -EINVAL);

	vlh = cur->pos;
	h_proto = eth->h_proto;

#pragma unroll
	for (i = 0; i < VLAN_MAX_DEPTH; i++) {
		if (!proto_is_vlan(h_proto))
			break;

		if (unlikely((void *)(vlh + 1) > cur->end))
			break;

		h_proto = vlh->h_vlan_encapsulated_proto;

		vlh++;
	}

	cur->pos = vlh;
	return h_proto; /* Network byte order. */
}

static __always_inline int
skip_ip6hdrext(XfwHdrCursor *cur, uint8_t next_hdr_t)
{
	int i = 0;
	for ( ; i < IPV6_EXT_MAX_CHAIN; ++i) {
		struct ipv6_opt_hdr *hdr = cur->pos;

		if (unlikely((void *)(hdr + 1) > cur->end))
			return -EINVAL;

		if (unlikely(next_hdr_t == IPPROTO_FRAGMENT))
			return -EFBIG;

		if (next_hdr_t == IPPROTO_AH) {
			cur->pos = (char *)hdr + (hdr->hdrlen + 2) * 4;
			next_hdr_t = hdr->nexthdr;
			continue;
		}

		if (next_hdr_t != IPPROTO_HOPOPTS && next_hdr_t != IPPROTO_DSTOPTS
		    && next_hdr_t != IPPROTO_ROUTING && next_hdr_t != IPPROTO_MH)
			return next_hdr_t;

		cur->pos = (char *)hdr + (hdr->hdrlen + 1) * 8;
		next_hdr_t = hdr->nexthdr;
	}

	/* Extension-header chain exceeded the parser budget. */
	return -EINVAL;
}

/* Returns L4 protocol, -EFBIG for fragmented IPv6, or -EINVAL on bad input. */
static __always_inline int
parse_ip6hdr(XfwHdrCursor *cur, struct ipv6hdr **ip6hdr)
{
	struct ipv6hdr *ip6h = cur->pos;

	if (unlikely((void *)(ip6h + 1) > cur->end))
		return -EINVAL;

	if (ip6h->version != 6)
		return -EINVAL;

	cur->pos = ip6h + 1;
	*ip6hdr = ip6h;

	XFW_CTX_DBG("IPv6 packet: %pI6 -> %pI6", &ip6h->saddr, &ip6h->daddr);

	return skip_ip6hdrext(cur, ip6h->nexthdr);
}

/* TODO: validate IPv4 header checksum. */
static __always_inline int
parse_iphdr(XfwHdrCursor *cur, struct iphdr **iphdr)
{
	struct iphdr *iph = cur->pos;
	uint32_t hdr_sz;

	if (unlikely((void *)(iph + 1) > cur->end))
		return -EINVAL;

	if (iph->version != 4)
		return -EINVAL;

	hdr_sz = iph->ihl << 2;

	if ((uint64_t)hdr_sz < sizeof(*iph))
		return -EINVAL;

	CUR_ADVANCE(cur, hdr_sz, -EINVAL);
	*iphdr = iph;

	XFW_CTX_DBG("IPv4 packet: %pI4 -> %pI4", &iph->saddr, &iph->daddr);

	return iph->protocol;
}

static __always_inline int
parse_icmp6hdr(XfwHdrCursor *cur, struct icmp6hdr **icmp6hdr)
{
	struct icmp6hdr *icmp6h = cur->pos;

	if (unlikely((void *)(icmp6h + 1) > cur->end))
		return -EINVAL;

	cur->pos = icmp6h + 1;
	*icmp6hdr = icmp6h;

	return icmp6h->icmp6_type;
}

static __always_inline int
parse_icmphdr(XfwHdrCursor *cur, struct icmphdr **icmphdr)
{
	struct icmphdr *icmph = cur->pos;

	if (unlikely((void *)(icmph + 1) > cur->end))
		return -EINVAL;

	cur->pos = icmph + 1;
	*icmphdr = icmph;

	return icmph->type;
}

static __always_inline int
parse_icmphdr_common(XfwHdrCursor *cur, XfwICMPCommon **icmphdr)
{
	XfwICMPCommon *h = cur->pos;

	if (unlikely((void *)(h + 1) > cur->end))
		return -EINVAL;

	cur->pos = h + 1;
	*icmphdr = h;

	return h->type;
}

/* Parse UDP and return payload length. */
static __always_inline int
parse_udphdr(XfwHdrCursor *cur, struct udphdr **udphdr)
{
	struct udphdr *h = cur->pos;

	if (unlikely((void *)(h + 1) > cur->end))
		return -EINVAL;

	cur->pos = h + 1;
	*udphdr = h;

	int len = bpf_ntohs(h->len) - sizeof(struct udphdr);
	if (len < 0)
		return -EINVAL;

	XFW_CTX_DBG("UDP header parsed: sport=%d, dport=%d",
		    bpf_ntohs(h->source), bpf_ntohs(h->dest));
	return len;
}

/* Parse TCP and return the complete TCP header length. */
static __always_inline int
parse_tcphdr(XfwHdrCursor *cur, struct tcphdr **tcphdr)
{
	struct tcphdr *h = cur->pos;

	if (unlikely((void *)(h + 1) > cur->end))
		return -EINVAL;

	int len = h->doff * 4;
	if (unlikely((unsigned long)len < sizeof(*h)))
		return -EINVAL;

	CUR_ADVANCE(cur, len, -EINVAL);
	*tcphdr = h;

	XFW_CTX_DBG("TCP header parsed:%s%s%s%s sport=%d, dport=%d",
		    h->syn ? " SYN" : "", h->ack ? " ACK" : "",
		    h->fin ? " FIN" : "", h->rst ? " RST" : "",
		    bpf_ntohs(h->source), bpf_ntohs(h->dest));

	return len;
}

#undef BANNER
#pragma pop_macro("BANNER")
