/**
 *      Tempesta xFW DNS Filter BPF module
 *
 * SPDX-FileCopyrightText: © 2026 Tempesta Technologies, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#pragma once

#include "vmlinux.h"

#include "../bpf_uapi/stats.h"

#include "log.h"
#include "filter.h"
#include "ctx.h"
#include "parsing_helpers.h"

#define DNS_PORT			53

/* RFC1035 */
#define OPCODE_QUERY			0 /* a standard query (QUERY) */
#define RCODE_OK			0 /* No error condition */
#define QTYPE_IXFR			251

#define DNS_NAME_COMPRESSION_LABEL	0xC0

/* RFC 1035 */
#define MAX_DNS_NAME			255

/* Limit on answers count for verificator */
#define MAX_ANCOUNT			100

/* IPv4/IPv6 max len is 60, UDP len is 8*/
#define L3_L4_HDRS_MAXLEN		68

/* Necessary for verifier */
/* RFC 6891 (6.2.5)*/
#define MAX_DNS_UDP_PACKET		4096

#define DNS_QUERY			0
#define DNS_RESPONSE			1

/**
 * @qdcount	- Question count
 * @ancount	- Answer count
 * @nscount	- Authority count
 * @arcount	- Additional count
 */
typedef struct XfwDnsHdr {
	__be16		id;
	uint16_t	flags;
	__be16		qdcount;
	__be16		ancount;
	__be16		nscount;
	__be16		arcount;
} __attribute__((packed)) XfwDnsHdr;

/* DNS query record without name (because name length is variadic) */
typedef struct XfwDnsQRec {
	__be16		qtype;
	__be16		qclass;
} __attribute__((packed)) XfwDnsQRec;

/* DNS record without name (because name length is variadic) */
typedef struct XfwDnsRR {
	__be16		type;
	__be16		cls;
	__be32		ttl;
	__be16		rdata_len;
} __attribute__((packed)) XfwDnsRR;

/**
 * Packet metadata.
 * We fill it to pass some info to global functions or tail calls.
 *
 * @cur_pos	- Current position of cursor (offset)
 * @ip_pos	- Offset of ip hdr in packet
 * @is_ipv4	- 1 if L3 proto is IPv4, else 0 (in dns filter only IPv6)
 * @unused	- Currently unused field to match size of metadata
 */
typedef struct {
	uint16_t	cur_pos;
	uint16_t	ip_pos;
	uint16_t	is_ipv4;
	uint16_t	unused;
} __attribute__((packed)) XfwPacketMetadata;

STATIC_ASSERT(sizeof(XfwPacketMetadata) <= 32,
	      "Packet metadata must be less than 32 bytes");
STATIC_ASSERT(sizeof(XfwPacketMetadata) % 4 == 0,
	      "XDP metadata size must be 4-byte aligned");

SIMPLE_PARSE_FUNC_DECL(parse_dnshdr, XfwDnsHdr);
SIMPLE_PARSE_FUNC_DECL(parse_dns_question_record, XfwDnsQRec);
SIMPLE_PARSE_FUNC_DECL(parse_dns_rr, XfwDnsRR);

#define DNS_LABEL_CONTINUE		1
#define DNS_LABEL_FOUND			0
#define DNS_LABEL_NOTFOUND		(-1)

static __always_inline uint8_t
dns_get_qr(uint16_t hflags)
{
	return (uint8_t)((hflags >> 15) & 1);
}

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, __be16); /* DNS TX ID. Could be improved to
			      * TX ID + 5-tuple hash to reduce collisions. */
	__type(value, uint8_t);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, XFW_MAX_DNS_QRS_TRACKER_BUCKETS);
} MAP_DNS_EGR_FD_REF SEC(".maps");

static __always_inline bool
is_dns_filter_enabled(const XfwGlobalCtx *ctx)
{
	return ctx->cfg->rules.dns.enabled;
}

static __always_inline bool
is_dns_packet(const XfwGlobalCtx *ctx)
{
	if (unlikely(!ctx->uh))
		return false;

	if (ctx->uh->dest != bpf_htons(DNS_PORT) &&
	    ctx->uh->source != bpf_htons(DNS_PORT))
		return false;

	return true;
}

static __always_inline bool
dns_init_metadata(XfwGlobalCtx *ctx)
{
	XfwMd *xdp_ctx = ctx->ctx;
	uint16_t is_ipv4, ip_pos;

	if (ctx->ipver == bpf_ntohs(ETH_P_IP)) {
		is_ipv4 = 1;
		ip_pos = (void*)ctx->iph4 - XFW_CTX_DATA_BGN(ctx->ctx);
	}
	else if (ctx->ipver == bpf_ntohs(ETH_P_IPV6)) {
		is_ipv4 = 0;
		ip_pos = (void*)ctx->iph6 - XFW_CTX_DATA_BGN(ctx->ctx);
	}
	else {
		return false;
	}

	XfwPacketMetadata *md = (void *)(long)xdp_ctx->data_meta;
	if (unlikely((void *)(md + 1) > (void *)(long)xdp_ctx->data)) {
		XFW_CTX_DBG("Logic error: created meta data is incorrect.");
		return false;
	}

	md->cur_pos =  ctx->hdr_cur.pos - XFW_CTX_DATA_BGN(xdp_ctx);
	md->ip_pos = ip_pos;
	md->is_ipv4 = is_ipv4;

	return true;
}

static __always_inline void
egress_dns_filter(XfwGlobalCtx *ctx)
{
	if (unlikely(!ctx->cfg->rules.dns.enabled))
		return;

	if (ctx->uh->dest != bpf_htons(DNS_PORT) &&
		ctx->uh->source != bpf_htons(DNS_PORT))
		return;

	XfwDnsHdr *dh = parse_dnshdr(&ctx->hdr_cur);
	if (unlikely(dh == NULL))
		return;

	uint16_t hflags = bpf_ntohs(dh->flags);
	uint8_t qr = dns_get_qr(hflags);

	if (qr == DNS_QUERY) { /* Is query */
		uint8_t zero = 0;
		bpf_map_update_elem(&MAP_DNS_EGR_FD_REF, &dh->id, &zero, BPF_NOEXIST);
		return;
	}

	/* Packet is a response, nothing to do for now */
}
