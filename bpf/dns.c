/**
 *      Tempesta xFW ingress DNS filter BPF module
 *
 * SPDX-FileCopyrightText: © 2026 Tempesta Technologies, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#define BPF_PROGRAM
#define XFW_DNS
#define BANNER "dns"

#include "vmlinux.h"

#include "ctx.h"
#include "dns.h"

char LICENSE[] SEC("license") = "GPL";

typedef struct XfwDnsCtx {
	XfwMd		*ctx;
	XfwPerCpuStats	*g_stats;
	XfwHdrCursor	hdr_cur;
	XfwIp		ilog_addr;
	uint32_t	pkt_sz;
} XfwDnsCtx;

static __always_inline
int process_label(const XfwHdrCursor *c, uint32_t *offset)
{
	if (*offset > MAX_DNS_NAME)
		return DNS_LABEL_NOTFOUND;

	void* pos = c->pos + *offset;
	if (pos + 1 > c->end)
		return DNS_LABEL_NOTFOUND;
	uint8_t o = *(uint8_t *)pos;

	if ((o & DNS_NAME_COMPRESSION_LABEL) == DNS_NAME_COMPRESSION_LABEL) {
		/* Compression label is last label of dname. */
		*offset += 2;
		return DNS_LABEL_FOUND;
	}
	if (o > 63 || pos + o + 1 > c->end)
		/* Unknown label type */
		return DNS_LABEL_NOTFOUND;

	*offset += o + 1;
	if (!o)
		return DNS_LABEL_FOUND;
	return DNS_LABEL_CONTINUE;
}

/**
 * Iterate over labels: read every label length and skip it.
 */
static __always_inline int
process_dname_global(XfwMd *ctx)
{
	uint32_t offset = 0;
	XfwHdrCursor hdr_cur;
	INIT_CURSOR_FROM_BPF_CONTEXT(ctx, &hdr_cur);

	XfwPacketMetadata *md = (void *)(long)ctx->data_meta;
	/* Limiting is important for verifier */
	if (unlikely((void *)(md + 1) > hdr_cur.pos
		     || md->cur_pos > MAX_DNS_UDP_PACKET))
		return -1; /* internal error */
	hdr_cur.pos += md->cur_pos;

	uint8_t i;
	int r;
	bpf_for (i, 0, MAX_DNS_NAME) {
		r = process_label(&hdr_cur, &offset);
		if (r == DNS_LABEL_FOUND) {
			/* In unsuccessful cases we do not care about cursor anymore */
			md->cur_pos = md->cur_pos + offset;
			return 0;
		}
		if (r == DNS_LABEL_NOTFOUND)
			return -1;
	}
	return -1;
}

static __always_inline int
process_dname(XfwMd *ctx, XfwHdrCursor* hdr_cur)
{
	XfwPacketMetadata *md = (void *)(long)ctx->data_meta;
	if (unlikely((void *)(md + 1) > (void *)(long)ctx->data))
		return -1; /* internal error */

	md->cur_pos = hdr_cur->pos - (void *)(long)ctx->data;
	if (process_dname_global(ctx))
		return -1;

	/* Limiting is important for verifier */
	if (unlikely((void *)(md + 1) > (void *)(long)ctx->data
		     || md->cur_pos > MAX_DNS_UDP_PACKET))
		return -1; /* internal error */
	hdr_cur->pos = (void *)(long)ctx->data + md->cur_pos;

	if (unlikely(hdr_cur->pos >= hdr_cur->end))
		return -1; /* internal error */
	return 0;
}

/* End of parsing utils */

static __always_inline XfwDnsQRec *
parse_single_dns_question(XfwMd *ctx, XfwHdrCursor* hdr_cur, const XfwDnsHdr *dh)
{
	if (process_dname(ctx, hdr_cur))
		return NULL;

	return parse_dns_question_record(hdr_cur);
}

static __always_inline int
process_ingress_dns_query(XfwDnsCtx *dns_ctx, const XfwDnsHdr *dh)
{
	XfwDnsQRec *dq;

	uint16_t hflags = bpf_ntohs(dh->flags);
	uint8_t opcode = (hflags >> 11) & 0xF;
	uint8_t rcode  = hflags & 0xF;

	/* XXX: should we pass another opcodes? */
	if (opcode != OPCODE_QUERY)
		return XFW_CTX_CONTINUE;

	if (rcode != RCODE_OK)
		return XFW_MAKE_CTX_DROP_EXT(dns_ctx, XFW_DNS_QRY_RCODE_NOT_OK,
					     ": %u", rcode);

	/*
	 * Assume EDNS-only message.
	 * XXX: better validation (check opt type etc.)?
	 */
	if (dh->qdcount == 0 && dh->ancount == 0 && dh->nscount == 0 &&
	    bpf_ntohs(dh->arcount) == 1)
		return XFW_CTX_CONTINUE;

	/* We don't support multiple DNS queries - it's quite rare case */
	if (dh->qdcount != bpf_htons(1))
		return XFW_MAKE_CTX_DROP(dns_ctx, XFW_DNS_MULTIPLE_QUESTIONS);

	dq = parse_single_dns_question(dns_ctx->ctx, &dns_ctx->hdr_cur, dh);
	if (dq == NULL)
		return XFW_MAKE_CTX_DROP(dns_ctx, XFW_DNS_BAD_QUESTION);

	if (unlikely(dh->nscount != 0))
		return XFW_MAKE_CTX_DROP_EXT(dns_ctx, XFW_DNS_ANS_OR_AUTHS_IN_QUERY,
					     ": nscount = %u",
					     bpf_ntohs(dh->nscount));

	if (dq->qtype == bpf_ntohs(QTYPE_IXFR)) {
		/* XXX: should we pass it without further validation? */
		return XFW_CTX_CONTINUE;
	}

	/*
	 * Don’t allow any records in the answer section for query packets,
	 * except for IXFR queries.
	 */
	if (unlikely(dh->ancount != 0))
		return XFW_MAKE_CTX_DROP_EXT(dns_ctx, XFW_DNS_ANS_OR_AUTHS_IN_QUERY,
					     ": ancount = %u",
					     bpf_ntohs(dh->ancount));

	/*
	 * Maximum two records allowed (exactly in this order):
	 * EDNS OPT RR, TSIG RR.
	 */
	if (bpf_ntohs(dh->arcount) > 2)
		return XFW_MAKE_CTX_DROP_EXT(dns_ctx, XFW_DNS_QRY_BAD_ARCOUNT,
					     ": %u", bpf_ntohs(dh->arcount));

	return XFW_CTX_CONTINUE;
}

/**
 * Parse DNS record with name.
 */
static __always_inline XfwDnsRR *
parse_full_dns_rr(XfwMd *ctx, XfwHdrCursor* hdr_cur)
{
	if (process_dname(ctx, hdr_cur))
		return NULL;

	XfwDnsRR *dr = parse_dns_rr(hdr_cur);
	if (unlikely(dr == NULL))
		return NULL;

	uint16_t rdata_len = bpf_ntohs(dr->rdata_len);
	if (unlikely(rdata_len > MAX_DNS_UDP_PACKET))
		return NULL;

	CUR_ADVANCE(hdr_cur, rdata_len, NULL);

	return dr;
}

static __always_inline int
process_ingress_dns_response(XfwDnsCtx *dns_ctx, const XfwDnsHdr *dh)
{
	/*
	 * Drop all ingress responses, which we didn't see an
	 * outgoing queries for.
	 */
	if (bpf_map_lookup_elem(&MAP_DNS_EGR_FD_REF, &dh->id) == NULL)
		return XFW_MAKE_CTX_DROP(dns_ctx, XFW_DNS_NOT_ASKED_RESPONSE);


	if (unlikely(dns_ctx->pkt_sz > MAX_DNS_UDP_PACKET))
		return XFW_MAKE_CTX_DROP_EXT(dns_ctx, XFW_DNS_LARGE_RESPONSE,
					     ": %u", dns_ctx->pkt_sz);

	/* We don't support multiple DNS queries - it's quite rare case */
	if (dh->qdcount != bpf_htons(1))
		return XFW_MAKE_CTX_DROP(dns_ctx, XFW_DNS_MULTIPLE_QUESTIONS);

	if (parse_single_dns_question(dns_ctx->ctx, &dns_ctx->hdr_cur, dh) == NULL)
		return XFW_MAKE_CTX_DROP(dns_ctx, XFW_DNS_BAD_QUESTION);

	uint16_t an_count = bpf_ntohs(dh->ancount);

	if (an_count > MAX_ANCOUNT)
		return XFW_MAKE_CTX_DROP_EXT(dns_ctx, XFW_DNS_RESP_ANS_OVERLIMIT,
					     ": %u", an_count);

	uint16_t i;
	bpf_for (i, 0, an_count) {
		XfwDnsRR *dr = parse_full_dns_rr(dns_ctx->ctx, &dns_ctx->hdr_cur);
		if (dr == NULL)
			return XFW_MAKE_CTX_DROP(dns_ctx, XFW_DNS_BAD_RR);

		if (dr->ttl == 0 || bpf_ntohl(dr->ttl) > 604800)
			return XFW_MAKE_CTX_DROP_EXT(dns_ctx, XFW_DNS_ANSWER_ANOMALY,
						     ": %lu", bpf_ntohl(dr->ttl));
	}

	return XFW_CTX_CONTINUE;
}

static __always_inline int
init_dns_ctx(XfwDnsCtx *dns_ctx, XfwMd *ctx, XfwPerCpuStats *global_stats)
{
	__builtin_memset(dns_ctx, 0, sizeof(*dns_ctx));
	dns_ctx->g_stats = global_stats;

	dns_ctx->ctx = ctx;
	INIT_CURSOR_FROM_BPF_CONTEXT(ctx, &dns_ctx->hdr_cur);

	XfwPacketMetadata *md = (void *)(long)ctx->data_meta;
	/* Limiting is important for verifier */
	if (unlikely((void *)(md + 1) > dns_ctx->hdr_cur.pos
		     || md->cur_pos > L3_L4_HDRS_MAXLEN))
		return -1; /* internal error */
	dns_ctx->hdr_cur.pos += md->cur_pos;

	if (unlikely(md->ip_pos > L3_L4_HDRS_MAXLEN))
		return -1;
	void *ip_hdr = (void *)(long)ctx->data + md->ip_pos;
	if (md->is_ipv4) {
		struct iphdr *ipv4 = ip_hdr;
		if (unlikely((void*)(ipv4 + 1) > dns_ctx->hdr_cur.end))
			return -1;
		xfw_ipv4_to_ipv6_mapped(ipv4->saddr, dns_ctx->ilog_addr.addr32);
	}
	else {
		struct ipv6hdr *ipv6 = ip_hdr;
		if (unlikely((void*)(ipv6 + 1) > dns_ctx->hdr_cur.end))
			return -1;
		dns_ctx->ilog_addr.in6 = ipv6->saddr;
	}

	dns_ctx->pkt_sz = XFW_CTX_MD(ctx)->data_end - XFW_CTX_MD(ctx)->data;

	return 0;
}

static __always_inline int
ingress_dns_filter_global(XfwMd *ctx, XfwPerCpuStats *global_stats)
{
	/*
	 * Internal error that can't be reported. However it is impossible due
	 * to check in ingress_dns_filter. This is just check for verifier.
	 */
	if (unlikely(!global_stats))
		return XFW_CTX_CONTINUE;

	XfwDnsCtx dns_ctx;
	if (unlikely(init_dns_ctx(&dns_ctx, ctx, global_stats))) {
		XFW_CTX_DBG("Logic error: can not init dns context.");
		return XFW_CTX_CONTINUE;
	}

	XfwDnsHdr *dh = parse_dnshdr(&dns_ctx.hdr_cur);
	if (unlikely(dh == NULL))
		return XFW_MAKE_CTX_DROP(&dns_ctx, XFW_DNS_BADHDR_INGRESS);

	uint16_t hflags = bpf_ntohs(dh->flags);
	uint8_t qr = (hflags >> 15) & 1;

	if (qr == DNS_QUERY) /* Is query */
		return process_ingress_dns_query(&dns_ctx, dh);

	/* Packet is response */
	return process_ingress_dns_response(&dns_ctx, dh);
}

static __always_inline int
xfw_dns_filter(struct xdp_md *xdp, XfwPerCpuStats *g_stats)
{
	int r;
	size_t pkt_sz = XFW_CTX_DATA_END(xdp) - XFW_CTX_DATA_BGN(xdp);

	XFW_DBG_INIT();

	CHAIN_PASS_ALL(ingress_dns_filter_global, xdp, g_stats);

pass:
	count_traffic_stat(g_stats, pkt_sz,
			   XFW_PASSED_DOWNSTREAM_INGRESS);
	return XFW_CTX_PASS;
}

SEC("xdp")
int xfw_dns(struct xdp_md *xdp)
{
	const unsigned zero = 0;
	XfwPerCpuStats *g_stats;
	XfwFilterCfg *cfg;
	int r;

	g_stats = bpf_map_lookup_elem(&MAP_GLBL_STAT_REF, &zero);
	cfg = bpf_map_lookup_elem(&MAP_CFG_REF, &zero);
	VERIFY_TRUE_OR_RETURN(cfg && g_stats, XFW_CTX_PASS);

	r = xfw_dns_filter(xdp, g_stats);

	return finalize_result(cfg, r);
}
