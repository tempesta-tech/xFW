/**
 *	Tempesta xFW TCP SYN Cookies implementation
 *
 * The design reference is "Issuing SYN Cookies in XDP" by P.Penkov et al,
 * https://netdevconf.info/0x14/pub/papers/50/0x14-paper50-talk-paper.pdf
 *
 * SPDX-FileCopyrightText: © 2026 Tempesta Technologies, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#pragma once

#include "vmlinux.h"

#pragma push_macro("BANNER")
#undef BANNER
#define BANNER "syncookie"
#include "log.h"

#include "filter.h"
#include "parsing_helpers.h"

#ifndef BPF_F_CURRENT_NETNS
#define BPF_F_CURRENT_NETNS	-1
#endif

#define XFW_DEFAULT_TTL		64
#define XFW_DEFAULT_WSCALE	7
#define XFW_DEFAULT_WINDOW	(__be16)0xffff /* byte order invariant */

#define TCP_TS_HZ		1000

/*
 * Timestamps used to control SYN cookie generation frequency. These globals are
 * accessed lock-free. In the worst case, cookie generation may temporarily 
 * deviate from the configured rules, but this does not affect correctness.
 *
 * @last_try	- Time of the last SYN cookie attempt
 * @last_gen_ts	- Time of the last SYN cookie successfully generated
 */
typedef struct XfwTcpSynCookieTs {
	uint64_t	last_try_jiff;
	uint64_t	last_gen_jiff;
} XfwTcpSynCookieTs;

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, uint32_t);
	__type(value, XfwTcpSynCookieTs);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, 1);
} MAP_SYNCOOKIES_REF SEC(".maps");

static __always_inline __sum16
csum_fold(uint64_t csum64)
{
	int i;

#pragma unroll
	for (i = 0; i < 4; i++)
		if (csum64 >> 16)
			csum64 = (csum64 & 0xffff) + (csum64 >> 16);

	return (__sum16)~csum64;
}

static __always_inline uint64_t
csum_unfold(__sum16 csum)
{
	return ~csum & 0xffff;
}

static __always_inline void
ipv4_set_ttl_csum(XfwGlobalCtx *ctx, uint64_t *csum64)
{
	__be16 old_w = bpf_htons(((uint16_t)ctx->iph4->ttl << 8) | IPPROTO_TCP);
	__be16 new_w = bpf_htons(((uint16_t)XFW_DEFAULT_TTL << 8) | IPPROTO_TCP);

	*csum64 += ~(__be32)old_w;
	*csum64 += new_w;

	ctx->iph4->ttl = XFW_DEFAULT_TTL;
}

static __always_inline void
ipv4_set_tot_len_csum(XfwGlobalCtx *ctx, uint16_t len, uint64_t *csum64)
{
	*csum64 += ~(__be32)ctx->iph4->tot_len;

	ctx->iph4->tot_len = bpf_htons(len);
	*csum64 += ctx->iph4->tot_len;
}

static __always_inline void
tcp_ipv4_csum_update(XfwGlobalCtx *ctx, uint64_t csum)
{
	/*
	 * Sum addresses stored in network byte order w/o converting to little
	 * endian on x86-64 (reference csum_tcpudp_magic() in
	 * linux/arch/x86/include/asm/checksum_64.h).
	 */
	csum += (__be32)ctx->iph4->saddr;
	csum += (__be32)ctx->iph4->daddr;
	csum += (IPPROTO_TCP + ctx->th->doff * 4) << 8;

	csum = (csum & 0xffffffffUL) + (csum >> 32);
	csum = (csum & 0xffffffffUL) + (csum >> 32);

	ctx->th->check = csum_fold(csum & 0xffffffffUL);
}

static __always_inline void
tcp_ipv6_csum_update(XfwGlobalCtx *ctx, uint64_t csum)
{
	int i;

#pragma unroll
	for (i = 0; i < 4; i++)
		csum += (__be32)ctx->iph6->saddr.in6_u.u6_addr32[i];
#pragma unroll
	for (i = 0; i < 4; i++)
		csum += (__be32)ctx->iph6->daddr.in6_u.u6_addr32[i];

	csum += bpf_htonl(ctx->th->doff * 4);
	csum += bpf_htonl(IPPROTO_TCP);

	csum = (csum & 0xffffffffUL) + (csum >> 32);
	csum = (csum & 0xffffffffUL) + (csum >> 32);

	ctx->th->check = csum_fold(csum & 0xffffffffUL);
}

static __always_inline XfwTcpSynCookieTs *
__tcp_get_tcp_syncookie_ts(void)
{
	const uint32_t zero_idx = 0;

	return bpf_map_lookup_elem(&MAP_SYNCOOKIES_REF, &zero_idx);
}

/**
 * Check if SYN cookie flood mode should be active.
 *
 * Flood mode is active if the time since the last SYN cookie
 * generation is less than flood_timer. In this mode, cookie
 * generation/validation is never skipped.
 */
static __always_inline bool
tcp_syncookies_flood_mode(const XfwGlobalCtx *ctx, XfwTcpSynCookieTs *ts)
{
	if (ctx->cfg->rules.syncookie.flood_timer_jiff
	    >= ctx->ts_jiff - ts->last_gen_jiff)
	{
		XFW_CTX_DBG("Flood mode is on");
		ts->last_try_jiff = ctx->ts_jiff;
		return true;
	}
	return false;
}

/**
 * Check if SYN cookies can be tried in passive mode.
 *
 * Passive mode allows generating/checking cookies at intervals
 * defined by passive_timer. If the interval has not passed,
 * this attempt is skipped.
 *
 * Basically, xFW always starts in passive mode since ts->last_try_jiff
 * is initialized with 0.
 */
static __always_inline bool
tcp_syncookies_passive_mode(const XfwGlobalCtx *ctx, XfwTcpSynCookieTs *ts)
{
	if (ctx->cfg->rules.syncookie.passive_timer_jiff
	    <= ctx->ts_jiff - ts->last_try_jiff)
	{
		XFW_CTX_DBG("Passive mode - try to send a cookie");
		ts->last_try_jiff = ctx->ts_jiff;
		return true;
	}
	return false;
}

static __always_inline uint32_t
tcp_clock_ms(void)
{
	return bpf_ktime_get_ns() / (NSEC_PER_SEC / TCP_TS_HZ);
}

typedef struct {
	__be32			ts;
	uint8_t			wscale;
	uint8_t			sack_perm : 1,
				__reserved : 7;
} XfwTCPOpts;

/*
 * Parse TCP Options, RFC 9293 chapter 3.
 *
 * RFC does not specify what to do with duplicate MSS, Window Scale and SACK
 * Permited options, so for now we just use the last one for simplicity.
 * This can be added to the TCP anomaly filter later.
 */
static __noinline int
tcp_parse_opts(XfwGlobalCtx *ctx, XfwTCPOpts *opts)
{
	const uint8_t *e, *const o = (uint8_t *)ctx->th + sizeof(struct tcphdr);
	const uint8_t *const o_end = (uint8_t *)ctx->th + ctx->th->doff * 4;
	const uint8_t *const d_end = (uint8_t *)ctx->hdr_cur.end;

	/* The maximum lenght of options is 40 bytes (RFC 9293 3.1). */
	VERIFY_TRUE_OR_RETURN(o + 40 >= o_end, -E2BIG);

	uint8_t i;
	bpf_for (i, 0, 40) {
		if (o + i >= o_end || unlikely(o + i >= d_end))
			return 0;

		/* First byte is kind of the option. */
		switch (o[i]) {
		case TCPOPT_EOL:
			/*
			 * If non zero values are present after EOL, then the
			 * segment is anomalous (RFC 9293 3).
			 * Do not read out all trailing zeros at the moment due
			 * to performance reasons - maybe we should add this for
			 * the TCP anomaly filter.
			 */
			return 0;

		case TCPOPT_NOP:
			++i;
			continue;

		case TCPOPT_WSCALE:
			/* RFC 7323 2.2: kind, len=3, 1 byte val */
			e = o + i + TCPOPT_WSCALE_SZ;
			VERIFY_TRUE_OR_RETURN(e <= o_end && e <= d_end, -EINVAL);
			VERIFY_TRUE_OR_RETURN(o[i + 1] == TCPOPT_WSCALE_SZ, -EINVAL);
			opts->wscale = o[i + 2];
			VERIFY_TRUE_OR_RETURN(o[i] <= TCPOPT_WSCALE_MAX, -EINVAL);
			i += TCPOPT_WSCALE_SZ;
			continue;

		case TCPOPT_SACK_PERM:
			/* RFC 2018 2: kind, len=2 */
			e = o + i + TCPOPT_SACK_PERM_SZ;
			VERIFY_TRUE_OR_RETURN(e <= o_end && e <= d_end, -EINVAL);
			VERIFY_TRUE_OR_RETURN(o[i + 1] == TCPOPT_SACK_PERM_SZ,
					      -EINVAL);
			opts->sack_perm = 1;
			i += TCPOPT_SACK_PERM_SZ;
			continue;

		case TCPOPT_TIMESTAMP:
			/*
			 * RFC 7323 3.2:
			 * kind, len=10, TS val 4 bytes, TS echo (tsecr) 4 bytes
			 */
			e = o + i + TCPOPT_TIMESTAMP_SZ;
			VERIFY_TRUE_OR_RETURN(e <= o_end && e <= d_end, -EINVAL);
			VERIFY_TRUE_OR_RETURN(o[i + 1] == TCPOPT_TIMESTAMP_SZ, -EINVAL);
			/* RFC 7323 4.3: ignore duplicate timestamp options. */
			if (likely(!opts->ts))
				opts->ts = get_unaligned((__be32 *)(o + i + 2));
			i += TCPOPT_TIMESTAMP_SZ;
			continue;

		default:
			/*
			 * Generic processing of other options.
			 * Only NOP and EOL have 1 byte lengh, all others must
			 * have length field (RFC 9293 3.1).
			 */
			e = o + i + 2;
			VERIFY_TRUE_OR_RETURN(e <= o_end && e <= d_end, -EINVAL);
			uint8_t olen = o[i + 1];
			VERIFY_TRUE_OR_RETURN(olen >= 2, -EINVAL);
			e = o + i + olen;
			VERIFY_TRUE_OR_RETURN(e <= o_end && e <= d_end, -EINVAL);
			i += olen;
			continue;
		}
	}

	return 0;
}

/**
 * Generate a timestamp-based SYN cookie for a TCP SYN packet.
 * The cookie encodes window scale, SACK, and ECN flags from client options.
 * Returns true if cookie was successfully generated.
 *
 * See cookie_init_timestamp() in linux/net/ipv4/syncookies.c :
 *
 * MSB                               LSB
 * | 31 ...   6 |  5  |  4   | 3 2 1 0 |
 * |  Timestamp | ECN | SACK | WScale  |
 */
static __always_inline __be32
tcp_syncookies_make_cookie_ts(struct tcphdr *th, XfwTCPOpts *opts)
{
#define TS_OPT_SACK_SHIFT	4
#define TS_OPT_ECN_SHIFT	5
#define TSBITS			6

	uint32_t co = opts->wscale
		      ? opts->wscale & TCPOPT_WSCALE_MASK
		      : TCPOPT_WSCALE_MASK;

	co |= (!!opts->sack_perm) << 4;

	co |= (!!th->ece) << TS_OPT_ECN_SHIFT;

	uint32_t ts_now = tcp_clock_ms();
	uint32_t ts = ((ts_now >> TSBITS) << TSBITS) | co;
	if (ts > ts_now)
		ts -= (1UL << TSBITS);

	return bpf_htonl(ts);
#undef TS_OPT_ECN_SHIFT
#undef TS_OPT_SACK_SHIFT
}

/**
 * Build TCP options for SYN-ACK packet.
 *
 * We MAY send only (in prioirity order): MSS, Window Scale, SACK Permitted and
 * Timestamp options. We write the options only if sender did send us any TCP
 * options, i.e. we have enough space in the packet. Option-less TCP
 * communications are allowed, but not normal - do not spend cycles in
 * bpf_xdp_adjust_tail() for suspicious TCP SYNs.
 *
 * @return the total length in double words of written options.
 */
static __always_inline int
tcp_syncookies_write_opts(XfwGlobalCtx *ctx, uint16_t mss, XfwTCPOpts *opts)
{
#define OPTS_DWORD(a, b, c, d)						\
	bpf_htonl(((uint32_t)(a) << 24)	| ((uint32_t)(b) << 16)		\
		  | ((uint32_t)(c) << 8) | (uint32_t)(d))

	__be32 *o = (__be32 *)(ctx->th + 1);
	const __be32 *const d_end = XFW_CTX_DATA_END(ctx->ctx);

	if (o + 1 > d_end)
		return 0;
	/*
	 * MSS (the most important): kind, len=4, 2 bytes val.
	 * Don't use OPTS_DWORD to write 2-byte value as is.
	 */
	*o = bpf_htonl(((uint32_t)TCPOPT_MSS << 24)
		       | ((uint32_t)TCPOPT_MSS_SZ << 16) | (uint32_t)mss);

	if (++o + 1 > d_end)
		return 1;
	/* Window Scale: NOP, kind, len=3, 1 byte val. */
	*o = OPTS_DWORD(TCPOPT_NOP, TCPOPT_WSCALE, TCPOPT_WSCALE_SZ,
			XFW_DEFAULT_WSCALE);

	if (++o + 1 > d_end)
		return 2;
	if (!opts->ts || o + 3 > d_end) {
		/*
		 * Write only SACK Permitted if we shouldn't or can't send TS:
		 *   kind, len=2, NOP, EOL.
		 */
		if (opts->sack_perm) {
			*o = OPTS_DWORD(TCPOPT_SACK_PERM, TCPOPT_SACK_PERM_SZ,
					TCPOPT_NOP, TCPOPT_EOL);
			return 3;
		}
		return 2;
	}

	/*
	 * Do not write the option if client sent us zero timestamp.
	 *
	 * Pack SACK Petmitted OR NOP with Timestamp:
	 *   <kind, len=2 | NOP>, kind, len=10
	 *   timestamp
	 *   TS Echo Reply
	 */
	if (opts->sack_perm) {
		*o = OPTS_DWORD(TCPOPT_SACK_PERM, TCPOPT_SACK_PERM_SZ,
				TCPOPT_TIMESTAMP, TCPOPT_TIMESTAMP_SZ);
	} else {
		*o = OPTS_DWORD(TCPOPT_NOP, TCPOPT_NOP,
				TCPOPT_TIMESTAMP, TCPOPT_TIMESTAMP_SZ);
	}
	++o;

	*o++ = tcp_syncookies_make_cookie_ts(ctx->th, opts);
	*o = opts->ts;

	return 5;
#undef OPTS_DWORD
}

/**
 * Construct a SYN-ACK packet using SYN cookie.
 *
 * - Generates timestamp cookie if options provided
 * - Builds TCP options
 * - Adjusts TCP header doff, window, and checksum
 * - Swaps IP/ethernet addresses
 * - Adjusts tail for added options
 */
static __always_inline int
tcp_syncookies_make_synack(XfwGlobalCtx *ctx, uint32_t cookie, uint16_t mss,
			   XfwTCPOpts *opts)
{
	/* Minimal TCP header size = 5 in 4-byte double words. */
	uint8_t new_doff = 5 + tcp_syncookies_write_opts(ctx, mss, opts);
	int16_t d_len = (new_doff - ctx->th->doff) * 4;
	uint16_t tcplen = new_doff * 4;

	const void *const d_end = ctx->hdr_cur.end;
	VERIFY_TRUE_OR_RETURN((void *)ctx->th + tcplen <= d_end, -EFBIG);

	ctx->th->doff = new_doff;

	ctx->th->window = XFW_DEFAULT_WINDOW;
	ctx->th->check = 0;
	tcp_flag_word(ctx->th) |= TCP_FLAG_ACK;
	ctx->th->ack_seq = bpf_htonl(bpf_ntohl(ctx->th->seq) + 1);
	ctx->th->seq = bpf_htonl(cookie);

	/*
	 * TODO #224,#544: review the checksum computation -
	 * this diff from zero looks strange.
	 * Update xfw/t/unit/{csum,main}.cc
	 *
	 * See linux/tools/testing/selftests/bpf/progs/xdp_synproxy_kern.c
	 */
	int64_t csum = bpf_csum_diff(0, 0, (void *)ctx->th, tcplen, 0);
	VERIFY_TRUE_OR_RETURN(csum >= 0, csum);

	/*
	 * Swapping fields of size >= 16 bits doesn't affect the checksum,
	 * because the checksum is calculated over 16-bit words.
	 */
	SWAP(ctx->th->source, ctx->th->dest);

	struct ethhdr tmp_eth = *ctx->eth;
	memcpy(ctx->eth->h_dest, tmp_eth.h_source, sizeof(tmp_eth.h_source));
	memcpy(ctx->eth->h_source, tmp_eth.h_dest, sizeof(tmp_eth.h_dest));

	if (ctx->iph4) {
		uint64_t ip_csum = csum_unfold(ctx->iph4->check);
		uint16_t ip_len = bpf_ntohs(ctx->iph4->tot_len) + d_len;
		ipv4_set_ttl_csum(ctx, &ip_csum);
		ipv4_set_tot_len_csum(ctx, ip_len, &ip_csum);
		ctx->iph4->check = csum_fold(ip_csum);

		SWAP(ctx->iph4->saddr, ctx->iph4->daddr);
		/* TODO #224: don't clear IP options for now - is this OK? */

		tcp_ipv4_csum_update(ctx, csum);
	}
	else if (ctx->iph6) {
		ctx->iph6->hop_limit = XFW_DEFAULT_TTL;
		uint16_t payload_len = bpf_ntohs(ctx->iph6->payload_len);
		ctx->iph6->payload_len = bpf_htons(payload_len + d_len);

		SWAP(ctx->iph6->saddr, ctx->iph6->daddr);

		tcp_ipv6_csum_update(ctx, csum);
	}

	return 0;
}

/**
 * Lookup a listening TCP socket using the parsed packet headers.
 *
 * This function constructs a `bpf_sock_tuple` from the IP/TCP headers in `ctx`
 * and performs a socket lookup via `bpf_skc_lookup_tcp()`.
 *
 * Notes:
 * - IPv4 and IPv6 are supported; tuple size is adjusted accordingly.
 * - This operation is relatively expensive and should be minimized where possible.
 * - Returns a pointer to a `bpf_sock` if found, or NULL if no matching socket exists.
 */
static __always_inline struct bpf_sock *
tcp_sk_listen_lookup(const XfwGlobalCtx *ctx)
{
	struct bpf_sock_tuple t;
	size_t tlen;

	if (ctx->iph4) {
		tlen = sizeof(t.ipv4);
		t.ipv4.sport = ctx->th->source;
		t.ipv4.dport = ctx->th->dest;
		t.ipv4.saddr = ctx->iph4->saddr;
		t.ipv4.daddr = ctx->iph4->daddr;
	}
	else if (ctx->iph6) {
		tlen = sizeof(t.ipv6);
		t.ipv6.sport = ctx->th->source;
		t.ipv6.dport = ctx->th->dest;
		xfw_ipv6_addr_cpy(t.ipv6.saddr, &ctx->iph6->saddr);
		xfw_ipv6_addr_cpy(t.ipv6.daddr, &ctx->iph6->daddr);
	}
	else {
		return NULL;
	}

	return bpf_sk_lookup_tcp(ctx->ctx, &t, tlen, BPF_F_CURRENT_NETNS, 0);
}

/**
 * Handle incoming SYN packets (without ACK) using SYN cookies.
 * 
 * This logic intentionally diverges slightly from strict TCP behavior under
 * flood conditions to prioritize protection. Out-of-order or malformed packets
 * are tolerated where possible.
 */
static __always_inline int
tcp_syncookies_syn_filter(XfwGlobalCtx *ctx)
{
	XfwTcpSynCookieTs *ts = __tcp_get_tcp_syncookie_ts();
	XFW_ASSERT(ts);

	if (!tcp_syncookies_flood_mode(ctx, ts)
	    && !tcp_syncookies_passive_mode(ctx, ts))
		return XFW_CTX_CONTINUE;

	const bool is_ip4 = ctx->iph4 != NULL;
	void *iph = is_ip4 ? (void *)ctx->iph4 : (void *)ctx->iph6;
	uint32_t iph_len = is_ip4 ? sizeof(struct iphdr) : sizeof(struct ipv6hdr);
	XFW_ASSERT(iph && iph + iph_len <= ctx->hdr_cur.end);

	/*
	 * The kernel syncookie helper expects a minimal SYN header. Temporarily
	 * hide TCP options from the helper and then restore/encode the options
	 * we can safely preserve in the generated SYN-ACK.
	 *
	 * In flood mode, parse failures mean option preservation is skipped.
	 * Passive mode keeps using the parsed option data. Make the emitted
	 * option profile configurable later.
	 */
	uint16_t old_doff = ctx->th->doff;
	ctx->th->doff = (sizeof(struct tcphdr) / 4) & 0xF;
	struct bpf_sock *sk = tcp_sk_listen_lookup(ctx);
	if (unlikely(!sk)) {
		/* Treat a SYN for a non-listening or absent socket as flooding. */
		ts->last_gen_jiff = ctx->ts_jiff;
		return XFW_MAKE_CTX_DROP(ctx, XFW_SYNCOOKIE_FAILED,
					 "No listening socket");
	}

	int64_t seq_mss = bpf_tcp_gen_syncookie(sk, iph, iph_len, ctx->th,
						sizeof(struct tcphdr));
	bpf_sk_release(sk);
	ctx->th->doff = old_doff & 0xF;

	/*
	 * The kernel tcp_get_syncookie_mss() may decide to not to
	 * generate a cookie, e.g. if there is no SYN flood, and
	 * -ENOENT is returned.
	 */
	if (unlikely(seq_mss == -ENOENT))
		return XFW_CTX_CONTINUE;

	/* Treat all, even invalid SYNs, as flooding. */
	ts->last_gen_jiff = ctx->ts_jiff;

	if (unlikely(seq_mss < 0)) {
		XFW_CTX_DBG("Cannot generate syncookie, %d", seq_mss);
		return XFW_MAKE_CTX_DROP(ctx, XFW_SYNCOOKIE_FAILED, "bad MSS");
	}

	XfwTCPOpts opts = { 0 };
	long r = tcp_parse_opts(ctx, &opts);
	if (unlikely(r)) {
		XFW_CTX_DBG("Cannot parse TCP options, %d", r);
		return XFW_MAKE_CTX_DROP(ctx, XFW_SYNCOOKIE_FAILED,
					 "bad TCP options in SYN");
	}

	r = tcp_syncookies_make_synack(ctx, (uint32_t)seq_mss,
				       (uint16_t)(seq_mss >> 32), &opts);
	if (unlikely(r))
		return XFW_MAKE_CTX_DROP_EXT(ctx, XFW_SYNCOOKIE_FAILED,
					     "Cannot generate SYN-ACK, %d", r);

	return MAKE_XDP_TX(ctx, XFW_SYNCOOKIE_GENERATED);
}

/**
 * Handle ACK packets related to SYN cookies only.
 *
 * Returns:
 *  - XFW_CTX_CONTINUE if packet is valid
 *  - DROP if SYN cookie is invalid or host socket not found
 */
static __always_inline int
tcp_syncookies_ack_filter(const XfwGlobalCtx *ctx)
{
	/* Lookup socket to validate ACK against SYN cookie */
	struct bpf_sock *sk = tcp_sk_listen_lookup(ctx);
	if (!sk)
		return XFW_MAKE_CTX_DROP(ctx, XFW_SYNCOOKIE_FAILED,
					 "No host socket");

	const bool in_listen_state = sk->state == BPF_TCP_LISTEN;
	bpf_sk_release(sk);

	/* Only handle ACKs destined to listening sockets */
	if (!in_listen_state)
		return XFW_CTX_CONTINUE;

	/*
	 * Raw SYN cookie verification (IPv4/IPv6).
	 *
	 * We need to reimplement bpf_tcp_check_syncookie due to inconsistencies
	 * in kernel error codes (see rejected patch and discussion:
	 * https://lore.kernel.org/bpf/20211019144655.34831975maximmi@nvidia.com/).
	 * Most of the original checks can be reproduced, but
	 * tcp_synq_no_recent_overflow() cannot, so it is intentionally skipped
	 * here.
	 */
	if (ctx->iph4) {
		int r = bpf_tcp_raw_check_syncookie_ipv4(ctx->iph4, ctx->th);
		if (r < 0)
			return XFW_MAKE_CTX_DROP_EXT(ctx, XFW_SYNCOOKIE_FAILED,
				"IPv4 ACK with invalid cookie, retcode=%d.", r);
	} else if (ctx->iph6) {
		int r = bpf_tcp_raw_check_syncookie_ipv6(ctx->iph6, ctx->th);
		if (r < 0)
			return XFW_MAKE_CTX_DROP_EXT(ctx, XFW_SYNCOOKIE_FAILED,
				"IPv6 ACK with invalid cookie, retcode=%d.", r);
	}

	return XFW_CTX_CONTINUE;
}

#undef BANNER
#pragma pop_macro("BANNER")
