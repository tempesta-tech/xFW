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
ipv4_set_ttl_csum(struct iphdr *iph4, uint64_t *csum64)
{
	__be16 old_w = bpf_htons(((uint16_t)iph4->ttl << 8) |
				 XFW_L4_PROTO_TCP);
	__be16 new_w = bpf_htons(((uint16_t)XFW_DEFAULT_TTL << 8) |
				 XFW_L4_PROTO_TCP);

	*csum64 += ~(__be32)old_w;
	*csum64 += new_w;

	iph4->ttl = XFW_DEFAULT_TTL;
}

static __always_inline void
ipv4_set_tot_len_csum(struct iphdr *iph4, uint16_t len, uint64_t *csum64)
{
	*csum64 += ~(__be32)iph4->tot_len;
	iph4->tot_len = bpf_htons(len);
	*csum64 += iph4->tot_len;
}

static __always_inline void
tcp_ipv4_csum_update(struct iphdr *iph4, struct tcphdr *th, uint64_t csum)
{
	/*
	 * Sum addresses stored in network byte order w/o converting to little
	 * endian on x86-64 (reference csum_tcpudp_magic() in
	 * linux/arch/x86/include/asm/checksum_64.h).
	 */
	csum += (__be32)iph4->saddr;
	csum += (__be32)iph4->daddr;
	csum += (XFW_L4_PROTO_TCP + th->doff * 4) << 8;

	csum = (csum & 0xffffffffUL) + (csum >> 32);
	csum = (csum & 0xffffffffUL) + (csum >> 32);

	th->check = csum_fold(csum & 0xffffffffUL);
}

static __always_inline void
tcp_ipv6_csum_update(struct ipv6hdr *iph6, struct tcphdr *th, uint64_t csum)
{
	int i;

#pragma unroll
	for (i = 0; i < 4; i++)
		csum += (__be32)iph6->saddr.in6_u.u6_addr32[i];
#pragma unroll
	for (i = 0; i < 4; i++)
		csum += (__be32)iph6->daddr.in6_u.u6_addr32[i];

	csum += bpf_htonl(th->doff * 4);
	csum += bpf_htonl(XFW_L4_PROTO_TCP);

	csum = (csum & 0xffffffffUL) + (csum >> 32);
	csum = (csum & 0xffffffffUL) + (csum >> 32);

	th->check = csum_fold(csum & 0xffffffffUL);
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
 * The maximum length of options is 40 bytes (RFC 9293 3.1).
 *
 * A practical limit for TCP options would be 30: 10 x <NOP, NOP, 2 byte option>.
 * However, there are options-stripping and TCP normalizing middleboxes that
 * typically just rewrite options with NOPs instead of moving the options.
 */
#define TCP_OPTS_MAX		40
/*
 * The parsing buffer is a bit larger than the options area, so the verifier
 * can prove in-bounds access for all option value reads knowing only that
 * the option offset is less than TCP_OPTS_MAX: the largest access is a 4-byte
 * timestamp value read at offset 39 (kind) + 2 (option header) = 45. Use 48
 * as the smallest 8-byte alignment.
 */
#define TCP_OPTS_BUF_SZ		48

typedef struct {
	uint8_t			buf[TCP_OPTS_BUF_SZ];
	XfwTCPOpts		*opts;
	const uint64_t		opt_len;
	uint64_t		off;
	int			err;
} XfwTCPOptCtx;

/**
 * Parse a single TCP option from the stack buffer @c->buf.
 *
 * All the offset arithmetic is 64-bit: with 32-bit types clang zero-extends
 * values with the '<<= 32; >>= 32' shift pairs in separate registers, so the
 * verifier refines the bounds of the zero-extended copy, but sees the
 * original register, used in the buffer access, as unbounded.
 *
 * @return 0 to continue the loop, 1 to stop it (@c->err holds the result).
 */
static long
tcp_parse_one_opt(uint64_t index, void *cb_data)
{
	XfwTCPOptCtx *c = cb_data;
	const uint64_t off = c->off, opt_len = c->opt_len;

	/*
	 * This is the normal loop termination condition.
	 * We use 1 extra step in bpf_loop() exactly to call the callback last
	 * time and return with zero error code on reaching end of data.
	 */
	if (off >= opt_len) {
		c->err = 0;
		return 1;
	}

	/* The first byte is the kind of the option. */
	const uint8_t kind = c->buf[off];

	if (kind == TCPOPT_EOL) {
		/*
		 * If non zero values are present after EOL, then the
		 * segment is anomalous (RFC 9293 3).
		 * Do not read out all trailing zeros at the moment due
		 * to performance reasons - maybe we should add this for
		 * the TCP anomaly filter.
		 */
		c->err = 0;
		return 1;
	}
	if (kind == TCPOPT_NOP) {
		c->off = off + 1;
		return 0;
	}

	/*
	 * All other options carry the length in the second byte (RFC 9293 3.1)
	 * and must fit into the options area.
	 */
	if (unlikely(off + 2 > opt_len))
		goto bad_opt;

	const uint64_t len = c->buf[off + 1];
	if (unlikely(len < 2 || off + len > opt_len))
		goto bad_opt;

	switch (kind) {
	case TCPOPT_WSCALE: {
		/* RFC 7323 2.2: kind, len=3, 1 byte val. */
		if (unlikely(len != TCPOPT_WSCALE_SZ))
			goto bad_opt;
		const uint8_t ws = c->buf[off + 2];
		/* RFC 7323 2.3: values above 14 are capped to 14. */
		c->opts->wscale = ws <= TCPOPT_WSCALE_MAX
				  ? ws : TCPOPT_WSCALE_MAX;
		break;
	}
	case TCPOPT_SACK_PERM:
		/* RFC 2018 2: kind, len=2. */
		if (unlikely(len != TCPOPT_SACK_PERM_SZ))
			goto bad_opt;
		c->opts->sack_perm = 1;
		break;
	case TCPOPT_TIMESTAMP:
		/*
		 * RFC 7323 3.2:
		 * kind, len=10, TS val 4 bytes, TS echo 4 bytes.
		 */
		if (unlikely(len != TCPOPT_TIMESTAMP_SZ))
			goto bad_opt;
		/* RFC 7323 4.3: ignore duplicate timestamp options. */
		if (likely(!c->opts->ts))
			c->opts->ts = get_unaligned((__be32 *)&c->buf[off + 2]);
		break;
	}

	c->off = off + len;
	return 0;

bad_opt:
	c->err = -EINVAL;
	return 1;
}

/*
 * Parse TCP Options, RFC 9293 chapter 3.
 *
 * RFC does not specify what to do with duplicate MSS, Window Scale and SACK
 * Permited options, so for now we just use the last one for simplicity.
 * This can be added to the TCP anomaly filter later.
 *
 * The options are copied to a zeroed stack buffer and parsed from the stack,
 * one option per bpf_loop() iteration. This way the verifier proves the
 * parsing loop in isolation, converging on the widened loop state, and
 * continues after the loop with a single state, no matter how complex the
 * surrounding program is.
 */
static __always_inline int
tcp_parse_opts(XfwGlobalCtx *ctx, struct tcphdr *th, XfwTCPOpts *opts)
{
	const uint8_t *const o = (uint8_t *)th + sizeof(struct tcphdr);
	const uint64_t th_len = th->doff * 4;

	VERIFY_TRUE_OR_RETURN(th_len >= sizeof(struct tcphdr), -EINVAL);
	const uint64_t opt_len = th_len - sizeof(struct tcphdr);
	VERIFY_TRUE_OR_RETURN(opt_len <= TCP_OPTS_MAX, -E2BIG);
	if (unlikely(opt_len == 0))
		return 0;

	XfwTCPOptCtx c = {
		.buf		= {0},
		.opts		= opts,
		.opt_len	= opt_len,
		.off		= 0,
		/* Reaching the iterations limit isn't normal. */
		.err		= -E2BIG,
	};

	/*
	 * Copy the options to the parsing buffer. The helper validates the
	 * packet bounds, so a truncated packet ends up with -EINVAL.
	 */
	const uint64_t opt_off = (void *)o - XFW_CTX_DATA_BGN(ctx->ctx);
	if (unlikely(bpf_xdp_load_bytes(ctx->ctx, opt_off, c.buf, opt_len)))
		return -EINVAL;

	/*
	 * One option per iteration: TCP_OPTS_MAX + 1 iterations guarantee
	 * that the terminal check in the callback is reached even for
	 * TCP_OPTS_MAX one-byte options.
	 */
	long r = bpf_loop(TCP_OPTS_MAX + 1, tcp_parse_one_opt, &c, 0);
	if (unlikely(r < 0))
		return r;

	return c.err;
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
tcp_syncookies_write_opts(XfwGlobalCtx *ctx, struct tcphdr *th,
			  uint16_t mss, XfwTCPOpts *opts)
{
#define OPTS_DWORD(a, b, c, d)						\
	bpf_htonl(((uint32_t)(a) << 24)	| ((uint32_t)(b) << 16)		\
		  | ((uint32_t)(c) << 8) | (uint32_t)(d))

	__be32 *o = (__be32 *)(th + 1);
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

	*o++ = tcp_syncookies_make_cookie_ts(th, opts);
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
tcp_syncookies_make_synack(XfwGlobalCtx *ctx, struct tcphdr *th,
			   uint32_t cookie, uint16_t mss, XfwTCPOpts *opts)
{
	/* Minimal TCP header size = 5 in 4-byte double words. */
	uint8_t new_doff = 5 + tcp_syncookies_write_opts(ctx, th, mss, opts);
	int16_t d_len = (new_doff - th->doff) * 4;
	uint16_t tcplen = new_doff * 4;

	const void *const d_end = ctx->hdr_cur.end;
	VERIFY_TRUE_OR_RETURN((void *)th + tcplen <= d_end, -EFBIG);

	th->doff = new_doff;
	th->window = XFW_DEFAULT_WINDOW;
	th->check = 0;
	tcp_flag_word(th) |= TCP_FLAG_ACK;
	th->ack_seq = bpf_htonl(bpf_ntohl(th->seq) + 1);
	th->seq = bpf_htonl(cookie);

	/*
	 * TODO #224,#544: review the checksum computation -
	 * this diff from zero looks strange.
	 * Update xfw/t/unit/{csum,main}.cc
	 *
	 * See linux/tools/testing/selftests/bpf/progs/xdp_synproxy_kern.c
	 */
	int64_t csum = bpf_csum_diff(0, 0, (void *)th, tcplen, 0);
	VERIFY_TRUE_OR_RETURN(csum >= 0, csum);

	/*
	 * Swapping fields of size >= 16 bits doesn't affect the checksum,
	 * because the checksum is calculated over 16-bit words.
	 */
	SWAP(th->source, th->dest);

	struct ethhdr *eth = XFW_PKT_PTR(ctx, 0, struct ethhdr);
	VERIFY_TRUE_OR_RETURN((void *)(eth + 1) <= d_end, -EFBIG);

	struct ethhdr tmp_eth = *eth;
	memcpy(eth->h_dest, tmp_eth.h_source, sizeof(tmp_eth.h_source));
	memcpy(eth->h_source, tmp_eth.h_dest, sizeof(tmp_eth.h_dest));

	if (ctx->ipver == bpf_ntohs(ETH_P_IP)) {
		struct iphdr *iph4 =
			XFW_PKT_PTR(ctx, ctx->ip_off, struct iphdr);
		VERIFY_TRUE_OR_RETURN((void *)(iph4 + 1) <= ctx->hdr_cur.end,
				      -EINVAL);
		uint64_t ip_csum = csum_unfold(iph4->check);
		uint16_t ip_len = bpf_ntohs(iph4->tot_len) + d_len;
		ipv4_set_ttl_csum(iph4, &ip_csum);
		ipv4_set_tot_len_csum(iph4, ip_len, &ip_csum);
		iph4->check = csum_fold(ip_csum);

		SWAP(iph4->saddr, iph4->daddr);
		/* TODO #224: don't clear IP options for now - is this OK? */

		tcp_ipv4_csum_update(iph4, th, csum);
	}
	else if (ctx->ipver == bpf_ntohs(ETH_P_IPV6)) {
		struct ipv6hdr *iph6 =
			XFW_PKT_PTR(ctx, ctx->ip_off, struct ipv6hdr);
		VERIFY_TRUE_OR_RETURN((void *)(iph6 + 1) <= ctx->hdr_cur.end,
				      -EINVAL);
		iph6->hop_limit = XFW_DEFAULT_TTL;
		uint16_t payload_len = bpf_ntohs(iph6->payload_len);
		iph6->payload_len = bpf_htons(payload_len + d_len);

		SWAP(iph6->saddr, iph6->daddr);

		tcp_ipv6_csum_update(iph6, th, csum);
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
tcp_sk_listen_lookup(const XfwGlobalCtx *ctx, struct tcphdr *th)
{
	struct bpf_sock_tuple t;
	size_t tlen;

	if (ctx->ipver == bpf_ntohs(ETH_P_IP)) {
		struct iphdr *iph4 =
			XFW_PKT_PTR(ctx, ctx->ip_off, struct iphdr);
		VERIFY_TRUE_OR_RETURN((void *)(iph4 + 1) <= ctx->hdr_cur.end,
				      NULL);
		tlen = sizeof(t.ipv4);
		t.ipv4.sport = th->source;
		t.ipv4.dport = th->dest;
		t.ipv4.saddr = iph4->saddr;
		t.ipv4.daddr = iph4->daddr;
	}
	else if (ctx->ipver == bpf_ntohs(ETH_P_IPV6)) {
		struct ipv6hdr *iph6 =
			XFW_PKT_PTR(ctx, ctx->ip_off, struct ipv6hdr);
		VERIFY_TRUE_OR_RETURN((void *)(iph6 + 1) <= ctx->hdr_cur.end,
				      NULL);
		tlen = sizeof(t.ipv6);
		t.ipv6.sport = th->source;
		t.ipv6.dport = th->dest;
		xfw_ipv6_addr_cpy(t.ipv6.saddr, &iph6->saddr);
		xfw_ipv6_addr_cpy(t.ipv6.daddr, &iph6->daddr);
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

	const bool is_ip4 = ctx->ipver == bpf_htons(ETH_P_IP);
	void *iph = is_ip4 ? 
		(void *)XFW_PKT_PTR(ctx, ctx->ip_off, struct iphdr) :
		(void *)XFW_PKT_PTR(ctx, ctx->ip_off, struct ipv6hdr);
	uint32_t iph_len = is_ip4 ? sizeof(struct iphdr) : sizeof(struct ipv6hdr);
	XFW_ASSERT(iph && iph + iph_len <= ctx->hdr_cur.end);
	XFW_ASSERT(ctx->l4_off <= L4_OFF_MAX);
	struct tcphdr *th = XFW_PKT_PTR(ctx, ctx->l4_off, struct tcphdr);
	XFW_ASSERT((void *)(th + 1) <= ctx->hdr_cur.end);

	/*
	 * The kernel syncookie helper expects a minimal SYN header. Temporarily
	 * hide TCP options from the helper and then restore/encode the options
	 * we can safely preserve in the generated SYN-ACK.
	 *
	 * In flood mode, parse failures mean option preservation is skipped.
	 * Passive mode keeps using the parsed option data. Make the emitted
	 * option profile configurable later.
	 */
	uint16_t old_doff = th->doff;
	th->doff = (sizeof(struct tcphdr) / 4) & 0xF;
	struct bpf_sock *sk = tcp_sk_listen_lookup(ctx, th);
	if (unlikely(!sk)) {
		/* Treat a SYN for a non-listening or absent socket as flooding. */
		ts->last_gen_jiff = ctx->ts_jiff;
		return XFW_MAKE_CTX_DROP(ctx, XFW_SYNCOOKIE_FAILED,
					 "No listening socket");
	}

	int64_t seq_mss = bpf_tcp_gen_syncookie(sk, iph, iph_len, th,
						sizeof(struct tcphdr));
	bpf_sk_release(sk);
	th->doff = old_doff & 0xF;

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
	long r = tcp_parse_opts(ctx, th, &opts);
	if (unlikely(r)) {
		XFW_CTX_DBG("Cannot parse TCP options, %d", r);
		return XFW_MAKE_CTX_DROP(ctx, XFW_SYNCOOKIE_FAILED,
					 "bad TCP options in SYN");
	}

	r = tcp_syncookies_make_synack(ctx, th, (uint32_t)seq_mss,
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
tcp_syncookies_ack_filter(const XfwGlobalCtx *ctx, struct tcphdr *th)
{
	/* Lookup socket to validate ACK against SYN cookie */
	struct bpf_sock *sk = tcp_sk_listen_lookup(ctx, th);
	if (!sk)
		return XFW_MAKE_CTX_DROP(ctx, XFW_SYNCOOKIE_FAILED,
					 "No host socket");

	const bool in_listen_state = sk->state == BPF_TCP_LISTEN;
	bpf_sk_release(sk);

	/* Only handle ACKs destined to listening sockets */
	if (!in_listen_state)
		return XFW_CTX_CONTINUE;

	/*
	 * Use raw SYN cookie verification API.
	 *
	 * bpf_tcp_check_syncookie() return -EINVAL for disables tcp_syncookies
	 * or bad TCP or IP header lengths, -ENOENT for no recent overflow or
	 * unexpected TCP flags. This makes hard to process the function return
	 * code.
	 *
	 * There was a patch to fix this, it was rejected, it seems because of
	 * API backward compatibility. Reference:
	 * https://groups.google.com/g/clang-built-linux/c/Ehb-mZnip-E/m/nRWGW24PBAAJ
	 */
	if (ctx->ipver == bpf_ntohs(ETH_P_IP)) {
		struct iphdr *iph4 =
			XFW_PKT_PTR(ctx, ctx->ip_off, struct iphdr);
		XFW_ASSERT((void *)(iph4 + 1) <= ctx->hdr_cur.end);

		int r = bpf_tcp_raw_check_syncookie_ipv4(iph4, th);
		if (r < 0)
			return XFW_MAKE_CTX_DROP_EXT(ctx, XFW_SYNCOOKIE_FAILED,
				"IPv4 ACK with invalid cookie, retcode=%d.", r);
	}
	else if (ctx->ipver == bpf_ntohs(ETH_P_IPV6)) {
		struct ipv6hdr *iph6 =
			XFW_PKT_PTR(ctx, ctx->ip_off, struct ipv6hdr);
		/* This check is just to satisfy the verifier. */
		XFW_ASSERT((void *)(iph6 + 1) <= ctx->hdr_cur.end);

		int r = bpf_tcp_raw_check_syncookie_ipv6(iph6, th);
		if (r < 0)
			return XFW_MAKE_CTX_DROP_EXT(ctx, XFW_SYNCOOKIE_FAILED,
				"IPv6 ACK with invalid cookie, retcode=%d.", r);
	}

	return XFW_CTX_CONTINUE;
}

#undef BANNER
#pragma pop_macro("BANNER")
