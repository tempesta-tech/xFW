/**
 *	Tempesta xFW shared TCP cookie packet helpers
 *
 * SPDX-FileCopyrightText: © 2026 Tempesta Technologies, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#pragma once

#include "vmlinux.h"
#include "filter.h"
#include "parsing_helpers.h"

#ifndef BPF_F_CURRENT_NETNS
#define BPF_F_CURRENT_NETNS	-1
#endif

#define XFW_DEFAULT_TTL		64
#define XFW_DEFAULT_WSCALE	7
#define TCP_TS_HZ		1000

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

static __always_inline __sum16
tcp_ipv4_csum(const struct iphdr *iph4, uint16_t tcp_len, uint64_t csum)
{
	/*
	 * Sum addresses stored in network byte order w/o converting to little
	 * endian on x86-64 (reference csum_tcpudp_magic() in
	 * linux/arch/x86/include/asm/checksum_64.h).
	 */
	csum += (__be32)iph4->saddr;
	csum += (__be32)iph4->daddr;
	csum += (XFW_L4_PROTO_TCP + tcp_len) << 8;

	csum = (csum & 0xffffffffUL) + (csum >> 32);
	csum = (csum & 0xffffffffUL) + (csum >> 32);

	return csum_fold(csum & 0xffffffffUL);
}

static __always_inline __sum16
tcp_ipv6_csum(const struct ipv6hdr *iph6, uint16_t tcp_len, uint64_t csum)
{
	int i;

#pragma unroll
	for (i = 0; i < 4; i++)
		csum += (__be32)iph6->saddr.in6_u.u6_addr32[i];
#pragma unroll
	for (i = 0; i < 4; i++)
		csum += (__be32)iph6->daddr.in6_u.u6_addr32[i];

	csum += bpf_htonl(tcp_len);
	csum += bpf_htonl(XFW_L4_PROTO_TCP);

	csum = (csum & 0xffffffffUL) + (csum >> 32);
	csum = (csum & 0xffffffffUL) + (csum >> 32);

	return csum_fold(csum & 0xffffffffUL);
}

static __always_inline void
tcp_ipv4_csum_update(struct iphdr *iph4, struct tcphdr *th, uint64_t csum)
{
	th->check = tcp_ipv4_csum(iph4, th->doff * 4, csum);
}

static __always_inline void
tcp_ipv6_csum_update(struct ipv6hdr *iph6, struct tcphdr *th, uint64_t csum)
{
	th->check = tcp_ipv6_csum(iph6, th->doff * 4, csum);
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
				wscale_present : 1,
				ts_present : 1,
				__reserved : 5;
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
	 * The options length must fit into the temporary options buffer.
	 * Besides validating the invariant, this gives the verifier an explicit
	 * upper bound for subsequent accesses to the stack-backed buffer.
	 */
	if (unlikely(opt_len > TCP_OPTS_BUF_SZ))
		goto bad_opt;

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
		c->opts->wscale_present = 1;
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
		c->opts->ts_present = 1;
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

