/**
 * The minimal XDP module dropping all the traffic to estimate the
 * XDP performance baseline.
 *
 * Build & load:
 *
 * $ clang -O2 -g -Wall -target bpf -D__TARGET_ARCH_x86 \
 *   -I/usr/include/x86_64-linux-gnu -c xdp_baseline.c -o xdp_baseline.o
 *
 * $ xdp-loader load -m native enp202s0f0np0 ./xdp_baseline.o
 * $ xdp-loader load -m native enp202s0f1np1 ./xdp_baseline.o
 *
 * $ xdp-loader unload --all enp202s0f1np1
 * $ xdp-loader unload --all enp202s0f0np0
 *
 * SPDX-FileCopyrightText: © 2026 Tempesta Technologies, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define unlikely(X)	__builtin_expect(!!(X), 0)

SEC("xdp")
int
xdp_dummy(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr *eth = data;

	if (unlikely((void *)(eth + 1) > data_end))
		return XDP_DROP;

	/* Let TRex resolve MAC address. */
	if (unlikely(eth->h_proto == bpf_htons(ETH_P_ARP)))
		return XDP_PASS;

	return XDP_DROP;
}

char _license[] SEC("license") = "GPL";
