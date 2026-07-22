# eBPF Verifier Guide

## Verifier state space

The eBPF verifier analyzes all possible execution paths using symbolic
execution.

Branches, pointer checks and value constraints may split execution into
multiple verifier states. Increasing the number of reachable states
increases verification time.

Small changes in control flow or the order of packet validation may
significantly affect verifier complexity without changing program
semantics.

## Verification time vs runtime performance

Verification time and runtime performance are independent metrics.

A change that improves the runtime packet processing path may increase
verifier complexity, and vice versa. Evaluate both metrics
independently.

Example:

Commit `7efcd5534ad087a5a3463a42887de822a1e6d752` reordered argument
analysis. The resulting program executes faster at runtime, but requires
more verifier work during program loading.

| Metric                 |  Before |   After |
| ---------------------- | ------: | ------: |
| `load_xdp()` (Debug)   | 1804 ms | 2481 ms |
| `load_xdp()` (Release) |  833 ms |  961 ms |

The increased loading time is caused by a larger verifier state space,
not by slower runtime execution.

Always measure both:

* verifier loading time (`load_xdp()`);
* runtime performance (latency, throughput, CPU utilization).

Do not use one metric as a proxy for the other.

## Stack usage

The eBPF verifier limits the maximum stack usage to 512 bytes. The limit
is evaluated over the call chain rather than for an individual function.

The verifier rounds each function's stack usage before summing it across
the call chain. As a result, small changes in local stack usage may have
a disproportionate impact on verification.

Example: commit `d7747b514d29833c45e738b770e741f3f81ff32e`.

```text
xfw_xdp()                   360
ingress_dns_filter_global() 128
process_dname_global()       24

round(360) + round(128) + round(24)
= 384 + 128 + 32
= 544 > 512
```

Although `xfw_xdp()` used only 360 bytes, verifier rounding caused the
effective stack usage to exceed the 512-byte limit.

Reducing the stack usage of `xfw_xdp()` by only 20 bytes moved it below
the rounding threshold, allowing the program to pass verification.

The stack reduction was achieved by delaying the initialization of a
local variable until it was actually needed, reducing its lifetime in the
generated BPF code.

Debug and Release builds may produce different stack layouts. The
verifier analyzes the generated BPF instructions, not the C source, so a
program that verifies in one build configuration may fail in another.

## Moving scalar context to a BPF map

In some cases the eBPF verifier may become a limiting factor due to stack
size restrictions, function complexity, or program decomposition requirements.
One possible optimization strategy is to move a subset of the packet processing
context from the stack into a per-CPU BPF map. Only scalar values should be
moved this way. Pointers to packet data, packet headers, cursor structures, or
other verifier-tracked references must remain on the stack because they cannot
be safely transferred through BPF maps.

For example, the following subset of `XfwGlobalCtx` can be stored in a map:

```c
typedef struct XfwPktCtx {
	uint32_t	pkt_sz;
	int		ipver;
	uint64_t	ts_jiff;
	uint8_t		l4_proto;
	XfwIp		ilog_addr;
} XfwPktCtx;
```

The corresponding map:

```c
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, XfwPktCtx);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, 1);
} xfw_pkt_ctx SEC(".maps");
```

The global context then stores a pointer to the per-CPU map value instead of
keeping all scalar fields on the stack:

```c
typedef struct XfwGlobalCtx {
	...
	XfwPktCtx *pkt_ctx;
	...
} XfwGlobalCtx;
```

The pointer is initialized during context setup:

```c
static __always_inline int
xfw_ctx_init(XfwGlobalCtx *ctx, XfwMd *pkt_ctx)
{
	const unsigned zero = 0;

	memset(ctx, 0, sizeof(*ctx));

	ctx->cfg = bpf_map_lookup_elem(&MAP_CFG_REF, &zero);
	ctx->g_stats = bpf_map_lookup_elem(&MAP_GLBL_STAT_REF, &zero);
	ctx->pkt_ctx = bpf_map_lookup_elem(&xfw_pkt_ctx, &zero);

	if (unlikely(!(ctx->cfg && ctx->g_stats && ctx->pkt_ctx)))
		return -1;

	memset(ctx->pkt_ctx, 0, sizeof(*ctx->pkt_ctx));

	INIT_CURSOR_FROM_BPF_CONTEXT(pkt_ctx, &ctx->hdr_cur);

	ctx->pkt_sz = ctx->hdr_cur.end - ctx->hdr_cur.pos;
	ctx->pkt_ctx->pkt_sz = ctx->pkt_sz;

	ctx->ctx = pkt_ctx;

	ctx->ts_jiff = bpf_jiffies64();
	ctx->pkt_ctx->ts_jiff = ctx->ts_jiff;

	return 0;
}
```

This approach allows reducing stack pressure while preserving access to
frequently used scalar packet metadata. At the moment, keeping data on the
stack is generally preferred because stack accesses are cheaper than map
accesses. Therefore, this technique should be considered only when verifier
limitations become a practical issue.
