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
