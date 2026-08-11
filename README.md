# Tempesta xFW

**Open-source volumetric DDoS protection for Linux, powered by XDP and eBPF.**

Tempesta xFW filters malicious L3-L4 traffic close to the network interface,
before it reaches the protected application. Run it on an individual server, an
inline Linux gateway, or a dedicated scrubbing node to mitigate TCP, UDP, ICMP,
and DNS floods.

**At a glance**

- **[Host · Gateway · Scrubbing](#deployment-modes)**
- **[Published lab workload: up to approximately 200 Mpps on one Intel Xeon Gold 6348 CPU](#performance)**
- **[Optional L3-L7 and bot-protection stack](#full-stack-ddos-and-bot-protection)**

**Quick links**

- [GitHub](https://github.com/tempesta-tech/xFW)
- [Get started](#quick-start)
- [Documentation](https://tempesta-tech.com/tempesta-escudo/knowledge-base/XFW/)
- [Benchmarks](#performance)
- [DDoS protection use cases](https://tempesta-tech.com/tempesta-escudo/knowledge-base/DDoS-Protection-Use-Cases/)

## Why Tempesta xFW?

- **Filter early.** XDP handles ingress traffic ahead of the Linux network stack,
  while TC observes the egress path needed by bidirectional protections.
- **Deploy where the traffic is.** Protect one host, an entire network behind a
  gateway, or only the attacked prefixes redirected to a scrubbing cluster.
- **Apply precise policy.** Combine protocol validation, ACLs, GeoIP rules, TCP
  connection checks, and packet/byte rate limits instead of relying on a single
  coarse threshold.
- **Roll out safely.** Evaluation mode reports traffic that would be blocked
  without dropping it, so policies can be tuned against real workloads.
- **Operate with familiar tooling.** Update rules over gRPC, export Prometheus
  counters, and optionally record security events in ClickHouse.
- **Extend protection through L7.** Combine xFW with
  [Tempesta FW](https://github.com/tempesta-tech/tempesta) and
  [WebShield](https://github.com/tempesta-tech/webshield) for volumetric,
  application-layer, and bot protection.

## How it works

```text
                         control plane
                         tfw CLI / gRPC
                              |
                              v
Internet -> NIC -> XDP ingress filters -> Linux host, router, or application
                                                |
                                                v
                                      TC egress processing -> Network
```

The XDP and TC programs form the high-performance mitigation data plane. The
management daemon validates and applies policy changes at runtime, locally or
remotely. In an on-demand scrubbing design, an external attack detector and
controller can redirect an attacked destination or prefix through xFW and update
its mitigation rules.

The management daemon listens on a network socket and accepts gRPC requests. Use
the [`tfw` CLI](https://tempesta-tech.com/tempesta-escudo/knowledge-base/Command-line-interface/)
to configure xFW, or use the
[C client library](https://tempesta-tech.com/tempesta-escudo/knowledge-base/Client-library/)
to build xFW control flows into an application.

## Features

- **Volumetric flood mitigation:** TCP SYN, ACK, RST, FIN, NULL, XMAS, and other
  flag floods; UDP floods; and ICMPv4/ICMPv6 floods.
- **TCP defenses:** high-performance SYN cookies in host mode, SYN/RST rate
  limiting in gateway mode, handshake-aware authentication, and configurable
  anomaly checks.
- **DNS protection:** protects authoritative and recursive DNS over UDP/53 from
  malformed traffic, reflection, and amplification, including unsolicited or
  oversized responses and anomalous queries.
- **IPv4 and IPv6 policy:** source address/prefix and port rules, destination
  address/port rules, protocol selection, allow/block policies, optional GeoIP
  country matching, and GRE support when configured.
- **Layered rate limiting:** named per-source and per-destination limits in packets
  and bytes per second, plus ICMP- and TCP-flag-specific limits.
- **Protocol validation:** rejects malformed and unsupported packet layouts,
  invalid TCP/UDP fields, suspicious TCP flag combinations, and fragmented IP
  traffic.
- **FlowSpec-aligned rule model:** covers most match categories from
  [RFC 8955 and RFC 8956](https://tempesta-tech.com/tempesta-escudo/knowledge-base/XFW-Filtration-Rules/#rfc-8955-and-rfc-8956-filtering).
- **Dynamic configuration:** push complete configurations or incremental patches
  through the `tfw` CLI and gRPC management endpoint.
- **Observability:** Prometheus-format packet and byte counters, detailed drop
  reasons, and optional ClickHouse event logging.
- **Driver compatibility:** native XDP for higher performance or SKB/generic XDP
  for wider network-driver support.

## Deployment modes

| Mode | Where xFW runs | Traffic path | Best suited for |
| --- | --- | --- | --- |
| **Host** | On the protected server | xFW protects the host's own addresses and sees both directions | Web and DNS nodes, CDN edges, on-premises ADCs, and full-stack Tempesta deployments |
| **Gateway (gate)** | On an inline Linux router | Client and return traffic pass through xFW before reaching the protected network | Transparent protection for services or network segments |
| **Scrubbing** | On a shared mitigation node or cluster | A router redirects only attacked destinations/prefixes through xFW; unaffected traffic stays on its normal path and direct server return is supported | On-demand mitigation, shared scrubbing capacity, and failure isolation |

Gateway and scrubbing deployments are both network-protection variants. A hybrid
pass-through design can keep inexpensive ACLs, protocol checks, and coarse limits
always active, then enable more selective rules when a detector reports an attack.
See the [complete modes-of-operation guide](https://tempesta-tech.com/tempesta-escudo/knowledge-base/XFW/#modes-of-operation)
for routing and return-path requirements.

## Full-stack DDoS and bot protection

Tempesta xFW is useful on its own and is also the network-protection layer of
[Tempesta Escudo](https://tempesta-tech.com/solutions/ddos-protection/):

| Layer | Open-source component | Role |
| --- | --- | --- |
| Network, L3-L4 | **Tempesta xFW** | Volumetric flood mitigation and network policy |
| Application, L7 | [Tempesta FW](https://github.com/tempesta-tech/tempesta) | HTTP DDoS and web-attack protection, WAF, load balancing, and acceleration |
| Bots and advanced L7 attacks | [Tempesta WebShield](https://github.com/tempesta-tech/webshield) | Malicious-bot and sophisticated application-layer DDoS protection |

This layered deployment filters L3-L4 attacks early while preserving
application context for L7 and bot decisions.

> Tempesta WebShield's README currently labels version 0.1 experimental and not
> suitable for production. Check that project's current status before deployment.

## Performance

Lab measurements demonstrate attack processing at **up to approximately 200
Mpps** and **more than 100 Gbps**, depending on packet size, attack type, and
enabled protection. The documented test system uses one Intel Xeon Gold 6348 CPU
and a dual-port NVIDIA/Mellanox ConnectX-6 Dx 100 GbE adapter.

The test coverage includes ICMPv6 floods, mixed TCP/UDP floods, SYN-cookie
protection in host mode, SYN rate limiting in gateway/scrubbing mode, and latency
under load. Reported rates are aggregate TRex offered workloads across both ports
while xFW processes and filters the traffic, not end-to-end application
throughput.

Benchmarks are updated regularly. See the
[Performance page](https://tempesta-tech.com/tempesta-escudo/knowledge-base/Performance/)
for the latest numbers, test configurations, methodology, and raw results. The
repository also contains the [TRex workload sources](t/trex/).

## Quick start

### Requirements

- Ubuntu Server 24.04.3 LTS or later
- Linux kernel 6.8 or later with BPF syscall and event support, BTF, BPF JIT,
  eBPF JIT, and SYN cookies enabled
- A network driver with native XDP support for best performance, or SKB/generic
  mode for compatibility
- Clang 19 for a source build
- amd64/x86-64; the documented BPF build currently uses x86-64 system headers

ClickHouse 21.1 or later is optional and is needed only for security-event
analytics. See [Basic Administration](https://tempesta-tech.com/tempesta-escudo/knowledge-base/Basic-Administration/)
for the complete kernel requirement list.

### Build from source

Install the build and runtime dependencies on Ubuntu 24.04:

```bash
sudo apt update
sudo apt install -y git curl cmake make g++ pkgconf jq xdp-tools \
    clang-19 clang-tools-19 clang-tidy-19 clang-format-19 \
    libboost-all-dev flatbuffers-compiler libflatbuffers-dev \
    libprotobuf-dev libgrpc++-dev libfmt-dev libspdlog-dev \
    libmaxminddb-dev libbpf-dev libbpf-tools libgtest-dev \
    libxxhash-dev libbenchmark-dev linux-tools-common \
    linux-tools-generic linux-cloud-tools-generic
```

Clone the public repositories, build an optimized binary, and install it under
`/opt/tempesta`:

```bash
git clone https://github.com/tempesta-tech/xFW.git
cd xFW

# The checked-in submodule URL uses SSH; override it locally with public HTTPS.
git config submodule.fw.url https://github.com/tempesta-tech/tempesta.git
git submodule update --init --recursive

make -j"$(nproc)"
sudo make install
```

The source install provides binaries but does not install a main configuration.
Start with the compatibility-oriented host example, select the real interface,
and disable optional ClickHouse logging for the first run:

```bash
sudo install -d -m 0755 /etc/tempesta
if ! sudo test -e /etc/tempesta/xfw.json; then
    sudo install -m 0644 examples/xfw-skb-host.json /etc/tempesta/xfw.json
fi
sudoedit /etc/tempesta/xfw.json
```

For example:

```json
{
    "devices": "ens3",
    "devices-mode": "skb",
    "event-logging": "off"
}
```

Check the host and start xFW:

```bash
sudo /opt/tempesta/bin/xfwctl --check-req
sudo /opt/tempesta/bin/xfwctl --start
sudo /opt/tempesta/bin/xfwctl --status
```

> **No filtering rules are active yet, so traffic is still allowed.** Review the
> protected addresses, ports, and workload-specific limits before applying a
> ruleset. In xFW configuration, `bps` means **bytes** per second.

Copy and customize one of the supplied rulesets, then push it to the local
management daemon:

```bash
if ! sudo test -e /etc/tempesta/xfw-http-rules.conf; then
    sudo install -m 0644 examples/xfw-http-rules.conf /etc/tempesta/
fi
sudoedit /etc/tempesta/xfw-http-rules.conf
/opt/tempesta/bin/tfw push --conf /etc/tempesta/xfw-http-rules.conf
sudo /opt/tempesta/bin/xfwctl --status
```

Use [evaluation mode](https://tempesta-tech.com/tempesta-escudo/knowledge-base/Evaluation-Mode/)
to observe proposed blocks before enforcing a new policy. Evaluation mode and
the `tcp_syncookies` rule cannot be enabled together.

The repository also includes a [native-XDP gateway configuration](examples/xfw-native-gate.json),
[DNS protection rules](examples/xfw-dns-rules.conf), and more context in the
[step-by-step policy guide](https://tempesta-tech.com/tempesta-escudo/knowledge-base/Quick-start/).

### Daily operations

```bash
# Show program, rule, daemon, and interface state.
sudo /opt/tempesta/bin/xfwctl --status

# Read Prometheus metrics (default management address).
curl http://127.0.0.1:9090/metrics

# Inspect available lifecycle and CLI operations.
/opt/tempesta/bin/xfwctl --help
/opt/tempesta/bin/tfw --help

# Stop xFW and detach its programs from configured devices.
sudo /opt/tempesta/bin/xfwctl --stop
```

`xfwctl --stop` unloads all programs managed by `xdp-loader` and removes the
`clsact` qdisc from each configured interface. Check for coexisting XDP or TC
applications before using it on a shared interface.

See [Observability](https://tempesta-tech.com/tempesta-escudo/knowledge-base/Observability/)
to enable ClickHouse event logging and interpret counters and drop reasons.

## Documentation

| Topic | Guide |
| --- | --- |
| Concepts, device modes, and deployment | [Tempesta xFW overview](https://tempesta-tech.com/tempesta-escudo/knowledge-base/XFW/) |
| Kernel and system requirements | [Basic Administration](https://tempesta-tech.com/tempesta-escudo/knowledge-base/Basic-Administration/) |
| Policy walkthrough and verification | [Quick start](https://tempesta-tech.com/tempesta-escudo/knowledge-base/Quick-start/) |
| Rules and filter chaining | [xFW Filtration Rules](https://tempesta-tech.com/tempesta-escudo/knowledge-base/XFW-Filtration-Rules/) |
| Web, DNS, and advanced policies | [DDoS Protection Use Cases](https://tempesta-tech.com/tempesta-escudo/knowledge-base/DDoS-Protection-Use-Cases/) |
| Metrics and security events | [Observability](https://tempesta-tech.com/tempesta-escudo/knowledge-base/Observability/) |
| Remote and cluster management | [Tempesta Manager](https://tempesta-tech.com/tempesta-escudo/knowledge-base/Manager/) |
| Test setup and raw benchmark output | [Performance](https://tempesta-tech.com/tempesta-escudo/knowledge-base/Performance/) and [repository notes](doc/perf.md) |

## Development

After a successful build, run the repository's unit test targets with:

```bash
make test
```

The Python integration environment has additional setup requirements documented
in [t/func/README.md](t/func/README.md). `make benchmark` runs local hash
microbenchmarks; the network-performance suite is under [t/trex/](t/trex/).

For an eBPF debug build, clean and build as separate steps:

```bash
make clean
make -j"$(nproc)" DEBUG=1
sudo cat /sys/kernel/tracing/trace_pipe  # Press Ctrl-C to stop.
```

Run `make help` for all top-level build targets. A custom install prefix is
supported with `sudo make install PREFIX=/custom/path`; set
`TEMPESTA_XFW_PATH=/custom/path` when running `xfwctl` from another location.

## Contributing and support

Bug reports, feature proposals, benchmark results, and pull requests are welcome.
Start with [GitHub Issues](https://github.com/tempesta-tech/xFW/issues) and include
the xFW revision, kernel version, NIC/driver, device mode, configuration, and a
minimal reproduction when applicable.

Tempesta xFW is maintained by [Tempesta Technologies](https://tempesta-tech.com/).
See [LICENSE](LICENSE) for the open-source license terms.
