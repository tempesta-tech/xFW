# DDOS emulation with `TRex` and `trafgen`
- Trafgen is a part of [netsniff-ng](https://github.com/netsniff-ng/netsniff-ng). Generates traffic
or PCAPs based on a template (config).
- TRex is a Cisco software, see [trex-tgn](https://trex-tgn.cisco.com/trex/doc/trex_manual.html).
Sends packets effectively, can generate Gbps load.

## trafgen
How to run trafgen:
```
sudo trafgen -c syn-flood.conf -o syn-flood.pcap -n 1
```

- `-n N` — stop after producing N packets. Useful for testing and PCAP generation.
- `-P N` — for to N processes (default: number of cores).
- `-b rate` — limit output rate (could be inaccurate, won't use TX ring so don't expect to reach
10Gbit with it).
- You could use preprocessor (`-p`) and pass constants (`-DPARAM=VALUE`) for more flexible setup.

See trafgen manual for config syntax (or trafgen-examples folder).

### PCAPs modification routine for usage in TRex

1. Tune trafgen config as you need. It doesn't make sence to modify the next parameters, see TRex
chapter why (just use `drnd()`):
    * `eth(da=drnd(), sa=drnd())`
    * `ipv4(saddr=drnd(), daddr=drnd())`
    * `tcp|udp(sport=drnd())`

> TRex in Stateful mode doesn't work with other L4 protocols than TCP/UDP. You could get error
message if you provide something else:
```
ERROR packet 1 is not supported, should be Ethernet/IP(0x0800)/(TCP|UDP) format try to convert it
using Wireshark !
```
> Also it lies about packet number, be careful :-)

2. Run trafgen to write traffic to PCAP:
```
trafgen -c syn-flood.conf -o syn-flood.pcap -n 1
```
3. (Optional) review resulting PCAP with Wireshark.
4. Copy new PCAP file to `trex-core/scripts` folder, write proper YAML for TRex and run TRex.

## TRex

TRex can send trafgen generated PCAP files at enormous speeds, effectively utilizing the bandwidth
of the network interface.

What you need to understand TRex fast (Stateful mode only, Stateless and ASTF are out of scope):

1. Basically, you create PCAPs with trafgen as described above. One packet should be enough for
monotonous traffic (SYN flood, RST flood etc.), because TRex allows to multiply traffic (see `cps`,
`ipg` YAML config settings, `-m` CLI argument).

> See how `trex-core/scripts/cap2/imix_1518.yaml` improves performance.

2. Write YAML like in [manual](https://trex-tgn.cisco.com/trex/doc/trex_manual.html). Pay attention
to examples from chapter 4, especially look at 'multiple generators' feature.

3. TRex replaces source IP, source port and destination IP of a packet, so you could use any
valid value when generate it with trafgen. But you shall provide desired destination port:
    * Source IP is replaced with `clients_start`/`clients_end` or `generator_clients.ip_start`/
    `ip_end`.
    * Source ports are set to random values, it's number depends on traffic intensivity.
    * Destination IP is replaced with `servers_start`/`servers_end` or `generator_servers.ip_start`/
    `ip_end`.
    * Ethernet both addresses are replaced as well to appropriate.
    * All another characteristics of traffic won't be rewritten AFAIK, so tune it with trafgen.

4. TRex default setup assumes that you have paired NICs (1, 2) and two servers: generating traffic
(G) and server under test (S). G1 connected to S1, G2 to S2. We send traffic from G1 to S1 and it's
routed to be sent back from S2 to G2. G1-S1 traffic is `Total-Tx` on TRex control plane and
`Total-Rx` is S2-G2. When you run TRex on valid traffic (not SYN/RST/ACK flood or something), you
shall see in control plane that `Total-Tx` equals `Total-Rx` (or almost).

> You could provide another setup with dummy ports, see how it's done in
[performance tests](https://github.com/tempesta-tech/xFW/blob/main/doc/perf.md). If you just send traffic and don't receive, Total-Rx will be 0,
of course.

5. If `Total-Tx` == `Total-Rx`, but you cannot achieve desired bandwidth, first of all check
`Cpu Utilization` in control plane (or just in htop). If it's close to 100%, probably you need to
increase number of cores in TRex (`-c`) or somehow optimize test script.

6. If after some time Total-Rx from Total-Tx goes to zero, probably than means that SUT NIC started
to drop packets (see in ifconfig on SUT).

Steps to run TRex:

1. Copy desired files (YAML + PCAPs) to TRex scripts folder.

2. Validate YAML - it prints resulting traffic on success:
```
./bp-sim-64-debug -f syn-flood.yaml -o my.erf -v 3
```
> `bp-sim-64-debug` is provided only in binary package, not in source code

3. Run TRex like:
```
sudo ./t-rex-64 -f syn-flood.yaml -m 1000 -c 32 -d 5
```
* Experiment with `-m` to maximize bandwidth. This is multiplier of traffic amount, so you could
provide any reasonable value.
* Don't forget to provide `-c` with maximum value for optimal CPU utilization (otherwise full
bandwidth could be not achieved).
* `-d` just overrides `duration` config value, it's handly to pass it as argument.
