# How to write the tests

## Best practices

- `check_connection(client, server)` is the main method to verify a connection.
- Parametrize with `protocol`, `ip_version`, `server`, `client` instead of listing `tcp_ip4_*` by hand.
- Put `server.ip_testing` / `client.ip_testing` into rules. New addresses and ports: `generate_new_address()`, `generate_new_port()`.
- Snapshot counters with `metrics_diff` / `syncookies_kern_stats_diff`, not absolute `metrics()`. For TCP pass `wait_softirq=True`.
- Do not `stop()` clones from `client_cloner` / `server_cloner` — the fixtures close them after the test.

## Regular sockets

Kernel `server` / `client` fixtures iterate TCP/UDP and IPv4/IPv6, and `establish_connection` starts the pair.

```python
from framework.cmp import check_connection
from framework.stateful import RegularKernelSocketNetworkStateful
from framework.xfw import XFW


async def test_dst_allowed(
    xfw: XFW,
    protocol: str,
    ip_version: str,
    server: RegularKernelSocketNetworkStateful,
    client: RegularKernelSocketNetworkStateful,
    establish_connection,
):
    await xfw.rules_set(f"""
        xfw {{
            defaults {{ dst: allow; }}
            dst {ip_version}.{protocol} : allow {{
                {server.ip_testing}:{server.port}
            }}
        }}
        """)

    await client.send_message("test\n")
    assert await server.receive_message() == "test\n"
    assert await check_connection(client, server) is True, (
        f"Server {server.ip_testing}:{server.port} is not available"
    )
```

## Raw sockets

A raw TCP client does a handshake, sends payload, and closes the connection against a kernel server.

```python
from scapy.layers.inet import TCP

from framework.asyn import TcpRawClient
from framework.stateful import RegularKernelSocketNetworkStateful


async def test_raw_tcp_client_with_handshake(
    tcp_server: RegularKernelSocketNetworkStateful,
    tcp_raw_client: TcpRawClient,
    start_tcp_server_and_raw_clients,
):
    assert await tcp_raw_client.handshake() is True

    await tcp_raw_client.send_packet(TCP(flags="PA") / b"test_data_1")
    response = await tcp_raw_client.receive_packet()
    assert tcp_raw_client.has_flag(
        response, "A"
    ), f"Unexpected reply packet with flags = {response.flags}. Expected A"

    assert await tcp_raw_client.close_connection() is True
```

## Custom TCP packet

Build a SYN with `get_tcp_packet()` and send it with `send_packet()`.

```python
from framework.asyn import TcpRawClient, TcpRawServer
from framework.utils import get_tcp_packet
from framework.xfw import XFW


async def test_send_custom_tcp_packet(
    xfw: XFW,
    tcp_raw_server: TcpRawServer,
    tcp_raw_client: TcpRawClient,
    start_tcp_raw_server_and_raw_clients,
):
    await xfw.rules_set("xfw { }")

    packet = get_tcp_packet(flag="S")
    await tcp_raw_client.send_packet(packet)
    assert await tcp_raw_server.receive_packet() is not None
```

## Custom Ethernet packet

Assemble an Ethernet frame with Scapy and send it through `ether_raw_client`.

```python
from asyncio import gather

from scapy.all import ETH_P_IP, Raw
from scapy.layers.inet import IP, UDP, Ether

from framework.asyn.ether_raw_client import EtherRawClient
from framework.asyn.ether_raw_server import EtherRawServer
from framework.xfw import XFW


async def test_send_custom_ethernet_packet(
    xfw: XFW,
    ether_raw_client: EtherRawClient,
    ether_raw_server: EtherRawServer,
):
    await ether_raw_server.start()
    await ether_raw_client.start()

    src_mac, dst_mac = await gather(
        ether_raw_client.get_mac_address(),
        ether_raw_server.get_mac_address(),
    )
    payload = b"payload"
    packet = (
        Ether(dst=dst_mac, src=src_mac, type=ETH_P_IP)
        / IP(src=ether_raw_client.ip, dst=ether_raw_server.ip)
        / UDP(sport=ether_raw_client.port, dport=ether_raw_server.port)
        / Raw(payload)
    )

    await xfw.rules_set("xfw {}")
    await ether_raw_client.send_packet(packet)

    received = await ether_raw_server.receive_message(payload)
    assert received is not None
    assert bytes(received[Raw].load) == payload
```

## xFW and reload

`rules_set` applies the config immediately; after `restart()` push the rules again.

```python
from framework.cmp import check_connection
from framework.stateful import RegularKernelSocketNetworkStateful
from framework.xfw import XFW


async def test_xfw_reload(
    xfw: XFW,
    tcp_ip4_server: RegularKernelSocketNetworkStateful,
    tcp_ip4_client: RegularKernelSocketNetworkStateful,
):
    await tcp_ip4_server.start()
    await tcp_ip4_client.start()

    await xfw.rules_set("""
        xfw {
            defaults { dst: allow; }
        }
        """)
    assert await check_connection(tcp_ip4_client, tcp_ip4_server) is True

    await xfw.restart()
    await xfw.rules_set("""
        xfw {
            defaults { dst: allow; }
        }
        """)
    assert await check_connection(tcp_ip4_client, tcp_ip4_server) is True
```

## Client and server clonners

Clones get new addresses and ports and are closed automatically after the test, so do not call `stop()`.

```python
from framework.cmp import check_connection
from framework.stateful import RegularKernelSocketNetworkStateful
from framework.xfw import XFW


async def test_block_one_backend(
    xfw: XFW,
    protocol: str,
    ip_version: str,
    server: RegularKernelSocketNetworkStateful,
    client: RegularKernelSocketNetworkStateful,
    server_cloner,
    client_cloner,
):
    extra_server = server_cloner(cloner=server, amount=1)[0]
    extra_client = client_cloner(cloner=client, amount=1)[0]
    extra_client.remote_ip = extra_server.ip
    extra_client.remote_port = extra_server.port

    await server.start()
    await extra_server.start()
    await client.start()
    await extra_client.start()

    await xfw.rules_set(f"""
        xfw {{
            defaults {{ dst: allow; }}
            dst {ip_version}.{protocol} : block {{
                {server.ip_testing}:{server.port}
            }}
        }}
        """)

    assert await check_connection(client, server) is False
    assert await check_connection(extra_client, extra_server) is True
```

## xFW metrics and kernel SYN cookies

`metrics_diff` and `syncookies_kern_stats_diff` give counter deltas for the code inside `async with`.

```python
import random

from framework.asyn import TcpRawClient, TcpServer
from framework.utils import compare_metrics_diff
from framework.xfw import XFW

XFW_STATS = [
    "xfw_syncookie_generated_packets",
    "xfw_syncookie_received_packets",
    "xfw_syncookie_failed_packets",
]
KERN_STATS = ["SyncookieSent", "SyncookieRecv", "SyncookieFailed"]


async def test_syncookie_metrics(
    xfw: XFW,
    tcp_server: TcpServer,
    tcp_raw_client: TcpRawClient,
    start_tcp_server_and_raw_clients,
):
    await xfw.rules_set("xfw { tcp_syncookies flood_timer=2 passive_timer=3; }")
    tcp_raw_client.port = random.randrange(1, 65000)

    async with (
        xfw.metrics_diff(XFW_STATS, wait_softirq=True) as diff,
        xfw.syncookies_kern_stats_diff() as kern_diff,
    ):
        assert await tcp_raw_client.handshake() is True

    invalid_xfw = compare_metrics_diff(
        compare_metrics=XFW_STATS,
        all_metrics=diff,
        diff_metrics={
            "xfw_syncookie_generated_packets": 1,
            "xfw_syncookie_received_packets": 1,
            "xfw_syncookie_failed_packets": 0,
        },
    )
    invalid_kern = compare_metrics_diff(
        compare_metrics=KERN_STATS,
        all_metrics=kern_diff,
        diff_metrics={
            "SyncookieSent": 0,
            "SyncookieRecv": 1,
            "SyncookieFailed": 0,
        },
    )
    assert invalid_xfw == [], f"xFW metrics: {invalid_xfw}"
    assert invalid_kern == [], f"kernel metrics: {invalid_kern}"
```
