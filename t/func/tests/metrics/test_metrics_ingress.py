# SPDX-FileCopyrightText: (c) 2026 Tempesta Technologies, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later
import asyncio

from scapy.data import ETH_P_ARP
from scapy.layers.l2 import ARP, Ether

from framework.metrics import PrometheusMetricsDiff
from tests.metrics.utils import make_l4_packet


def get_expected_total_ingress_counters(
    packets_n: int, protocol: str, ip_version: str
) -> PrometheusMetricsDiff:
    match protocol, ip_version:
        case "tcp", "ip4":
            # 14 (Eth) + 20 (IP) + 20 (TCP) + 5 (Raw)
            return PrometheusMetricsDiff(
                xfw_ip4_total_ingress_packets=packets_n,
                xfw_ip4_total_ingress_bytes=packets_n * 59,
                xfw_tcp_total_ingress_packets=packets_n,
                xfw_tcp_total_ingress_bytes=packets_n * 59,
            )

        case "tcp", "ip6":
            # 14 (Eth) + 40 (IP) + 20 (TCP) + 5 (Raw)
            return PrometheusMetricsDiff(
                xfw_ip6_total_ingress_packets=[packets_n, packets_n + 3],
                xfw_ip6_total_ingress_bytes=[packets_n * 79, 1112],
                xfw_tcp_total_ingress_packets=[packets_n, packets_n + 3],
                xfw_tcp_total_ingress_bytes=[packets_n * 79, (packets_n + 3) * 79],
            )

        case "udp", "ip4":
            # 14 (Eth) + 20 (IP) + 8 (UDP) + 5 (Raw)
            return PrometheusMetricsDiff(
                xfw_ip4_total_ingress_packets=packets_n,
                xfw_ip4_total_ingress_bytes=packets_n * 47,
                xfw_udp_total_ingress_packets=packets_n,
                xfw_udp_total_ingress_bytes=packets_n * 47,
            )

        case "udp", "ip6":
            # 14 (Eth) + 40 (IP) + 8 (UDP) + 5 (Raw)
            return PrometheusMetricsDiff(
                xfw_ip6_total_ingress_packets=[packets_n, packets_n + 3],
                xfw_ip6_total_ingress_bytes=[packets_n * 67, (packets_n + 3) * 67],
                xfw_udp_total_ingress_packets=[packets_n, packets_n + 3],
                xfw_udp_total_ingress_bytes=[packets_n * 67, (packets_n + 3) * 67],
            )

        case _:
            raise ValueError(f"Unsupported protocol/ip combo: {protocol}, {ip_version}")


async def test_total_ingress_metrics(
    protocol,
    ip_version,
    metric_analyzer,
    xfw,
    server,
    raw_l4_client,
    client_cloner,
    flush_arp_cache,
):
    packets_n = 10
    client = raw_l4_client
    client_2 = client_cloner(cloner=client, amount=1)[0]

    await server.start()
    await client.start()
    await client_2.start()

    await xfw.rules_set("xfw {}")

    packet = make_l4_packet(protocol, client.port, server.port)
    packet_2 = make_l4_packet(protocol, client_2.port, server.port)

    async with metric_analyzer.expected_metrics_diff(
        xfw=xfw,
        expected_metrics=get_expected_total_ingress_counters(packets_n, protocol, ip_version),
    ):
        await asyncio.gather(
            *[client.send_packet(packet) for _ in range(int(packets_n / 2))]
            + [client_2.send_packet(packet_2) for _ in range(int(packets_n / 2))]
        )
        await asyncio.gather(*[server.receive_message() for _ in range(packets_n)])


async def test_downstream_ingress_metrics(
    metric_analyzer,
    xfw,
    tcp_ip4_raw_client,
    tcp_ip4_server,
    client_cloner,
    flush_arp_cache,
):
    packets_n = 10
    client_2 = client_cloner(cloner=tcp_ip4_raw_client, amount=1)[0]

    await tcp_ip4_server.start()
    await tcp_ip4_raw_client.start()
    await client_2.start()

    await xfw.rules_set("xfw {}")

    expected_packets_n = [packets_n, packets_n + 3]
    expected_bytes_n = [packets_n * 71, (packets_n + 3) * 71]
    packet = tcp_ip4_raw_client.valid_syn_packet
    packet_2 = client_2.valid_syn_packet
    async with metric_analyzer.expected_metrics_diff(
        xfw=xfw,
        expected_metrics=PrometheusMetricsDiff(
            xfw_total_downstream_ingress_packets=expected_packets_n,
            xfw_total_downstream_ingress_bytes=expected_bytes_n,
            xfw_passed_downstream_ingress_packets=expected_packets_n,
            xfw_passed_downstream_ingress_bytes=expected_bytes_n,
        ),
    ):
        await asyncio.gather(
            *[tcp_ip4_raw_client.send_packet(packet) for _ in range(int(packets_n / 2))]
            + [client_2.send_packet(packet_2) for _ in range(int(packets_n / 2))]
        )
        await asyncio.gather(*[tcp_ip4_server.receive_message() for _ in range(packets_n)])


async def test_gre_ingress_metrics(
    metric_analyzer,
    ip_version,
    xfw,
    gre_raw_client,
    gre_raw_server,
    client_cloner,
    flush_arp_cache,
):
    packets_n = 10
    client_2 = client_cloner(cloner=gre_raw_client, amount=1)[0]

    await gre_raw_server.start()
    await gre_raw_client.start()
    await client_2.start()

    await xfw.rules_set("xfw { ip_proto { 47, 58 } }")

    async with metric_analyzer.expected_metrics_diff(
        xfw=xfw,
        expected_metrics=PrometheusMetricsDiff(
            xfw_gre_ingress_packets=packets_n,
            xfw_gre_ingress_bytes=packets_n * 43 if ip_version == "ip4" else packets_n * 63,
        ),
    ):
        await asyncio.gather(
            *[gre_raw_client.ping() for _ in range(int(packets_n / 2))]
            + [client_2.ping() for _ in range(int(packets_n / 2))]
        )
        await asyncio.gather(*[gre_raw_server.receive_packet() for _ in range(packets_n)])


async def test_icmp_ingress_metrics(
    metric_analyzer,
    ip_version,
    xfw,
    udp_server,
    icmp_raw_client,
    client_cloner,
):
    """
    TODO: The IP6 tests have a diapason of values. The minimal
        values are exactly the expected results. BUT,
        sometimes we catch some foreign network packets.
        Probably, it could be solved with total network
        isolation.
    """
    packets_n = 10
    client_2 = client_cloner(cloner=icmp_raw_client, amount=1)[0]

    await udp_server.start()
    await icmp_raw_client.start()
    await client_2.start()

    await xfw.rules_set("xfw {}")

    expected_bytes_n = packets_n * 42 if ip_version == "ip4" else packets_n * 62
    async with metric_analyzer.expected_metrics_diff(
        xfw=xfw,
        expected_metrics=PrometheusMetricsDiff(
            xfw_icmp_total_ingress_packets=[packets_n, None],
            xfw_icmp_total_ingress_bytes=[expected_bytes_n, None],
        ),
    ):
        await asyncio.gather(
            *[icmp_raw_client.ping() for _ in range(int(packets_n / 2))]
            + [client_2.ping() for _ in range(int(packets_n / 2))]
        )
        await asyncio.gather(*[udp_server.receive_message() for _ in range(packets_n)])


async def test_ingress_preload_metrics(
    metric_analyzer,
    xfw,
    udp_ip4_client,
    udp_ip4_server,
    flush_arp_cache,
):
    await xfw.restart()
    await udp_ip4_server.start()
    await udp_ip4_client.start()

    async with metric_analyzer.expected_metrics_diff(
        xfw=xfw,
        expected_metrics=PrometheusMetricsDiff(
            xfw_preload_ingress_packets=[10, 11],
            xfw_preload_ingress_bytes=[470, 512],
            xfw_arp_ingress_packets=0,
            xfw_arp_ingress_bytes=0,
        ),
    ):
        await asyncio.gather(*[udp_ip4_client.ping() for _ in range(10)])
        await asyncio.gather(*[udp_ip4_server.receive_message() for _ in range(10)])


async def test_arp_ingress_metrics(
    metric_analyzer,
    xfw,
    config,
    logging_level,
    ether_raw_client,
    ether_raw_server,
):
    """
    sizeof(ethhdr) = 14
    sizeof(arphdr) = 28
    bytes_n = (14 + 28) * packets_n
    """
    packets_n = 10
    bytes_n = 42 * packets_n

    await xfw.rules_set("xfw {}")

    await ether_raw_client.start()
    await ether_raw_server.start()

    src_mac, dst_mac = await asyncio.gather(
        ether_raw_client.get_mac_address(),
        ether_raw_server.get_mac_address(),
    )

    packet = Ether(dst=dst_mac, src=src_mac, type=ETH_P_ARP)
    arp_part = bytes(ARP(op=1, pdst=ether_raw_server.ip))

    async with metric_analyzer.expected_metrics_diff(
        xfw=xfw,
        expected_metrics=PrometheusMetricsDiff(
            xfw_preload_ingress_packets=0,
            xfw_preload_ingress_bytes=0,
            xfw_arp_ingress_packets=packets_n,
            xfw_arp_ingress_bytes=bytes_n,
        ),
    ):
        await asyncio.gather(
            *[ether_raw_client.send_packet(packet / arp_part) for _ in range(packets_n)]
        )
        await asyncio.gather(*[ether_raw_server.receive_packet() for _ in range(packets_n)])
