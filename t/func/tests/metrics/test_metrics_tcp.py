# SPDX-FileCopyrightText: (c) 2026 Tempesta Technologies, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later
import asyncio

from scapy.layers.inet import TCP

from framework.metrics import PrometheusMetricsDiff


def get_expected_tcp_metrics(packets_n: int, ip_version: str) -> PrometheusMetricsDiff:
    # IPv4: 14 (eth) + 20 (IPv4) + 20 (TCP)
    # IPv6: 14 (eth) + 40 (IPv6) + 20 (TCP)
    packet_size = 54 if ip_version == "ip4" else 74
    return PrometheusMetricsDiff(
        xfw_syn_packets=packets_n,
        xfw_syn_bytes=packets_n * packet_size,
        xfw_ack_packets=packets_n,
        xfw_ack_bytes=packets_n * packet_size,
        xfw_synack_packets=packets_n,
        xfw_synack_bytes=packets_n * packet_size,
        xfw_fin_packets=packets_n,
        xfw_fin_bytes=packets_n * packet_size,
        xfw_rst_packets=packets_n,
        xfw_rst_bytes=packets_n * packet_size,
    )


async def test_tcp_metrics(
    metric_analyzer,
    ip_version,
    xfw,
    tcp_raw_client,
    tcp_raw_server,
    client_cloner,
    flush_arp_cache,
):
    packets_n = 10

    await tcp_raw_server.start()
    await tcp_raw_client.start()

    await xfw.rules_set("xfw {}")

    async with metric_analyzer.expected_metrics_diff(
        xfw, get_expected_tcp_metrics(packets_n, ip_version)
    ):
        await asyncio.gather(
            *[tcp_raw_client.send_packet(TCP(flags="S")) for _ in range(packets_n)]
        )
        await asyncio.gather(
            *[tcp_raw_client.send_packet(TCP(flags="A")) for _ in range(packets_n)]
        )
        await asyncio.gather(
            *[tcp_raw_client.send_packet(TCP(flags="SA")) for _ in range(packets_n)]
        )
        await asyncio.gather(
            *[tcp_raw_client.send_packet(TCP(flags="F")) for _ in range(packets_n)]
        )
        await asyncio.gather(
            *[tcp_raw_client.send_packet(TCP(flags="R")) for _ in range(packets_n)]
        )
        await asyncio.gather(*[tcp_raw_server.receive_packet() for _ in range(packets_n * 5)])
