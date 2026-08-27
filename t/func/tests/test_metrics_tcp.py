# SPDX-FileCopyrightText: (c) 2026 Tempesta Technologies, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later
import asyncio

import pytest
from scapy.layers.inet import TCP

from framework.utils import compare_metrics_diff


@pytest.fixture
def tcp_metrics() -> list[str]:
    return [
        "xfw_syn_packets",
        "xfw_syn_bytes",
        "xfw_ack_packets",
        "xfw_ack_bytes",
        "xfw_synack_packets",
        "xfw_synack_bytes",
        "xfw_fin_packets",
        "xfw_fin_bytes",
        "xfw_rst_packets",
        "xfw_rst_bytes",
    ]


def get_expected_tcp_metrics(packets_n: int, ip_version: str) -> dict[str, int]:
    # IPv4: 14 (eth) + 20 (IPv4) + 20 (TCP)
    # IPv6: 14 (eth) + 40 (IPv6) + 20 (TCP)
    packet_size = 54 if ip_version == "ip4" else 74
    return {
        "xfw_syn_packets": packets_n,
        "xfw_syn_bytes": packet_size * packets_n,
        "xfw_ack_packets": packets_n,
        "xfw_ack_bytes": packet_size * packets_n,
        "xfw_synack_packets": packets_n,
        "xfw_synack_bytes": packet_size * packets_n,
        "xfw_fin_packets": packets_n,
        "xfw_fin_bytes": packet_size * packets_n,
        "xfw_rst_packets": packets_n,
        "xfw_rst_bytes": packet_size * packets_n,
    }


async def test_tcp_metrics(
    tcp_metrics, ip_version, xfw, tcp_raw_client, tcp_raw_server, client_cloner, flush_arp_cache
):
    packets_n = 10

    await tcp_raw_server.start()
    await tcp_raw_client.start()

    await xfw.rules_set("xfw {}")

    async with xfw.metrics_diff(tcp_metrics) as diff:
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

    invalid_metrics = compare_metrics_diff(
        compare_metrics=tcp_metrics,
        all_metrics=diff,
        diff_metrics=get_expected_tcp_metrics(packets_n, ip_version),
    )

    assert invalid_metrics == [], f"Some metrics are different: {invalid_metrics}"
