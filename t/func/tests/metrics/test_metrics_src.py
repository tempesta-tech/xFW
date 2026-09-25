# SPDX-FileCopyrightText: (c) 2026 Tempesta Technologies, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later

import asyncio

import pytest
from scapy.layers.inet import TCP, UDP
from scapy.packet import Raw

from framework.asyn import (
    TcpIpV4RawClient,
    TcpIpV6RawClient,
    UdpIpV4RawClient,
    UdpIpV6RawClient,
)
from framework.metrics import PrometheusMetricsDiff
from framework.xfw import XFW


def _get_expected_bytes_n(packets_n: int, protocol: str, ip_version: str) -> int:
    match protocol, ip_version:
        case "tcp", "ip4":
            return 59 * packets_n
        case "tcp", "ip6":
            return 79 * packets_n
        case "udp", "ip4":
            return 47 * packets_n
        case "udp", "ip6":
            return 67 * packets_n
        case _:
            raise ValueError(f"Unsupported protocol/ip combo: {protocol}, {ip_version}")


def _make_packet(protocol: str, sport: int, dport: int) -> int:
    if protocol == "tcp":
        return TCP(
            sport=sport,
            dport=dport,
            flags="S",
            seq=1122421,
            window=65535,
        ) / Raw(b"ping\n")

    return UDP() / Raw(b"ping\n")


async def test_src_ip(
    metric_analyzer,
    ip_version,
    protocol,
    xfw: XFW,
    server,
    udp_ip4_raw_client: UdpIpV4RawClient,
    udp_ip6_raw_client: UdpIpV6RawClient,
    tcp_ip4_raw_client: TcpIpV4RawClient,
    tcp_ip6_raw_client: TcpIpV6RawClient,
    client_cloner,
    flush_arp_cache,
):
    packets_n = 10
    bytes_n = _get_expected_bytes_n(packets_n, protocol, ip_version)
    client = locals()[f"{protocol}_{ip_version}_raw_client"]
    client_2 = client_cloner(cloner=client, amount=1)[0]

    packet = _make_packet(protocol, client.port, server.port)
    packet_2 = _make_packet(protocol, client_2.port, server.port)

    await server.start()
    await client.start()
    await client_2.start()

    """
    Hack to trigger neighbor discovery on IPv6 before setting rules for xFW. This prevents account
    NDP ICMP packets into xfw_src_ip_allowed_packets.
    """
    if ip_version == "ip6":
        await client.send_packet(packet)
        await client_2.send_packet(packet)

    await xfw.rules_set(
        f"xfw {{ src {ip_version}.{protocol}: allow {{ {client.ip_testing}, {client_2.ip_testing} }} }}"
    )

    async with metric_analyzer.expected_metrics_diff(
        xfw,
        expected_metrics=PrometheusMetricsDiff(
            xfw_src_ip_allowed_packets=packets_n,
            xfw_src_ip_allowed_bytes=bytes_n,
        ),
    ):
        await asyncio.gather(
            *[client.send_packet(packet) for _ in range(int(packets_n / 2))]
            + [client_2.send_packet(packet_2) for _ in range(int(packets_n / 2))]
        )
        await asyncio.gather(*[server.receive_message() for _ in range(packets_n)])


async def test_src_port(
    metric_analyzer,
    ip_version,
    protocol,
    xfw: XFW,
    server,
    udp_ip4_raw_client: UdpIpV4RawClient,
    udp_ip6_raw_client: UdpIpV6RawClient,
    tcp_ip4_raw_client: TcpIpV4RawClient,
    tcp_ip6_raw_client: TcpIpV6RawClient,
    client_cloner,
):
    packets_n = 10
    bytes_n = _get_expected_bytes_n(packets_n, protocol, ip_version)
    client = locals()[f"{protocol}_{ip_version}_raw_client"]
    client_2 = client_cloner(cloner=client, amount=1)[0]

    packet = _make_packet(protocol, client.port, server.port)
    packet_2 = _make_packet(protocol, client_2.port, server.port)

    await server.start()
    await client.start()
    await client_2.start()

    await xfw.rules_set(
        f"xfw {{ src {ip_version}.{protocol}: allow {{ :{client.port}, :{client_2.port} }} }}"
    )

    async with metric_analyzer.expected_metrics_diff(
        xfw,
        expected_metrics=PrometheusMetricsDiff(
            xfw_src_port_allowed_packets=packets_n,
            xfw_src_port_allowed_bytes=bytes_n,
        ),
    ):
        await asyncio.gather(
            *[client.send_packet(packet) for _ in range(int(packets_n / 2))]
            + [client_2.send_packet(packet_2) for _ in range(int(packets_n / 2))]
        )
        await asyncio.gather(*[server.receive_message() for _ in range(packets_n)])
