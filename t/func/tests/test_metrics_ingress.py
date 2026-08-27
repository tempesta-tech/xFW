# SPDX-FileCopyrightText: (c) 2026 Tempesta Technologies, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later
import asyncio
from contextlib import asynccontextmanager

import pytest
from scapy.data import ETH_P_ARP
from scapy.layers.l2 import ARP, Ether

from framework.utils import compare_metrics_diff
from framework.xfw import XFW


@pytest.fixture
def ingress_total_metrics_counters() -> list[str]:
    return [
        "xfw_ip4_total_ingress_packets",
        "xfw_ip4_total_ingress_bytes",
        "xfw_ip6_total_ingress_packets",
        "xfw_ip6_total_ingress_bytes",
        "xfw_tcp_total_ingress_packets",
        "xfw_tcp_total_ingress_bytes",
        "xfw_udp_total_ingress_packets",
        "xfw_udp_total_ingress_bytes",
    ]


@pytest.fixture
def ingress_downstream_metrics_counters() -> list[str]:
    return [
        "xfw_total_downstream_ingress_packets",
        "xfw_total_downstream_ingress_bytes",
        "xfw_passed_downstream_ingress_packets",
        "xfw_passed_downstream_ingress_bytes",
    ]


@pytest.fixture
def ingress_gre_metrics_counters() -> list[str]:
    return [
        "xfw_gre_ingress_packets",
        "xfw_gre_ingress_bytes",
    ]


@pytest.fixture
def ingress_icmp_metrics_counters() -> list[str]:
    return [
        "xfw_icmp_total_ingress_packets",
        "xfw_icmp_total_ingress_bytes",
    ]


@pytest.fixture
def pre_load_metrics_counters() -> list[str]:
    """
    Need to compare only metrics from the list to prevent comparing egress metrics.
    Egress traffic is accounted even if no rules are loaded.
    """
    return [
        "xfw_arp_ingress_packets",
        "xfw_arp_ingress_bytes",
        "xfw_preload_ingress_packets",
        "xfw_preload_ingress_bytes",
    ]


def get_expected_total_ingress_counters(
    packets_n: int, protocol: str, ip_version: str
) -> dict[str, int | list[int]]:
    match protocol, ip_version:
        case "tcp", "ip4":
            packets_n, bytes_n = 10, 710
        case "tcp", "ip6":
            packets_n, bytes_n = 10, 910
        case "udp", "ip4":
            packets_n, bytes_n = 10, 470
        case "udp", "ip6":
            packets_n, bytes_n = [10, 13], [670, 900]

    return {
        f"xfw_{ip_version}_total_ingress_packets": packets_n,
        f"xfw_{ip_version}_total_ingress_bytes": bytes_n,
        f"xfw_{protocol}_total_ingress_packets": packets_n,
        f"xfw_{protocol}_total_ingress_bytes": bytes_n,
    }


async def test_total_ingress_metrics(
    protocol,
    ip_version,
    ingress_total_metrics_counters,
    xfw,
    server,
    client,
    client_cloner,
    flush_arp_cache,
):
    packets_n = 10
    client_2 = client_cloner(cloner=client, amount=1)[0]

    await server.start()
    await client.start()
    await client_2.start()

    await xfw.rules_set("xfw {}")

    async with xfw.metrics_diff(ingress_total_metrics_counters) as diff:
        await asyncio.gather(
            *[client.ping() for _ in range(int(packets_n / 2))]
            + [client_2.ping() for _ in range(int(packets_n / 2))]
        )

    invalid_metrics = compare_metrics_diff(
        compare_metrics=ingress_total_metrics_counters,
        all_metrics=diff,
        diff_metrics=get_expected_total_ingress_counters(packets_n, protocol, ip_version),
    )

    assert invalid_metrics == [], f"Some metrics are different: {invalid_metrics}"


async def test_downstream_ingress_metrics(
    ingress_downstream_metrics_counters,
    xfw,
    tcp_ip4_client,
    tcp_ip4_server,
    client_cloner,
    flush_arp_cache,
):
    packets_n = 10
    client_2 = client_cloner(cloner=tcp_ip4_client, amount=1)[0]

    await tcp_ip4_server.start()
    await tcp_ip4_client.start()
    await client_2.start()

    await xfw.rules_set("xfw {}")

    async with xfw.metrics_diff(ingress_downstream_metrics_counters) as diff:
        await asyncio.gather(
            *[tcp_ip4_client.ping() for _ in range(int(packets_n / 2))]
            + [client_2.ping() for _ in range(int(packets_n / 2))]
        )

    invalid_metrics = compare_metrics_diff(
        compare_metrics=ingress_downstream_metrics_counters,
        all_metrics=diff,
        diff_metrics={
            "xfw_total_downstream_ingress_packets": packets_n,
            "xfw_total_downstream_ingress_bytes": 710,
            "xfw_passed_downstream_ingress_packets": packets_n,
            "xfw_passed_downstream_ingress_bytes": 710,
        },
    )

    assert invalid_metrics == [], f"Some metrics are different: {invalid_metrics}"


async def test_gre_ingress_metrics(
    ingress_gre_metrics_counters,
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

    async with xfw.metrics_diff(ingress_gre_metrics_counters) as diff:
        await asyncio.gather(
            *[gre_raw_client.ping() for _ in range(int(packets_n / 2))]
            + [client_2.ping() for _ in range(int(packets_n / 2))]
        )

    invalid_metrics = compare_metrics_diff(
        compare_metrics=ingress_gre_metrics_counters,
        all_metrics=diff,
        diff_metrics={
            "xfw_gre_ingress_packets": packets_n,
            "xfw_gre_ingress_bytes": 430 if ip_version == "ip4" else 630,
        },
    )

    assert invalid_metrics == [], f"Some metrics are different: {invalid_metrics}"


async def test_icmp_ingress_metrics(
    ingress_icmp_metrics_counters,
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

    async with xfw.metrics_diff(ingress_icmp_metrics_counters) as diff:
        await asyncio.gather(
            *[icmp_raw_client.ping() for _ in range(int(packets_n / 2))]
            + [client_2.ping() for _ in range(int(packets_n / 2))]
        )

    invalid_metrics = compare_metrics_diff(
        compare_metrics=ingress_icmp_metrics_counters,
        all_metrics=diff,
        diff_metrics={
            "xfw_icmp_total_ingress_packets": packets_n if ip_version == "ip4" else [10, 13],
            "xfw_icmp_total_ingress_bytes": 420 if ip_version == "ip4" else [620, 900],
        },
    )

    assert invalid_metrics == [], f"Some metrics are different: {invalid_metrics}"


async def test_ingress_preload_metrics(
    pre_load_metrics_counters: list[str],
    xfw,
    udp_ip4_client,
    udp_ip4_server,
    flush_arp_cache,
):
    await udp_ip4_server.start()
    await udp_ip4_client.start()

    async with xfw.metrics_diff(pre_load_metrics_counters) as diff:
        await asyncio.gather(*[udp_ip4_client.ping() for _ in range(10)])

    invalid_metrics = compare_metrics_diff(
        compare_metrics=pre_load_metrics_counters,
        all_metrics=diff,
        diff_metrics=dict(xfw_preload_ingress_packets=11, xfw_preload_ingress_bytes=512),
        strict=True,
    )

    assert invalid_metrics == [], f"Some metrics are different: {invalid_metrics}"


async def test_arp_ingress_metrics(
    pre_load_metrics_counters,
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

    async with xfw.metrics_diff(pre_load_metrics_counters) as diff:
        await asyncio.gather(
            *[ether_raw_client.send_packet(packet / arp_part) for _ in range(packets_n)]
        )

    invalid_metrics = compare_metrics_diff(
        compare_metrics=pre_load_metrics_counters,
        all_metrics=diff,
        diff_metrics={"xfw_arp_ingress_packets": packets_n, "xfw_arp_ingress_bytes": bytes_n},
    )

    assert invalid_metrics == [], f"Some metrics are different: {invalid_metrics}"
