# SPDX-FileCopyrightText: (c) 2026 Tempesta Technologies, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later

import asyncio

import pytest
from scapy.layers.inet import TCP

from framework.asyn import TcpRawClient, TcpServer, UdpClient, UdpServer
from framework.utils import compare_metrics_diff
from framework.xfw import XFW


@pytest.fixture
def dst_stats_counters() -> list[str]:
    return [
        "xfw_dst_blocked_packets",
        "xfw_dst_blocked_bytes",
        "xfw_dst_rate_limited_packets",
        "xfw_dst_rate_limited_bytes",
    ]


@pytest.mark.parametrize(
    "rule,ip,counters",
    [
        pytest.param(
            "xfw {{ dst ip4.udp: block {{ {host}:{port}  }} }}",
            "ip4",
            dict(
                xfw_dst_blocked_packets=10,
                xfw_dst_blocked_bytes=480,
            ),
            id="ip4-block-udp",
            marks=pytest.mark.skip("ISSUE: 40 (xFW)"),
        ),
        pytest.param(
            "xfw {{ dst ip6.udp: block {{ {host}:{port}  }} }}",
            "ip6",
            dict(
                xfw_dst_blocked_packets=10,
                xfw_dst_blocked_bytes=680,
            ),
            id="ip6-block-udp",
            marks=pytest.mark.skip("ISSUE: 40 (xFW)"),
        ),
        pytest.param(
            "xfw {{ ratelimit=test pps=0 bps=0; dst ip4.udp: ratelimit=test {{ {host}:{port}  }} }}",
            "ip4",
            dict(
                xfw_dst_rate_limited_packets=10,
                xfw_dst_rate_limited_bytes=480,
            ),
            id="ip4-ratelimit-udp",
            marks=pytest.mark.skip("ISSUE: 40 (xFW)"),
        ),
        pytest.param(
            "xfw {{ ratelimit=test pps=0 bps=0; dst ip6.udp: ratelimit=test {{ {host}:{port}  }} }}",
            "ip6",
            dict(
                xfw_dst_rate_limited_packets=10,
                xfw_dst_rate_limited_bytes=680,
            ),
            id="ip6-ratelimit-udp",
            marks=pytest.mark.skip("ISSUE: 40 (xFW)"),
        ),
    ],
)
async def test_dst_udp_stats(
    rule: str,
    ip: str,
    counters: dict[str, int],
    dst_stats_counters: list[str],
    xfw: XFW,
    udp_ip4_server: UdpServer,
    udp_ip6_server: UdpServer,
    udp_ip4_client: UdpClient,
    udp_ip6_client: UdpClient,
    client_cloner,
):
    server = locals().get(f"udp_{ip}_server")
    client = locals().get(f"udp_{ip}_client")
    client_2 = client_cloner(cloner=client, amount=1)[0]

    await server.start()
    await client.start()
    await client_2.start()

    await xfw.rules_set(rule.format(host=server.ip_testing, port=server.port))

    async with xfw.metrics_diff(dst_stats_counters) as diff:
        await asyncio.gather(
            *[client.send_message(f"12345{i}") for i in range(5)]
            + [client_2.send_message(f"12345{i}") for i in range(5)]
        )

    invalid_metrics = compare_metrics_diff(
        compare_metrics=dst_stats_counters, all_metrics=diff, diff_metrics=counters
    )

    await client.stop()
    await client_2.stop()
    await server.stop()

    assert invalid_metrics == [], f"Some metrics are different: {invalid_metrics}"


@pytest.mark.parametrize(
    "rule,ip,counters",
    [
        pytest.param(
            "xfw {{ dst ip4.tcp: block {{ {host}:{port}  }} }}",
            "ip4",
            dict(
                xfw_dst_blocked_packets=10,
                xfw_dst_blocked_bytes=610,
            ),
            id="ip4-block-tcp",
            marks=pytest.mark.skip("ISSUE: 40 (xFW)"),
        ),
        pytest.param(
            "xfw {{ dst ip6.tcp: block {{ {host}:{port}  }} }}",
            "ip6",
            dict(
                xfw_dst_blocked_packets=10,
                xfw_dst_blocked_bytes=810,
            ),
            id="ip6-block-tcp",
            marks=pytest.mark.skip("ISSUE: 40 (xFW)"),
        ),
        pytest.param(
            "xfw {{ ratelimit=test pps=0 bps=0; dst ip4.tcp: ratelimit=test {{ {host}:{port}  }} }}",
            "ip4",
            dict(
                xfw_dst_rate_limited_packets=10,
                xfw_dst_rate_limited_bytes=610,
            ),
            id="ip4-ratelimit-tcp",
            marks=pytest.mark.skip("ISSUE: 40 (xFW)"),
        ),
        pytest.param(
            "xfw {{ ratelimit=test pps=0 bps=0; dst ip6.tcp: ratelimit=test {{ {host}:{port}  }} }}",
            "ip6",
            dict(
                xfw_dst_rate_limited_packets=10,
                xfw_dst_rate_limited_bytes=810,
            ),
            id="ip6-ratelimit-tcp",
            marks=pytest.mark.skip("ISSUE: 40 (xFW)"),
        ),
    ],
)
async def test_dst_tcp_stats(
    rule: str,
    ip: str,
    counters: dict[str, int],
    dst_stats_counters: list[str],
    xfw: XFW,
    tcp_ip4_server: TcpServer,
    tcp_ip6_server: TcpServer,
    tcp_ip4_raw_client: TcpRawClient,
    tcp_ip6_raw_client: TcpRawClient,
    client_cloner,
):
    """
    We have to use in this test TcpRawSocket because
    it prevents sending of duplicated TCP packets.

    The kernel retries to send packet if it was not
    delivered
    """
    server: TcpServer = locals().get(f"tcp_{ip}_server")
    client: TcpRawClient = locals().get(f"tcp_{ip}_raw_client")
    client_2: TcpRawClient = client_cloner(cloner=client, amount=1)[0]

    await server.start()
    await client.start()
    await client_2.start()

    await xfw.rules_set(rule.format(host=server.ip_testing, port=server.port))

    async with xfw.metrics_diff(dst_stats_counters, wait_softirq=True) as diff:
        await asyncio.gather(
            *[
                client.send_packet(TCP(flags="PA", seq=22211) / f"012345{i}".encode())
                for i in range(5)
            ]
            + [
                client_2.send_packet(TCP(flags="PA", seq=32211) / f"012345{i}".encode())
                for i in range(5)
            ]
        )

    invalid_metrics = compare_metrics_diff(
        compare_metrics=dst_stats_counters, all_metrics=diff, diff_metrics=counters
    )

    await client.stop()
    await client_2.stop()
    await server.stop()

    assert invalid_metrics == [], f"Some metrics are different: {invalid_metrics}"
