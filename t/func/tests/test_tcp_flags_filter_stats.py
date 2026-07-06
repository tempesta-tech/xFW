# SPDX-FileCopyrightText: (c) 2026 Tempesta Technologies, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later

import asyncio

import pytest

from framework.asyn import (
    TcpIpV4RawClient,
    TcpIpV4RawServer,
    TcpIpV6RawClient,
    TcpIpV6RawServer,
)
from framework.utils import compare_metrics_diff
from framework.xfw import XFW


@pytest.fixture
def stats_counters() -> list[str]:
    return [
        "xfw_syn_rate_limited_packets",
        "xfw_syn_rate_limited_bytes",
        "xfw_rst_rate_limited_packets",
        "xfw_rst_rate_limited_bytes",
    ]


@pytest.mark.parametrize(
    "rule,protocol,flag,counters",
    [
        pytest.param(
            "xfw { ratelimit=test pps=0 bps=0; tcp_flags syn : ratelimit=test; }",
            "ip4",
            "S",
            dict(
                xfw_syn_rate_limited_packets=10,
                xfw_syn_rate_limited_bytes=740,
            ),
            id="ip4-syn",
            marks=pytest.mark.skip("ISSUE: 332"),
        ),
        pytest.param(
            "xfw { ratelimit=test pps=0 bps=0; tcp_flags syn : ratelimit=test; }",
            "ip6",
            "S",
            dict(
                xfw_syn_rate_limited_packets=10,
                xfw_syn_rate_limited_bytes=940,
            ),
            id="ip6-syn",
            marks=pytest.mark.skip("ISSUE: 332"),
        ),
        pytest.param(
            "xfw { ratelimit=test pps=0 bps=0; tcp_flags rst : ratelimit=test; }",
            "ip4",
            "R",
            dict(
                xfw_rst_rate_limited_packets=10,
                xfw_rst_rate_limited_bytes=740,
            ),
            id="ip4-rst",
            marks=pytest.mark.skip("ISSUE: 332"),
        ),
        pytest.param(
            "xfw { ratelimit=test pps=0 bps=0; tcp_flags rst : ratelimit=test; }",
            "ip6",
            "R",
            dict(
                xfw_rst_rate_limited_packets=10,
                xfw_rst_rate_limited_bytes=940,
            ),
            id="ip6-rst",
            marks=pytest.mark.skip("ISSUE: 332"),
        ),
    ],
)
async def test_tcp_flags_filter_stats(
    rule: str,
    protocol: str,
    flag: str,
    counters: dict[str, int],
    stats_counters: list[str],
    xfw: XFW,
    tcp_ip4_raw_server: TcpIpV4RawServer,
    tcp_ip6_raw_server: TcpIpV6RawServer,
    tcp_ip4_raw_client: TcpIpV4RawClient,
    tcp_ip6_raw_client: TcpIpV6RawClient,
    client_cloner,
):
    server = locals().get(f"tcp_{protocol}_raw_server")
    client = locals().get(f"tcp_{protocol}_raw_client")
    client.auto_ack_seq = False
    client_2 = client_cloner(cloner=client, amount=1)[0]
    client_2.auto_ack_seq = False

    await server.start()
    await client.start()
    await client_2.start()

    await xfw.rules_set(rule)

    packet = client.valid_syn_packet
    packet.flags = flag

    async with xfw.metrics_diff(stats_counters) as diff:
        await asyncio.gather(
            *[client.send(packet) for _ in range(5)] + [client_2.send(packet) for _ in range(5)]
        )

    invalid_metrics = compare_metrics_diff(
        compare_metrics=stats_counters, all_metrics=diff, diff_metrics=counters
    )

    await client.stop()
    await client_2.stop()
    await server.stop()

    assert invalid_metrics == [], f"Some metrics are different: {invalid_metrics}"
