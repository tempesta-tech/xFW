# SPDX-FileCopyrightText: (c) 2026 Tempesta Technologies, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later

import asyncio

import pytest
from scapy.layers.inet import TCP

from framework.asyn import TcpRawClient, TcpRawServer
from framework.utils import compare_metrics_diff
from framework.xfw import XFW


@pytest.fixture
def stats_counters() -> list[str]:
    return [
        "xfw_tcp_auth_failed_packets",
        "xfw_tcp_auth_failed_bytes",
        "xfw_tcp_auth_timeout_packets",
        "xfw_tcp_auth_timeout_bytes",
    ]


@pytest.mark.parametrize(
    "protocol, counters",
    [
        pytest.param(
            "ip4",
            dict(xfw_tcp_auth_failed_packets=10, xfw_tcp_auth_failed_bytes=540),
            id="ip4-non-existing-connection",
            marks=pytest.mark.skip("ISSUE: 40 (xFW)"),
        ),
        pytest.param(
            "ip6",
            dict(xfw_tcp_auth_failed_packets=10, xfw_tcp_auth_failed_bytes=740),
            id="ip6-non-existing-connection",
            marks=pytest.mark.skip("ISSUE: 40 (xFW)"),
        ),
    ],
)
async def test_block_non_existing_session(
    protocol: str,
    counters: dict[str, int],
    stats_counters: list[str],
    xfw: XFW,
    tcp_ip4_raw_client: TcpRawClient,
    tcp_ip6_raw_server: TcpRawServer,
    tcp_ip6_raw_client: TcpRawClient,
    client_cloner,
):
    client: TcpRawClient = locals().get(f"tcp_{protocol}_raw_client")
    client.auto_ack_seq = False
    client_2 = client_cloner(cloner=client, amount=1)[0]
    client_2.auto_ack_seq = False

    await client.start()
    await client_2.start()

    await xfw.rules_set("xfw { tcp_auth_filter; }")

    async with xfw.metrics_diff(stats_counters) as diff:
        await asyncio.gather(
            *[client.send_packet(TCP(flags="A")) for i in range(5)]
            + [client_2.send_packet(TCP(flags="A")) for i in range(5)]
        )

    invalid_metrics = compare_metrics_diff(
        compare_metrics=stats_counters, all_metrics=diff, diff_metrics=counters
    )

    await client.stop()
    await client_2.stop()

    assert invalid_metrics == [], f"Some metrics are different: {invalid_metrics}"
