# SPDX-FileCopyrightText: (c) 2026 Tempesta Technologies, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later

import asyncio
import pytest

from framework.utils import compare_metrics_diff, client_cloner
from framework.asyn import (
    UdpIpV4RawClient,
    UdpIpV6RawClient,
    UdpV4Server,
    UdpV6Server, UdpRawClient
)
from framework.xfw import XFW


@pytest.fixture
def stats_counters() -> list[str]:
    return [
        'xfw_udp_anom_zero_port_packets',
        'xfw_udp_anom_zero_port_bytes',
    ]


@pytest.mark.parametrize(
    'protocol, counters',
    [
        pytest.param(
            'ip4',
            dict(
                xfw_udp_anom_zero_port_packets=10,
                xfw_udp_anom_zero_port_bytes=460
            ),
            id='ip4-zero-port',
        ),
        pytest.param(
            'ip6',
            dict(
                xfw_udp_anom_zero_port_packets=10,
                xfw_udp_anom_zero_port_bytes=660
            ),
            id='ip6-zero-port',
        ),
    ]
)
async def test_zero_port(
        protocol: str,
        counters: dict[str, int],
        stats_counters: list[str],
        xfw: XFW,
        udp_ip4_server: UdpV4Server,
        udp_ip6_server: UdpV6Server,
        udp_ip4_raw_client: UdpIpV4RawClient,
        udp_ip6_raw_client: UdpIpV6RawClient,
):
    server = locals().get(f'udp_{protocol}_server')
    client: UdpRawClient = locals().get(f'udp_{protocol}_raw_client')
    client_2: UdpRawClient = client_cloner(client=client, amount=1)[0]

    await server.start()
    await client.start()
    await client_2.start()

    client.remote_port = 0
    client_2.remote_port = 0

    await xfw.rules_set('xfw { tcp_anomaly_filter; }')

    async with xfw.metrics_diff(stats_counters) as diff:
        await asyncio.gather(*[
            client.ping() for _ in range(5)
        ] + [
            client_2.ping() for _ in range(5)
        ])

    invalid_metrics = compare_metrics_diff(
        compare_metrics=stats_counters,
        all_metrics=diff,
        diff_metrics=counters
    )

    await client.stop()
    await client_2.stop()
    await server.stop()

    assert invalid_metrics == [], \
        f'Some metrics are different: {invalid_metrics}'
