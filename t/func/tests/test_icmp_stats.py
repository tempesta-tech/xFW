# SPDX-FileCopyrightText: (c) 2026 Tempesta Technologies, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later

import asyncio
import pytest

from framework.asyn import IcmpRawClient, UdpServer
from framework.xfw import XFW
from framework.utils import compare_metrics_diff, client_cloner


@pytest.fixture
def icmp_stats_counters() -> list[str]:
    return [
        'xfw_icmp_blocked_packets',
        'xfw_icmp_blocked_bytes',
        'xfw_icmp_rate_limited_packets',
        'xfw_icmp_rate_limited_bytes',
        'xfw_icmp_default_blocked_packets',
        'xfw_icmp_default_blocked_bytes',
        'xfw_icmp_default_rate_limited_packets',
        'xfw_icmp_default_rate_limited_bytes',
    ]


@pytest.mark.parametrize(
    'rule,protocol,counters',
    [
        pytest.param(
            'xfw { icmp ip4 : block {0, 8} }',
            'ip4',
            dict(
                xfw_icmp_blocked_packets=10,
                xfw_icmp_blocked_bytes=420,
            ),
            id='ip4-block'
        ),
        pytest.param(
            'xfw { icmp ip6 : block {128, 129} }',
            'ip6',
            dict(
                xfw_icmp_blocked_packets=[10, 13],
                xfw_icmp_blocked_bytes=[620, 900]
            ),
            id='ip6-block'
        ),
        pytest.param(
            'xfw { ratelimit=test pps=0 bps=0; icmp ip4 : ratelimit=test {0, 8} }',
            'ip4',
            dict(
                xfw_icmp_rate_limited_packets=10,
                xfw_icmp_rate_limited_bytes=420,
            ),
            id='ip4-ratelimit'
        ),
        pytest.param(
            'xfw { ratelimit=test pps=0 bps=0; icmp ip6 : ratelimit=test {128, 129} }',
            'ip6',
            dict(
                xfw_icmp_rate_limited_packets=[10, 13],
                xfw_icmp_rate_limited_bytes=[620, 900],
            ),
            id='ip6-ratelimit'
        ),
        pytest.param(
            'xfw { defaults { icmp ip4 : block; } }',
            'ip4',
            dict(
                xfw_icmp_default_blocked_packets=10,
                xfw_icmp_default_blocked_bytes=420,
            ),
            id='ip4-block-default'
        ),
        pytest.param(
            'xfw { defaults { icmp ip6 :  block; } }',
            'ip6',
            dict(
                xfw_icmp_default_blocked_packets=[10, 13],
                xfw_icmp_default_blocked_bytes=[620, 900],
            ),
            id='ip6-block-default'
        ),
        pytest.param(
            'xfw { ratelimit=test pps=0 bps=0; defaults { icmp ip4 : ratelimit=test; } }',
            'ip4',
            dict(
                xfw_icmp_default_rate_limited_packets=10,
                xfw_icmp_default_rate_limited_bytes=420,
            ),
            id='ip4-ratelimit-default'
        ),
        pytest.param(
            'xfw { ratelimit=test pps=0 bps=0; defaults { icmp ip6 : ratelimit=test; } }',
            'ip6',
            dict(
                xfw_icmp_default_rate_limited_packets=[10, 13],
                xfw_icmp_default_rate_limited_bytes=[620, 900],
            ),
            id='ip6-ratelimit-default'
        ),
    ],
)
async def test_icmp_stats(
        rule: str,
        protocol: str,
        counters: dict[str, int],
        icmp_stats_counters: list[str],
        xfw: XFW,
        udp_ip4_server: UdpServer,
        udp_ip6_server: UdpServer,
        icmp_ip4_raw_client: IcmpRawClient,
        icmp_ip6_raw_client: IcmpRawClient,
):
    """
    TODO: The IP6 tests have a diapason of values. The minimal
        values are exactly the expected results. BUT,
        sometimes we catch some foreign network packets.
        Probably, it could be solved with total network
        isolation.
    """
    await locals().get(f'udp_{protocol}_server').start()
    client = locals().get(f'icmp_{protocol}_raw_client')
    client_2 = client_cloner(client=client, amount=1)[0]

    await client.start()
    await client_2.start()

    await xfw.rules_set(rule)

    async with xfw.metrics_diff(icmp_stats_counters) as diff:
        await asyncio.gather(*[
            client.ping()
            for _ in range(5)
        ] + [
            client_2.ping()
            for _ in range(5)
        ])

    invalid_metrics = compare_metrics_diff(
        compare_metrics=icmp_stats_counters,
        all_metrics=diff,
        diff_metrics=counters
    )
    assert invalid_metrics == [], \
        f'Some metrics are different: {invalid_metrics}'
