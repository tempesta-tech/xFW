# SPDX-FileCopyrightText: (c) 2026 Tempesta Technologies, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later

import asyncio

import pytest
from scapy.layers.inet import TCP

from framework.asyn import TcpRawClient, TcpServer, UdpClient, UdpServer
from framework.utils import compare_metrics_diff
from framework.xfw import XFW


@pytest.fixture
def src_stats_counters() -> list[str]:
    return [
        "xfw_src_ip_blocked_packets",
        "xfw_src_ip_blocked_bytes",
        "xfw_src_ip_rate_limited_packets",
        "xfw_src_ip_rate_limited_bytes",
        "xfw_src_ip_default_blocked_packets",
        "xfw_src_ip_default_blocked_bytes",
        "xfw_src_ip_default_rate_limited_packets",
        "xfw_src_ip_default_rate_limited_bytes",
        "xfw_src_port_blocked_packets",
        "xfw_src_port_blocked_bytes",
        "xfw_src_port_rate_limited_packets",
        "xfw_src_port_rate_limited_bytes",
        "xfw_src_port_default_blocked_packets",
        "xfw_src_port_default_blocked_bytes",
        "xfw_src_port_default_rate_limited_packets",
        "xfw_src_port_default_rate_limited_bytes",
    ]


@pytest.mark.parametrize(
    "rule,ip,counters",
    # udp ip
    [
        pytest.param(
            "xfw {{ src ip4.udp: block {{ {host}, {host_2} }} }}",
            "ip4",
            dict(
                xfw_src_ip_blocked_packets=10,
                xfw_src_ip_blocked_bytes=480,
            ),
            id="ip4-block-udp-ip",
        ),
        pytest.param(
            "xfw {{ src ip6.udp: block {{ {host}, {host_2} }} }}",
            "ip6",
            dict(
                xfw_src_ip_blocked_packets=10,
                xfw_src_ip_blocked_bytes=680,
            ),
            id="ip6-block-udp-ip",
        ),
        pytest.param(
            "xfw {{ ratelimit=test pps=0 bps=0; src ip4.udp: ratelimit=test {{ {host}, {host_2} }} }}",
            "ip4",
            dict(
                xfw_src_ip_rate_limited_packets=10,
                xfw_src_ip_rate_limited_bytes=480,
            ),
            id="ip4-ratelimit-udp-ip",
        ),
        pytest.param(
            "xfw {{ ratelimit=test pps=0 bps=0; src ip6.udp: ratelimit=test {{ {host}, {host_2} }} }}",
            "ip6",
            dict(
                xfw_src_ip_rate_limited_packets=10,
                xfw_src_ip_rate_limited_bytes=680,
            ),
            id="ip6-ratelimit-udp-ip",
        ),
        pytest.param(
            "xfw {{ defaults {{ src_ip ip4.udp: block; }} }}",
            "ip4",
            dict(
                xfw_src_ip_default_blocked_packets=10,
                xfw_src_ip_default_blocked_bytes=480,
            ),
            id="ip4-block-udp-ip-default",
        ),
        pytest.param(
            "xfw {{ defaults {{ src_ip ip6.udp: block; }} }}",
            "ip6",
            dict(
                xfw_src_ip_default_blocked_packets=10,
                xfw_src_ip_default_blocked_bytes=680,
            ),
            id="ip6-block-udp-ip-default",
        ),
        pytest.param(
            "xfw {{ ratelimit=test pps=0 bps=0; defaults {{ src_ip ip4.udp: ratelimit=test; }} }}",
            "ip4",
            dict(
                xfw_src_ip_default_rate_limited_packets=10,
                xfw_src_ip_default_rate_limited_bytes=480,
            ),
            id="ip4-ratelimit-udp-ip-default",
        ),
        pytest.param(
            "xfw {{ ratelimit=test pps=0 bps=0; defaults {{ src_ip ip6.udp: ratelimit=test; }} }}",
            "ip6",
            dict(
                xfw_src_ip_default_rate_limited_packets=10,
                xfw_src_ip_default_rate_limited_bytes=680,
            ),
            id="ip6-ratelimit-udp-ip-default",
        ),
    ]
    +
    # udp port
    [
        pytest.param(
            "xfw {{ src ip4.udp: block {{ :{port}, :{port_2} }} }}",
            "ip4",
            dict(
                xfw_src_port_blocked_packets=10,
                xfw_src_port_blocked_bytes=480,
            ),
            id="ip4-block-udp-port",
        ),
        pytest.param(
            "xfw {{ src ip6.udp: block {{ :{port}, :{port_2} }} }}",
            "ip6",
            dict(
                xfw_src_port_blocked_packets=10,
                xfw_src_port_blocked_bytes=680,
            ),
            id="ip6-block-udp-port",
        ),
        pytest.param(
            "xfw {{ ratelimit=test pps=0 bps=0; src ip4.udp: ratelimit=test {{ :{port}, :{port_2} }} }}",
            "ip4",
            dict(
                xfw_src_port_rate_limited_packets=10,
                xfw_src_port_rate_limited_bytes=480,
            ),
            id="ip4-ratelimit-udp-port",
        ),
        pytest.param(
            "xfw {{ ratelimit=test pps=0 bps=0; src ip6.udp: ratelimit=test {{ :{port}, :{port_2} }} }}",
            "ip6",
            dict(
                xfw_src_port_rate_limited_packets=10,
                xfw_src_port_rate_limited_bytes=680,
            ),
            id="ip6-ratelimit-udp-port",
        ),
        pytest.param(
            "xfw {{ defaults {{ src_port ip4.udp: block; }} }}",
            "ip4",
            dict(
                xfw_src_port_default_blocked_packets=10,
                xfw_src_port_default_blocked_bytes=480,
            ),
            id="ip4-block-udp-port-default",
        ),
        pytest.param(
            "xfw {{ defaults {{ src_port ip6.udp: block; }} }}",
            "ip6",
            dict(
                xfw_src_port_default_blocked_packets=10,
                xfw_src_port_default_blocked_bytes=680,
            ),
            id="ip6-block-udp-port-default",
        ),
        pytest.param(
            "xfw {{ ratelimit=test pps=0 bps=0; defaults {{ src_port ip4.udp: ratelimit=test; }} }}",
            "ip4",
            dict(
                xfw_src_port_default_rate_limited_packets=10,
                xfw_src_port_default_rate_limited_bytes=480,
            ),
            id="ip4-ratelimit-udp-port-default",
        ),
        pytest.param(
            "xfw {{ ratelimit=test pps=0 bps=0; defaults {{ src_port ip6.udp: ratelimit=test; }} }}",
            "ip6",
            dict(
                xfw_src_port_default_rate_limited_packets=10,
                xfw_src_port_default_rate_limited_bytes=680,
            ),
            id="ip6-ratelimit-udp-port-default",
        ),
    ],
)
async def test_src_udp_stats(
    rule: str,
    ip: str,
    counters: dict[str, int],
    src_stats_counters: list[str],
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

    await xfw.rules_set(
        rule.format(
            host=client.ip_testing,
            port=client.port,
            host_2=client_2.ip_testing,
            port_2=client_2.port,
        )
    )

    async with xfw.metrics_diff(src_stats_counters) as diff:
        await asyncio.gather(
            *[client.send(f"12345{i}") for i in range(5)]
            + [client_2.send(f"12345{i}") for i in range(5)]
        )

    invalid_metrics = compare_metrics_diff(
        compare_metrics=src_stats_counters, all_metrics=diff, diff_metrics=counters
    )

    await client.stop()
    await client_2.stop()
    await server.stop()

    assert invalid_metrics == [], f"Some metrics are different: {invalid_metrics}"


@pytest.mark.parametrize(
    "rule,ip,counters",
    # tcp ip
    [
        pytest.param(
            "xfw {{ src ip4.tcp: block {{ {host}, {host_2} }} }}",
            "ip4",
            dict(
                xfw_src_ip_blocked_packets=10,
                xfw_src_ip_blocked_bytes=610,
            ),
            id="ip4-block-tcp-ip",
        ),
        # tcp ip6 src filter blocks also ICMP6 packets, the results could be different
        pytest.param(
            """
            xfw {{ 
                icmp ip6: allow {{ 1, 2, 3, 4, 128, 129, 133, 134, 135, 136, 137, 143 }}
                src ip6.tcp: block {{ 
                    {host}, 
                    {host_2} 
                }}
            }}
            """,
            "ip6",
            dict(
                xfw_src_ip_blocked_packets=[3, 15],
                xfw_src_ip_blocked_bytes=[100, 1200],
            ),
            id="ip6-block-tcp-ip",
        ),
        pytest.param(
            "xfw {{ ratelimit=test pps=0 bps=0; src ip4.tcp: ratelimit=test {{ {host}, {host_2} }} }}",
            "ip4",
            dict(
                xfw_src_ip_rate_limited_packets=10,
                xfw_src_ip_rate_limited_bytes=610,
            ),
            id="ip4-ratelimit-tcp-ip",
        ),
        # tcp ip6 src filter blocks also ICMP6 packets, the results could be different
        pytest.param(
            """
            xfw {{ 
                defaults {{ icmp ip6: block; }}
                icmp ip6: allow {{ 0, 1, 2, 3, 4, 128, 129, 133, 134, 135, 136, 137, 143 }}
                ratelimit=test pps=0 bps=0; 
                src ip6.tcp: ratelimit=test {{ 
                    {host}, 
                    {host_2} 
                }} 
            }}
            """,
            "ip6",
            dict(
                xfw_src_ip_rate_limited_packets=[3, 15],
                xfw_src_ip_rate_limited_bytes=[100, 1200],
            ),
            id="ip6-ratelimit-tcp-ip",
        ),
        pytest.param(
            "xfw {{ defaults {{ src_ip ip4.tcp: block; }} }}",
            "ip4",
            dict(
                xfw_src_ip_default_blocked_packets=10,
                xfw_src_ip_default_blocked_bytes=610,
            ),
            id="ip4-block-tcp-ip-default",
        ),
        # tcp ip6 src filter blocks also ICMP6 packets, the results could be different
        pytest.param(
            """
            xfw {{ 
                defaults {{ 
                    src_ip ip6.tcp: block; 
                }} 
                icmp ip6: allow {{ 1, 2, 3, 4, 128, 129, 133, 134, 135, 136, 137, 143 }}
            }}
            """,
            "ip6",
            dict(
                xfw_src_ip_default_blocked_packets=[3, 15],
                xfw_src_ip_default_blocked_bytes=[100, 1200],
            ),
            id="ip6-block-tcp-ip-default",
        ),
        pytest.param(
            "xfw {{ ratelimit=test pps=0 bps=0; defaults {{ src_ip ip4.tcp: ratelimit=test; }} }}",
            "ip4",
            dict(
                xfw_src_ip_default_rate_limited_packets=10,
                xfw_src_ip_default_rate_limited_bytes=610,
            ),
            id="ip4-ratelimit-tcp-ip-default",
        ),
        # tcp ip6 src filter blocks also ICMP6 packets, the results could be different
        pytest.param(
            """
            xfw {{ 
                ratelimit=test pps=0 bps=0; 
                defaults {{ 
                    src_ip ip6.tcp: ratelimit=test; 
                }} 
                icmp ip6: allow {{ 1, 2, 3, 4, 128, 129, 133, 134, 135, 136, 137, 143 }}
            }}
            """,
            "ip6",
            dict(
                xfw_src_ip_default_rate_limited_packets=[3, 15],
                xfw_src_ip_default_rate_limited_bytes=[100, 1200],
            ),
            id="ip6-ratelimit-tcp-ip-default",
        ),
    ]
    +
    # tcp port
    [
        pytest.param(
            "xfw {{ src ip4.tcp: block {{ :{port}, :{port_2} }} }}",
            "ip4",
            dict(
                xfw_src_port_blocked_packets=10,
                xfw_src_port_blocked_bytes=610,
            ),
            id="ip4-block-tcp-port",
        ),
        pytest.param(
            "xfw {{ src ip6.tcp: block {{ :{port}, :{port_2} }} }}",
            "ip6",
            dict(
                xfw_src_port_blocked_packets=10,
                xfw_src_port_blocked_bytes=810,
            ),
            id="ip6-block-tcp-port",
        ),
        pytest.param(
            "xfw {{ ratelimit=test pps=0 bps=0; src ip4.tcp: ratelimit=test {{ :{port}, :{port_2} }} }}",
            "ip4",
            dict(
                xfw_src_port_rate_limited_packets=10,
                xfw_src_port_rate_limited_bytes=610,
            ),
            id="ip4-ratelimit-tcp-port",
        ),
        pytest.param(
            "xfw {{ ratelimit=test pps=0 bps=0; src ip6.tcp: ratelimit=test {{ :{port}, :{port_2} }} }}",
            "ip6",
            dict(
                xfw_src_port_rate_limited_packets=10,
                xfw_src_port_rate_limited_bytes=810,
            ),
            id="ip6-ratelimit-tcp-port",
        ),
        pytest.param(
            "xfw {{ defaults {{ src_port ip4.tcp: block; }} }}",
            "ip4",
            dict(
                xfw_src_port_default_blocked_packets=10,
                xfw_src_port_default_blocked_bytes=610,
            ),
            id="ip4-block-tcp-port-default",
        ),
        pytest.param(
            "xfw {{ defaults {{ src_port ip6.tcp: block; }} }}",
            "ip6",
            dict(
                xfw_src_port_default_blocked_packets=10,
                xfw_src_port_default_blocked_bytes=810,
            ),
            id="ip6-block-tcp-port-default",
        ),
        pytest.param(
            "xfw {{ ratelimit=test pps=0 bps=0; defaults {{ src_port ip4.tcp: ratelimit=test; }} }}",
            "ip4",
            dict(
                xfw_src_port_default_rate_limited_packets=10,
                xfw_src_port_default_rate_limited_bytes=610,
            ),
            id="ip4-ratelimit-tcp-port-default",
        ),
        pytest.param(
            "xfw {{ ratelimit=test pps=0 bps=0; defaults {{ src_port ip6.tcp: ratelimit=test; }} }}",
            "ip6",
            dict(
                xfw_src_port_default_rate_limited_packets=10,
                xfw_src_port_default_rate_limited_bytes=810,
            ),
            id="ip6-ratelimit-tcp-port-default",
        ),
    ],
)
async def test_src_tcp_stats(
    rule: str,
    ip: str,
    counters: dict[str, int],
    src_stats_counters: list[str],
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

    await xfw.rules_set(
        rule.format(
            host=client.ip_testing,
            port=client.port,
            host_2=client_2.ip_testing,
            port_2=client_2.port,
        )
    )

    async with xfw.metrics_diff(src_stats_counters, wait_softirq=True) as diff:
        await asyncio.gather(
            *[client.send(TCP(flags="PA", seq=22211) / f"012345{i}".encode()) for i in range(5)]
            + [client_2.send(TCP(flags="PA", seq=32211) / f"012345{i}".encode()) for i in range(5)]
        )

    invalid_metrics = compare_metrics_diff(
        compare_metrics=src_stats_counters, all_metrics=diff, diff_metrics=counters
    )

    await client.stop()
    await client_2.stop()
    await server.stop()

    assert invalid_metrics == [], f"Some metrics are different: {invalid_metrics}"
