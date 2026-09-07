# SPDX-FileCopyrightText: (c) 2026 Tempesta Technologies, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later
from typing import Callable

import pytest
from scapy.layers.inet import TCP

from framework.metrics import ClickhouseSingleMetric

from .test_icmp import ICMP_BLOCKING_TYPES_STR


@pytest.fixture
async def xfw_blocked_by_tcp_flags_syn(xfw):
    await xfw.rules_set(f"""
        xfw {{
            ratelimit=test pps=0 bps=1000;
            tcp_flags syn : ratelimit=test;
        }}
        """)


@pytest.fixture
async def xfw_blocked_by_tcp_flags_rst(xfw):
    await xfw.rules_set(f"""
        xfw {{
            ratelimit=test pps=0 bps=1000;
            tcp_flags rst : ratelimit=test;
        }}
        """)


@pytest.fixture
async def xfw_blocked_by_icmp(xfw, ip_version):
    await xfw.rules_set(f"""
        xfw {{ 
            defaults {{ icmp: allow; }}
            icmp {ip_version}: block {{ {ICMP_BLOCKING_TYPES_STR} }}
        }}
        """)


@pytest.fixture
async def xfw_blocked_by_icmp_ratelimit(xfw, ip_version):
    await xfw.rules_set(f"""
        xfw {{
            ratelimit=test pps=0 bps=5000;
            defaults {{ icmp: allow; }}
            icmp {ip_version}: ratelimit=test {{ {ICMP_BLOCKING_TYPES_STR} }}
        }}
        """)


@pytest.fixture
async def xfw_blocked_by_icmp_defaults(xfw):
    await xfw.rules_set(f"xfw {{ defaults {{ icmp: block; }} }}")


@pytest.fixture
async def xfw_blocked_by_icmp_defaults_ratelimit(xfw):
    await xfw.rules_set(f"""
        xfw {{
            ratelimit=test pps=0 bps=5000;
            defaults {{ icmp: ratelimit=test; }}
        }}
        """)


@pytest.fixture
async def xfw_blocked_by_dst(xfw, ip_version, protocol, client, server):
    await server.start()
    await client.start()

    await xfw.rules_set(f"""
        xfw {{ 
            defaults {{ dst : allow; }}
            dst {ip_version}.{protocol} : block {{
                {server.ip_testing}:{server.port}
            }}
        }}
        """)


@pytest.fixture
async def xfw_blocked_by_dst_ratelimit(xfw, ip_version, protocol, client, server):
    await server.start()
    await client.start()

    await xfw.rules_set(f"""
        xfw {{ 
            defaults {{ dst : allow; }}
            ratelimit=test pps=0 bps=500;
            dst {ip_version}.{protocol} : ratelimit=test {{
                {server.ip_testing}:{server.port}
            }}
        }}
        """)


@pytest.fixture
async def xfw_blocked_by_src_port(xfw, ip_version, protocol, client, server):
    await server.start()
    await client.start()

    await xfw.rules_set(f"""
        xfw {{ 
            defaults {{ src_port : allow; }}
            src {ip_version}.{protocol} : block {{
                :{client.port}
            }}
        }}
        """)


@pytest.fixture
async def xfw_ratelimit_by_src_port(xfw, ip_version, protocol, client, server):
    await server.start()
    await client.start()

    await xfw.rules_set(f"""
        xfw {{ 
            ratelimit=test pps=0 bps=500;
            defaults {{ src_port : allow; }}
            src {ip_version}.{protocol} : ratelimit=test {{
                :{client.port}
            }}
        }}
        """)


@pytest.fixture
async def xfw_blocked_by_src_port_defaults(xfw, ip_version, protocol, client, server):
    await server.start()
    await client.start()

    await xfw.rules_set(f"xfw {{ defaults {{ src_port : block; }} }}")


@pytest.fixture
async def xfw_ratelimit_by_src_port_defaults(xfw, ip_version, protocol, client, server):
    await server.start()
    await client.start()

    await xfw.rules_set(f"""
        xfw {{ 
            ratelimit=test pps=0 bps=500;
            defaults {{ src_port : ratelimit=test; }}
        }}
        """)


@pytest.fixture
async def xfw_blocked_by_src_ip(xfw, ip_version, protocol, client, server):
    await server.start()
    await client.start()

    await xfw.rules_set(f"""
        xfw {{ 
            defaults {{ src_ip : allow; }}
            src {ip_version}.{protocol} : block {{
                {client.ip_testing}
            }}
        }}
        """)


@pytest.fixture
async def xfw_ratelimit_by_src_ip(xfw, ip_version, protocol, client, server):
    await server.start()
    await client.start()

    await xfw.rules_set(f"""
        xfw {{ 
            ratelimit=test pps=0 bps=500;
            defaults {{ src_ip : allow; }}
            src {ip_version}.{protocol} : ratelimit=test {{
                {client.ip_testing}
            }}
        }}
        """)


@pytest.fixture
async def xfw_blocked_by_src_ip_defaults(xfw, ip_version, protocol, client, server):
    await server.start()
    await client.start()

    await xfw.rules_set(f"xfw {{ defaults {{ src_ip : block; }} }}")


@pytest.fixture
async def xfw_ratelimit_by_src_ip_defaults(xfw, ip_version, protocol, client, server):
    await server.start()
    await client.start()

    await xfw.rules_set(f"""
        xfw {{ 
            ratelimit=test pps=0 bps=500;
            defaults {{ src_ip : ratelimit=test; }}
        }}
        """)


@pytest.fixture
def xfw_setup(request):
    return request.getfixturevalue(request.param)


@pytest.mark.parametrize(
    "xfw_setup, expected_metric, blocking_packet",
    [
        pytest.param(
            "xfw_blocked_by_tcp_flags_syn",
            ClickhouseSingleMetric.blocked_by_tcp_flags_syn_ratelimit,
            TCP(flags="S"),
            id="blocked-by-tcp-flags-syn-1-bit",
        ),
        pytest.param(
            "xfw_blocked_by_tcp_flags_rst",
            ClickhouseSingleMetric.blocked_by_tcp_flags_rst_ratelimit,
            TCP(flags="R"),
            id="blocked-by-tcp-flags-rst-2-bit",
        ),
    ],
    indirect=["xfw_setup"],
)
async def test_tcp_flags(
    xfw_setup,
    expected_metric: Callable,
    blocking_packet: TCP,
    xfw,
    tcp_raw_client,
    tcp_raw_server,
    clickhouse_client,
    metric_analyzer,
):
    await clickhouse_client.connect()
    await tcp_raw_server.start()
    await tcp_raw_client.start()

    async with metric_analyzer.expected_clickhouse_metric_diff(
        clickhouse_client, ip_to_search=tcp_raw_client.ip_clickhouse
    ) as metric:
        await tcp_raw_client.send_packet(blocking_packet)
        assert await tcp_raw_server.receive_block()

    assert expected_metric(metric)


@pytest.mark.parametrize(
    "xfw_setup, expected_metric",
    [
        pytest.param(
            "xfw_blocked_by_icmp",
            ClickhouseSingleMetric.blocked_by_icmp_block,
            id="blocked-by-icmp-0-bit",
        ),
        pytest.param(
            "xfw_blocked_by_icmp_ratelimit",
            ClickhouseSingleMetric.blocked_by_icmp_ratelimit,
            id="blocked-by-icmp-ratelimit-3-bit",
        ),
        pytest.param(
            "xfw_blocked_by_icmp_defaults",
            ClickhouseSingleMetric.blocked_by_defaults_icmp_block,
            id="blocked-by-icmp-defaults-4-bit",
        ),
        pytest.param(
            "xfw_blocked_by_icmp_defaults_ratelimit",
            ClickhouseSingleMetric.blocked_by_defaults_icmp_ratelimit,
            id="blocked-by-icmp-defaults-ratelimit-5-bit",
        ),
    ],
    indirect=["xfw_setup"],
)
async def test_icmp(
    xfw_setup,
    expected_metric: Callable,
    xfw,
    icmp_raw_client,
    udp_server,
    clickhouse_client,
    metric_analyzer,
):
    await udp_server.start()
    await icmp_raw_client.start()
    await clickhouse_client.connect()

    async with metric_analyzer.expected_clickhouse_metric_diff(
        clickhouse_client, ip_to_search=icmp_raw_client.ip_clickhouse
    ) as metric:
        await icmp_raw_client.ping()
        assert await icmp_raw_client.pong() is False

    assert expected_metric(metric)


@pytest.mark.parametrize(
    "xfw_setup, expected_metric",
    [
        pytest.param(
            "xfw_blocked_by_dst",
            ClickhouseSingleMetric.blocked_by_dst_block,
            id="blocked-by-dst-6-bit",
        ),
        pytest.param(
            "xfw_blocked_by_dst_ratelimit",
            ClickhouseSingleMetric.rate_limited_by_dst_ratelimit,
            id="blocked-by-dst-ratelimit-7-bit",
        ),
    ],
    indirect=["xfw_setup"],
)
async def test_dst(
    xfw_setup, expected_metric: Callable, xfw, client, server, clickhouse_client, metric_analyzer
):
    await clickhouse_client.connect()

    async with metric_analyzer.expected_clickhouse_metric_diff(
        clickhouse_client, ip_to_search=client.ip_clickhouse
    ) as metric:
        await client.ping()
        assert await server.receive_block()

    assert expected_metric(metric)


@pytest.mark.parametrize(
    "xfw_setup, expected_metric",
    [
        pytest.param(
            "xfw_blocked_by_src_port",
            ClickhouseSingleMetric.blocked_by_src_port_block,
            id="blocked-by-src-port-8-bit",
        ),
        pytest.param(
            "xfw_ratelimit_by_src_port",
            ClickhouseSingleMetric.rate_limited_by_src_port_ratelimit,
            id="ratelimit-by-src-port-9-bit",
        ),
        pytest.param(
            "xfw_blocked_by_src_port_defaults",
            ClickhouseSingleMetric.blocked_by_defaults_src_port_block,
            id="blocked-by-src-port-defaults-10-bit",
        ),
        pytest.param(
            "xfw_ratelimit_by_src_port_defaults",
            ClickhouseSingleMetric.rate_limited_by_defaults_src_port_ratelimit,
            id="ratelimit-by-src-port-defaults-11-bit",
        ),
        pytest.param(
            "xfw_blocked_by_src_ip",
            ClickhouseSingleMetric.blocked_by_src_ip_block,
            id="blocked-by-src-ip-12-bit",
        ),
        pytest.param(
            "xfw_ratelimit_by_src_ip",
            ClickhouseSingleMetric.rate_limited_by_src_ip_ratelimit,
            id="ratelimit-by-src-ip-13-bit",
        ),
        pytest.param(
            "xfw_blocked_by_src_ip_defaults",
            ClickhouseSingleMetric.blocked_by_defaults_src_ip_block,
            id="blocked-by-src-ip-defaults-14-bit",
        ),
        pytest.param(
            "xfw_ratelimit_by_src_ip_defaults",
            ClickhouseSingleMetric.rate_limited_by_defaults_src_ip_ratelimit,
            id="ratelimit-by-src-ip-defaults-15-bit",
        ),
    ],
    indirect=["xfw_setup"],
)
async def test_src(
    xfw_setup, expected_metric: Callable, xfw, client, server, clickhouse_client, metric_analyzer
):
    await clickhouse_client.connect()

    async with metric_analyzer.expected_clickhouse_metric_diff(
        clickhouse_client, ip_to_search=client.ip_clickhouse
    ) as metric:
        await client.ping()
        assert await server.receive_block()

    assert expected_metric(metric)
