# SPDX-FileCopyrightText: (c) 2026 Tempesta Technologies, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later
from typing import Callable

import pytest

from framework.clickhouse import LogRecord
from framework.metrics import ClickhouseSingleMetric


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
    "xfw_setup, expected_property",
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
    xfw_setup, expected_property: Callable, xfw, client, server, clickhouse_client, metric_analyzer
):
    await clickhouse_client.connect()

    async with metric_analyzer.expected_clickhouse_metric_diff(
        clickhouse_client, ip_to_search=client.ip_clickhouse
    ) as metric:
        await client.ping()
        assert await server.receive_block()

    assert expected_property(metric)
