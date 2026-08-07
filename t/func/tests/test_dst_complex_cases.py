# SPDX-FileCopyrightText: (c) 2026 Tempesta Technologies, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later

import asyncio

import pytest

from framework.cmp import check_connection
from framework.stateful import RegularKernelSocketNetworkStateful
from framework.xfw import XFW


@pytest.fixture
def true_if_allowed(dst_defaults: str) -> bool:
    allow = dst_defaults == "allow"
    yield allow


@pytest.fixture
def error_message(true_if_allowed, server):
    msg = f"Server {server.ip_testing}:{server.port} is not blocked"

    if true_if_allowed:
        msg = f"Server {server.ip_testing}:{server.port} is not allowed"

    yield msg


async def test_dst_allowed_out_of_ip_list(
    xfw: XFW,
    protocol: str,
    ip_version: str,
    server: RegularKernelSocketNetworkStateful,
    client: RegularKernelSocketNetworkStateful,
    establish_connection,
    dst_defaults: str,
    true_if_allowed: bool,
    error_message: str,
):
    new_ip = server.generate_new_address()

    await xfw.rules_set(f"""
            xfw {{
                defaults {{ dst: {dst_defaults}; }}
                dst {ip_version}.{protocol} : allow {{
                    {server.ip_format(new_ip)}:{server.port}
                }}
            }}
        """)

    assert await check_connection(client, server) == true_if_allowed, error_message


async def test_dst_allowed_out_of_multiple_ip_list(
    xfw: XFW,
    protocol: str,
    ip_version: str,
    server: RegularKernelSocketNetworkStateful,
    client: RegularKernelSocketNetworkStateful,
    establish_connection,
    dst_defaults: str,
    true_if_allowed: bool,
    error_message: str,
):
    new_ip = server.generate_new_addresses(2)

    await xfw.rules_set(f"""
            xfw {{
                defaults {{ dst: {dst_defaults}; }}
                dst {ip_version}.{protocol} : allow {{
                    {server.ip_format(new_ip[0])}:{server.port}
                    {server.ip_format(new_ip[1])}:{server.port}
                }}
            }}
        """)
    assert await check_connection(client, server) == true_if_allowed, error_message


async def test_dst_allow_out_of_multiple_port_list_rules(
    xfw: XFW,
    protocol: str,
    ip_version: str,
    server: RegularKernelSocketNetworkStateful,
    client: RegularKernelSocketNetworkStateful,
    establish_connection,
    dst_defaults: str,
    true_if_allowed: bool,
    error_message: str,
):
    new_port = server.generate_new_ports(2)

    await xfw.rules_set(f"""
            xfw {{
                defaults {{ dst: {dst_defaults}; }}
                dst {ip_version}.{protocol} : allow {{
                    {server.ip_testing}:{new_port[0]}
                    {server.ip_testing}:{new_port[1]}
                }}
            }}
        """)
    assert await check_connection(client, server) == true_if_allowed, error_message


async def test_dst_change_ratelimit(
    xfw: XFW,
    protocol: str,
    ip_version: str,
    server: RegularKernelSocketNetworkStateful,
    client: RegularKernelSocketNetworkStateful,
    establish_connection,
    dst_defaults: str,
):

    await xfw.rules_set(f"""
            xfw {{
                ratelimit=a pps=0 bps=0;
                ratelimit=b pps=10 bps=1000;
                defaults {{ dst: {dst_defaults}; }}
                dst {ip_version}.{protocol} : ratelimit=a {{
                    {server.ip_testing}:{server.port}
                }}
            }}
        """)

    assert (
        await check_connection(client, server) is False
    ), f"Server {server.ip_testing}:{server.port} is not blocked"

    await client.stop()
    await xfw.rules_patch(f"""
        xfw {{
            dst {ip_version}.{protocol} : ratelimit=b {{
                {server.ip_testing}:{server.port}
            }}
        }}
        """)

    await client.start()
    assert (
        await check_connection(client, server) is True
    ), f"Server {server.ip_testing}:{server.port} is not allowed"


async def test_dst_change_ratelimit_value(
    xfw: XFW,
    protocol: str,
    ip_version: str,
    server: RegularKernelSocketNetworkStateful,
    client: RegularKernelSocketNetworkStateful,
    establish_connection,
    dst_defaults: str,
):

    await xfw.rules_set(f"""
            xfw {{
                ratelimit=a pps=0 bps=0;
                defaults {{ dst: {dst_defaults}; }}
                dst {ip_version}.{protocol} : ratelimit=a {{
                    {server.ip_testing}:{server.port}
                }}
            }}
        """)

    assert (
        await check_connection(client, server) is False
    ), f"Server {server.ip_testing}:{server.port} is not blocked"

    await client.stop()
    await xfw.rules_patch(f"""
        xfw {{
            ratelimit=b pps=10 bps=1000;
            dst {ip_version}.{protocol} : ratelimit=b {{
                {server.ip_testing}:{server.port}
            }}
        }}
        """)

    await client.start()
    assert (
        await check_connection(client, server) is True
    ), f"Server {server.ip_testing}:{server.port} is not allowed"


async def test_dst_switch_ratelimit_to_another_rule(
    xfw: XFW,
    protocol: str,
    ip_version: str,
    server: RegularKernelSocketNetworkStateful,
    client: RegularKernelSocketNetworkStateful,
    establish_connection,
    dst_defaults: str,
    true_if_allowed: bool,
    error_message: str,
):

    await xfw.rules_set(f"""
            xfw {{
                ratelimit=a pps=1 bps=1000;
                defaults {{ dst: block; }}
                dst {ip_version}.{protocol} : ratelimit=a {{
                    {server.ip_testing}:{server.port}
                }}
            }}
        """)
    assert await check_connection(client, server) is True, "Server is not allowed"

    await xfw.rules_patch(f"""
        xfw {{
            dst {ip_version}.{protocol} : {dst_defaults} {{
                {server.ip_testing}:{server.port}
            }}
        }}
        """)
    # we receive 3 times allowed or blocked, where ratelimit is 1
    assert await check_connection(client, server) is true_if_allowed, error_message
    assert await check_connection(client, server) is true_if_allowed, error_message
    assert await check_connection(client, server) is true_if_allowed, error_message


async def test_dst_block_all_src_allow(
    xfw: XFW,
    protocol: str,
    ip_version: str,
    server: RegularKernelSocketNetworkStateful,
    client: RegularKernelSocketNetworkStateful,
    establish_connection,
):
    await xfw.rules_set(f"""
            xfw {{
                defaults {{ dst: block; }}
                ratelimit=test pps=100 bps=10000;
                src {ip_version}.{protocol} : ratelimit=test {{
                    :{client.port}
                }}
            }}
        """)
    assert await check_connection(client, server) is False, "Client is allowed"
