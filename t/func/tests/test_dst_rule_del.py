# SPDX-FileCopyrightText: (c) 2026 Tempesta Technologies, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later

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


async def test_dst_del_block_by_ip(
    xfw: XFW,
    protocol: str,
    ip_version: str,
    server: RegularKernelSocketNetworkStateful,
    client: RegularKernelSocketNetworkStateful,
    dst_defaults: str,
    establish_connection,
    true_if_allowed: bool,
    error_message: str,
):
    await xfw.rules_set(f"""
        xfw {{
            defaults {{ dst: {dst_defaults}; }}
            dst=extended_group {ip_version}.{protocol} : block {{
                {server.ip_testing}:{server.port}
            }}
        }}
        """)
    await xfw.rules_patch(f"""
        xfw {{
            dst=extended_group/del {ip_version}.{protocol} {{
                {server.ip_testing}:{server.port}
            }}
        }}
        """)
    assert await check_connection(client, server) == true_if_allowed, error_message


async def test_dst_del_block_by_multiple_ip(
    xfw: XFW,
    protocol: str,
    ip_version: str,
    server: RegularKernelSocketNetworkStateful,
    client: RegularKernelSocketNetworkStateful,
    dst_defaults: str,
    establish_connection,
    true_if_allowed: bool,
    error_message: str,
):
    new_ip = server.generate_new_address()

    await xfw.rules_set(f"""
        xfw {{
            defaults {{ dst: {dst_defaults}; }}
            dst=extended_group {ip_version}.{protocol} : block {{
                {server.ip_testing}:{server.port}
                {server.ip_format(new_ip)}:{server.port}
            }}
        }}
        """)
    await xfw.rules_patch(f"""
        xfw {{
            dst=extended_group/del {ip_version}.{protocol} {{
                {server.ip_testing}:{server.port}
                {server.ip_format(new_ip)}:{server.port}
            }}
        }}
        """)
    assert await check_connection(client, server) == true_if_allowed, error_message


async def test_dst_del_block_by_port(
    xfw: XFW,
    protocol: str,
    ip_version: str,
    server: RegularKernelSocketNetworkStateful,
    client: RegularKernelSocketNetworkStateful,
    dst_defaults: str,
    establish_connection,
    true_if_allowed: bool,
    error_message: str,
):
    await xfw.rules_set(f"""
        xfw {{
            defaults {{ dst: {dst_defaults}; }}
            dst=extended_group {ip_version}.{protocol} : block {{
                {server.ip_testing}:{server.port}
            }}
        }}
        """)
    await xfw.rules_patch(f"""
        xfw {{
            dst=extended_group/del {ip_version}.{protocol} {{
                {server.ip_testing}:{server.port}
            }}
        }}
        """)

    assert await check_connection(client, server) == true_if_allowed, error_message


async def test_dst_del_block_by_multiple_port(
    xfw: XFW,
    protocol: str,
    ip_version: str,
    server: RegularKernelSocketNetworkStateful,
    client: RegularKernelSocketNetworkStateful,
    dst_defaults: str,
    establish_connection,
    true_if_allowed: bool,
    error_message: str,
):
    new_port = server.generate_new_port()

    await xfw.rules_set(f"""
        xfw {{
            defaults {{ dst: {dst_defaults}; }}
            dst=extended_group {ip_version}.{protocol} : block {{
                {server.ip_testing}:{server.port}
                {server.ip_testing}:{new_port}
            }}
        }}
        """)
    await xfw.rules_patch(f"""
        xfw {{
            dst=extended_group/del {ip_version}.{protocol} {{
                {server.ip_testing}:{server.port}
                {server.ip_testing}:{new_port}
            }}
        }}
        """)

    assert await check_connection(client, server) == true_if_allowed, error_message


async def test_dst_del_block_by_ratelimit(
    xfw: XFW,
    protocol: str,
    ip_version: str,
    server: RegularKernelSocketNetworkStateful,
    client: RegularKernelSocketNetworkStateful,
    dst_defaults: str,
    establish_connection,
    true_if_allowed: bool,
    error_message: str,
):
    await xfw.rules_set(f"""
        xfw {{
            ratelimit=test pps=0 bps=500;
            defaults {{ dst: {dst_defaults}; }}
            dst=extended_group {ip_version}.{protocol} : ratelimit=test {{
                {server.ip_testing}:{server.port}
            }}
        }}
        """)
    await xfw.rules_patch(f"""
        xfw {{
            dst=extended_group/del {ip_version}.{protocol} {{
                {server.ip_testing}:{server.port}
            }}
        }}
        """)

    assert await check_connection(client, server) is true_if_allowed, error_message


async def test_dst_del_only_one_protocol_subtype(
    xfw: XFW,
    protocol: str,
    ip_version: str,
    server: RegularKernelSocketNetworkStateful,
    remaining_client_server_group: dict[
        RegularKernelSocketNetworkStateful, RegularKernelSocketNetworkStateful
    ],
):
    await xfw.rules_set(f"""
        xfw {{
            defaults {{ dst: block; }}
            dst=extended_group {ip_version}.{protocol} : allow {{
                {server.ip_testing}:{server.port}
            }}
        }}
        """)
    await xfw.rules_patch(f"""
        xfw {{
            dst=extended_group/del {ip_version}.{protocol} {{
                {server.ip_testing}:{server.port}
            }}
        }}
        """)

    for new_client, new_server in remaining_client_server_group.items():
        assert (
            await check_connection(new_client, new_server) is False
        ), f"Server {new_server.ip_testing}:{new_server.port} is not blocked"
