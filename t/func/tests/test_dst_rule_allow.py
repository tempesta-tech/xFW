# SPDX-FileCopyrightText: (c) 2026 Tempesta Technologies, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later
import pytest

from framework.cmp import check_connection
from framework.stateful import RegularKernelSocketNetworkStateful
from framework.xfw import XFW


async def test_dst_allowed_ip(
    xfw: XFW,
    protocol: str,
    ip_version: str,
    server: RegularKernelSocketNetworkStateful,
    client: RegularKernelSocketNetworkStateful,
    dst_defaults: str,
    establish_connection,
):
    await xfw.rules_set(f"""
        xfw {{
            defaults {{ dst: {dst_defaults}; }}
            dst {ip_version}.{protocol} : allow {{
                {server.ip_testing}:{server.port}
            }}
        }}
        """)

    assert (
        await check_connection(client, server) is True
    ), f"Server {server.ip_testing}:{server.port} is not available"


async def test_dst_allowed_multiple_ip(
    xfw: XFW,
    protocol: str,
    ip_version: str,
    server: RegularKernelSocketNetworkStateful,
    client: RegularKernelSocketNetworkStateful,
    dst_defaults: str,
    establish_connection,
):
    new_ip = server.generate_new_address()

    await xfw.rules_set(f"""
        xfw {{
            defaults {{ dst: {dst_defaults}; }}
            dst {ip_version}.{protocol} : allow {{
                {server.ip_testing}:{server.port}
                {server.ip_format(new_ip)}:{server.port}
            }}
        }}
        """)

    assert (
        await check_connection(client, server) is True
    ), f"Server {server.ip_testing}:{server.port} is not available"


async def test_dst_allow_by_multiple_port(
    xfw: XFW,
    protocol: str,
    ip_version: str,
    server: RegularKernelSocketNetworkStateful,
    client: RegularKernelSocketNetworkStateful,
    dst_defaults: str,
    establish_connection,
):
    new_port = server.generate_new_port()

    await xfw.rules_set(f"""
        xfw {{
            defaults {{ dst: {dst_defaults}; }}
            dst {ip_version}.{protocol} : allow {{
                {server.ip_testing}:{server.port}
                {server.ip_testing}:{new_port}
            }}
        }}
        """)
    assert await check_connection(client, server) is True, f"Port {new_port} is not allowed"


@pytest.mark.skip("ISSUE: 39 (xFW)")
async def test_dst_allow_by_ratelimit(
    xfw: XFW,
    protocol: str,
    ip_version: str,
    server: RegularKernelSocketNetworkStateful,
    client: RegularKernelSocketNetworkStateful,
    dst_defaults: str,
    establish_connection,
):
    new_port = server.generate_new_ports(2)

    await xfw.rules_set(f"""
        xfw {{
            ratelimit=test pps=5 bps=500;
            defaults {{ dst: block; }}
            dst=extended_group {ip_version}.{protocol} : ratelimit=test {{
                {server.ip_testing}:{new_port[0]}
            }}
        }}
        """)
    await xfw.rules_patch(f"""
        xfw {{
            dst=extended_group/add {ip_version}.{protocol} {{
                {server.ip_testing}:{new_port[1]}
                {server.ip_testing}:{server.port}
            }}
        }}
        """)

    assert (
        await check_connection(client, server) is True
    ), f"Server {server.ip_testing}:{server.port} is not allowed"


async def test_dst_allow_only_one_protocol_subtype(
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
            dst {ip_version}.{protocol} : allow {{
                {server.ip_testing}:{server.port}
            }}
        }}
        """)

    for new_client, new_server in remaining_client_server_group.items():
        assert (
            await check_connection(new_client, new_server) is False
        ), f"Server {new_server.ip_testing}:{new_server.port} is not blocked"


@pytest.mark.skip("ISSUE: 336 (escudo)")
async def test_dst_allowed_ip_mapped(
    xfw: XFW,
    udp_ip4_client: RegularKernelSocketNetworkStateful,
    udp_ip4_mapped_ip6_server: RegularKernelSocketNetworkStateful,
):
    await xfw.rules_set(f"""
        xfw {{
            defaults {{ dst: block; }}
            dst ip6.udp : allow {{
                {udp_ip4_mapped_ip6_server.ip_testing}:{udp_ip4_mapped_ip6_server.port}
            }}
        }}
        """)

    assert (
        await check_connection(udp_ip4_client, udp_ip4_mapped_ip6_server) is True
    ), f"Server {udp_ip4_mapped_ip6_server.ip_testing}:{udp_ip4_mapped_ip6_server.port} is not available"
