# SPDX-FileCopyrightText: (c) 2026 Tempesta Technologies, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later

import pytest

from framework.cmp import check_connection
from framework.stateful import RegularKernelSocketNetworkStateful
from framework.xfw import XFW


async def test_dst_block_by_ip(
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
            dst {ip_version}.{protocol} : block {{
                {server.ip_testing}:{server.port}
            }}
        }}
        """)

    assert (
        await check_connection(client, server) is False
    ), f"IP {server.ip_testing}:{server.port} is not blocked"


async def test_dst_block_by_multiple_ip(
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
            dst {ip_version}.{protocol} : block {{
                {server.ip_testing}:{server.port}
                {server.ip_format(new_ip)}:{server.port}
            }}
        }}
        """)
    assert await check_connection(client, server) is False, f"IP {new_ip} is not blocked"


async def test_dst_block_by_multiple_port(
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
            dst {ip_version}.{protocol} : block {{
                {server.ip_testing}:{server.port}
                {server.ip_testing}:{new_port}
            }}
        }}
        """)
    assert await check_connection(client, server) is False, f"Port {new_port} is not blocked"


async def test_dst_block_by_ratelimit(
    xfw: XFW,
    protocol: str,
    ip_version: str,
    server: RegularKernelSocketNetworkStateful,
    client: RegularKernelSocketNetworkStateful,
    establish_connection,
):
    """
    Verify that a specific extended_group with pps=0 ratelimit
    overrides the default allow policy.
    """
    await xfw.rules_set(f"""
        xfw {{
            defaults {{ dst: allow; }}
            ratelimit=test pps=0 bps=500;
            dst=extended_group {ip_version}.{protocol} : ratelimit=test {{
                {server.ip_testing}:{server.port}
            }}
        }}
        """)

    assert (
        await check_connection(client, server) is False
    ), f"Server {server.ip_testing}:{server.port} is not blocked"


async def test_dst_block_only_one_protocol_subtype(
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
            defaults {{ dst: allow; }}
            dst {ip_version}.{protocol} : block {{
                {server.ip_testing}:{server.port}
            }}
        }}
        """)

    for new_client, new_server in remaining_client_server_group.items():
        assert (
            await check_connection(new_client, new_server) is True
        ), f"Server {new_server.ip_testing}:{new_server.port} is not allowed"


async def test_dst_block_by_ip_mapped(
    xfw: XFW,
    udp_ip4_client: RegularKernelSocketNetworkStateful,
    udp_ip4_mapped_ip6_server: RegularKernelSocketNetworkStateful,
):
    """
    This test ensures that even though the server application binds to an IPv6 address
    handling mapped IPv4 traffic, the xfw correctly intercepts and drops the packet
    at the network layer as standard IPv4 UDP traffic.

    The network stack automatically converts IPv4 packets from the client into IPv6-mapped
    format for the server (and vice versa). As a result, the packet is transmitted over
    the network using the IPv4 protocol. Therefore, the dst rule is written for the ip4.
    """
    await xfw.rules_set(f"""
        xfw {{
            defaults {{ dst: allow; }}
            dst ip4.udp : block {{
                {udp_ip4_mapped_ip6_server.ip_testing}:{udp_ip4_mapped_ip6_server.port}
            }}
        }}
        """)

    assert (
        await check_connection(udp_ip4_client, udp_ip4_mapped_ip6_server) is False
    ), f"IP {udp_ip4_mapped_ip6_server.ip_testing}:{udp_ip4_mapped_ip6_server.port} is not blocked"
