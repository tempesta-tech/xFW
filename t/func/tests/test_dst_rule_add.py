# SPDX-FileCopyrightText: (c) 2026 Tempesta Technologies, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later

from framework.cmp import check_connection
from framework.stateful import RegularKernelSocketNetworkStateful
from framework.xfw import XFW


async def test_dst_add_block_by_ip(
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
            dst=extended_group {ip_version}.{protocol} : block {{
                {server.ip_format(new_ip)}:{server.port}
            }}
        }}
        """)
    await xfw.rules_patch(f"""
        xfw {{
            dst=extended_group/add {ip_version}.{protocol} {{
                {server.ip_testing}:{server.port}
            }}
        }}
        """)
    assert (
        await check_connection(client, server) is False
    ), f"Server ({server.ip_testing}:{server.port}) is not blocked"


async def test_dst_add_block_by_multiple_ip(
    xfw: XFW,
    protocol: str,
    ip_version: str,
    server: RegularKernelSocketNetworkStateful,
    client: RegularKernelSocketNetworkStateful,
    dst_defaults: str,
    establish_connection,
):
    new_ip = server.generate_new_addresses(2)

    await xfw.rules_set(f"""
        xfw {{
            defaults {{ dst: {dst_defaults}; }}
            dst=extended_group {ip_version}.{protocol} : block {{
                {server.ip_format(new_ip[0])}:{server.port}
            }}
        }}
        """)
    await xfw.rules_patch(f"""
        xfw {{
            dst=extended_group/add {ip_version}.{protocol} {{
                {server.ip_format(new_ip[1])}:{server.port}
                {server.ip_testing}:{server.port}
            }}
        }}
        """)
    assert (
        await check_connection(client, server) is False
    ), f"Server ({server.ip_testing}:{server.port}) is not blocked"


async def test_dst_block_by_port(
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
            dst=extended_group {ip_version}.{protocol} : block {{
                {server.ip_testing}:{new_port}
            }}
        }}
        """)
    await xfw.rules_patch(f"""
        xfw {{
            dst=extended_group/add {ip_version}.{protocol} {{
                {server.ip_testing}:{server.port}
            }}
        }}
        """)

    assert (
        await check_connection(client, server) is False
    ), f"Server {server.ip_testing}:{server.port} is not blocked"


async def test_dst_block_by_multiple_port(
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
            defaults {{ dst: {dst_defaults}; }}
            dst=extended_group {ip_version}.{protocol} : block {{
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
        await check_connection(client, server) is False
    ), f"Server {server.ip_testing}:{server.port} is not blocked"


async def test_dst_block_by_ratelimit(
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
            defaults {{ dst: allow; }}
            ratelimit=test pps=100 bps=10000;
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


async def test_dst_add_only_one_protocol_subtype(
    xfw: XFW,
    protocol: str,
    ip_version: str,
    server: RegularKernelSocketNetworkStateful,
    remaining_client_server_group: dict[
        RegularKernelSocketNetworkStateful, RegularKernelSocketNetworkStateful
    ],
):
    new_port = server.generate_new_port()
    await xfw.rules_set(f"""
        xfw {{
            defaults {{ dst: allow; }}
            dst=extended_group {ip_version}.{protocol} : block  {{
                {server.ip_testing}:{new_port}
            }}
        }}
        """)
    await xfw.rules_patch(f"""
        xfw {{
            dst=extended_group/add {ip_version}.{protocol} {{
                {server.ip_testing}:{server.port}
            }}
        }}
        """)

    for new_client, new_server in remaining_client_server_group.items():
        assert (
            await check_connection(new_client, new_server) is True
        ), f"Server {new_server.ip_testing}:{new_server.port} is not allowed"
