# SPDX-FileCopyrightText: (c) 2026 Tempesta Technologies, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later

import pytest

from framework.cmp import check_block_connection, check_connection
from framework.stateful import RegularKernelSocketNetworkStateful
from framework.xfw import XFW


@pytest.fixture
def error_message(client):
    return f"Client {client.ip_testing}:{client.port} is not blocked"


async def test_src_del_block_by_ip(
    xfw: XFW,
    protocol: str,
    ip_version: str,
    server: RegularKernelSocketNetworkStateful,
    client: RegularKernelSocketNetworkStateful,
    establish_connection,
    error_message: str,
):
    await xfw.rules_set(f"""
        xfw {{
            defaults {{ src_ip: allow; }}
            src=extended_group {ip_version}.{protocol} : block {{
                {client.ip_testing}
            }}
        }}
        """)
    await xfw.rules_patch(f"""
        xfw {{
            src=extended_group/del {ip_version}.{protocol} {{
                {client.ip_testing}
            }}
        }}
        """)
    assert await check_connection(client, server), error_message


async def test_src_del_block_by_multiple_ip(
    xfw: XFW,
    protocol: str,
    ip_version: str,
    server: RegularKernelSocketNetworkStateful,
    client: RegularKernelSocketNetworkStateful,
    establish_connection,
    error_message: str,
):
    new_ip = client.generate_new_address()

    await xfw.rules_set(f"""
        xfw {{
            defaults {{ src_ip: allow; }}
            src=extended_group {ip_version}.{protocol} : block {{
                {client.ip_testing}
                {client.ip_format(new_ip)}
            }}
        }}
        """)
    await xfw.rules_patch(f"""
        xfw {{
            src=extended_group/del {ip_version}.{protocol} {{
                {client.ip_testing}
                {client.ip_format(new_ip)}
            }}
        }}
        """)
    assert await check_connection(client, server), error_message


async def test_src_del_block_by_mask(
    xfw: XFW,
    protocol: str,
    ip_version: str,
    server: RegularKernelSocketNetworkStateful,
    client: RegularKernelSocketNetworkStateful,
    establish_connection,
    error_message: str,
):
    await xfw.rules_set(f"""
        xfw {{
            defaults {{ src_ip: allow; }}
            src=extended_group {ip_version}.{protocol} : block {{
                {client.mask_formatted}
            }}
        }}
        """)
    await xfw.rules_patch(f"""
        xfw {{
            src=extended_group/del {ip_version}.{protocol} {{
                {client.mask_formatted}
            }}
        }}
        """)
    assert await check_connection(client, server), error_message


async def test_src_del_block_by_multiple_mask(
    xfw: XFW,
    protocol: str,
    ip_version: str,
    server: RegularKernelSocketNetworkStateful,
    client: RegularKernelSocketNetworkStateful,
    establish_connection,
    error_message: str,
):
    new_ip = client.generate_new_address()

    await xfw.rules_set(f"""
        xfw {{
            defaults {{ src_ip: allow; }}
            src=extended_group {ip_version}.{protocol} : block {{
                {client.mask_formatted}
                {client.mask_format(new_ip)}
            }}
        }}
        """)
    await xfw.rules_patch(f"""
        xfw {{
            src=extended_group/del {ip_version}.{protocol} {{
                {client.mask_formatted}
                {client.mask_format(new_ip)}
            }}
        }}
        """)
    assert await check_connection(client, server), error_message


async def test_src_del_block_by_port(
    xfw: XFW,
    protocol: str,
    ip_version: str,
    server: RegularKernelSocketNetworkStateful,
    client: RegularKernelSocketNetworkStateful,
    establish_connection,
    error_message: str,
):
    await xfw.rules_set(f"""
        xfw {{
            defaults {{ src_port: allow; }}
            src=extended_group {ip_version}.{protocol} : block {{
                :{client.port}
            }}
        }}
        """)
    await xfw.rules_patch(f"""
        xfw {{
            src=extended_group/del {ip_version}.{protocol} {{
                :{client.port}
            }}
        }}
        """)
    assert await check_connection(client, server), error_message


async def test_src_del_block_by_multiple_port(
    xfw: XFW,
    protocol: str,
    ip_version: str,
    server: RegularKernelSocketNetworkStateful,
    client: RegularKernelSocketNetworkStateful,
    establish_connection,
    error_message: str,
):
    new_port = client.generate_new_port()

    await xfw.rules_set(f"""
        xfw {{
            defaults {{ src_port: allow; }}
            src=extended_group {ip_version}.{protocol} : block {{
                :{client.port}
                :{new_port}
            }}
        }}
        """)
    await xfw.rules_patch(f"""
        xfw {{
            src=extended_group/del {ip_version}.{protocol} {{
                :{client.port}
                :{new_port}
            }}
        }}
        """)
    assert await check_connection(client, server), error_message


async def test_src_del_block_by_port_range(
    xfw: XFW,
    protocol: str,
    ip_version: str,
    server: RegularKernelSocketNetworkStateful,
    client: RegularKernelSocketNetworkStateful,
    establish_connection,
    error_message: str,
):
    new_port = client.generate_new_port()

    await xfw.rules_set(f"""
        xfw {{
            defaults {{ src_port: allow; }}
            src=extended_group {ip_version}.{protocol} : block {{
                :{client.port}-{new_port}
            }}
        }}
        """)
    await xfw.rules_patch(f"""
        xfw {{
            src=extended_group/del {ip_version}.{protocol} {{
                :{client.port}-{new_port}
            }}
        }}
        """)
    assert await check_connection(client, server), error_message


async def test_src_del_block_by_multiple_port_range(
    xfw: XFW,
    protocol: str,
    ip_version: str,
    server: RegularKernelSocketNetworkStateful,
    client: RegularKernelSocketNetworkStateful,
    establish_connection,
    error_message: str,
):
    new_port = client.generate_new_ports(3)

    await xfw.rules_set(f"""
        xfw {{
            defaults {{ src_port: allow; }}
            src=extended_group {ip_version}.{protocol} : block {{
                :{client.port}-{new_port[0]}
                :{new_port[1]}-{new_port[2]}
            }}
        }}
        """)
    await xfw.rules_patch(f"""
        xfw {{
            src=extended_group/del {ip_version}.{protocol} {{
                :{client.port}-{new_port[0]}
                :{new_port[1]}-{new_port[2]}
            }}
        }}
        """)
    assert await check_connection(client, server), error_message


async def test_src_replace_block_by_geoip_country(
    xfw: XFW,
    protocol: str,
    ip_version: str,
    server: RegularKernelSocketNetworkStateful,
    client: RegularKernelSocketNetworkStateful,
    establish_connection,
    error_message: str,
):
    await xfw.rules_set(f"""
        xfw {{
            defaults {{ src_ip {ip_version}: allow; }}
            src=extended_group {ip_version}.{protocol} : block {{ rs }}
        }}
        """)

    await xfw.rules_patch(f"""
        xfw {{
            src=extended_group/del {ip_version}.{protocol};
        }}
        """)

    assert await check_connection(client, server), error_message


async def test_src_del_block_by_ratelimit(
    xfw: XFW,
    protocol: str,
    ip_version: str,
    server: RegularKernelSocketNetworkStateful,
    client: RegularKernelSocketNetworkStateful,
    establish_connection,
    error_message: str,
):
    new_port = client.generate_new_ports(3)

    await xfw.rules_set(f"""
        xfw {{
            defaults {{ src_port: allow; }}
            src=extended_group {ip_version}.{protocol} : block {{
                :{client.port}-{new_port[0]}
                :{new_port[1]}-{new_port[2]}
            }}
        }}
        """)
    await xfw.rules_patch(f"""
        xfw {{
            ratelimit=test pps=0 bps=500;
            src=extended_group/del {ip_version}.{protocol} {{
                :{client.port}-{new_port[0]}
                :{new_port[1]}-{new_port[2]}
            }}
        }}
        """)
    assert await check_connection(client, server), error_message


async def test_src_del_only_one_protocol_subtype(
    xfw: XFW,
    protocol: str,
    ip_version: str,
    client: RegularKernelSocketNetworkStateful,
    remaining_client_server_group: dict[
        RegularKernelSocketNetworkStateful, RegularKernelSocketNetworkStateful
    ],
):
    await xfw.rules_set(f"""
        xfw {{
            defaults {{ src_ip ip4: block; src_ip ip6: block;}}
            src=extended_group {ip_version}.{protocol} : allow {{
                {client.ip_testing}
            }}
        }}
        """)
    await xfw.rules_patch(f"""
        xfw {{
            src=extended_group/del {ip_version}.{protocol} {{
                {client.ip_testing}
            }}
        }}
        """)

    for new_client, new_server in remaining_client_server_group.items():
        assert await check_block_connection(
            new_client, new_server
        ), f"Server {new_server.ip_testing}:{new_server.port} is not blocked"
