# SPDX-FileCopyrightText: (c) 2026 Tempesta Technologies, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later

from framework.cmp import check_connection
from framework.stateful import RegularKernelSocketNetworkStateful
from framework.xfw import XFW


async def test_src_add_block_by_ip(
    xfw: XFW,
    protocol: str,
    ip_version: str,
    server: RegularKernelSocketNetworkStateful,
    client: RegularKernelSocketNetworkStateful,
    establish_connection,
    src_defaults: str,
):
    new_ip = client.generate_new_address()

    await xfw.rules_set(f"""
        xfw {{
            defaults {{ src_ip {ip_version}: {src_defaults }; }}
            src=extended_group {ip_version}.{protocol} : block {{
                {client.ip_format(new_ip)}
            }}
        }}
        """)
    await xfw.rules_patch(f"""
        xfw {{
            src=extended_group/add {ip_version}.{protocol} {{
                {client.ip_testing}
            }}
        }}
        """)
    assert (
        await check_connection(client, server) is False
    ), f"Client {server.ip_testing}:{server.port} is not blocked"


async def test_src_add_block_by_multiple_ip(
    xfw: XFW,
    protocol: str,
    ip_version: str,
    server: RegularKernelSocketNetworkStateful,
    client: RegularKernelSocketNetworkStateful,
    establish_connection,
    src_defaults: str,
):
    new_ip = client.generate_new_addresses(2)

    await xfw.rules_set(f"""
        xfw {{
            defaults {{ src_ip {ip_version}: {src_defaults }; }}
            src=extended_group {ip_version}.{protocol} : block {{
                {client.ip_format(new_ip[0])}
            }}
        }}
        """)
    await xfw.rules_patch(f"""
        xfw {{
            src=extended_group/add {ip_version}.{protocol} {{
                {client.ip_format(new_ip[1])}
                {client.ip_testing}
            }}
        }}
        """)

    assert (
        await check_connection(client, server) is False
    ), f"Client {server.ip_testing}:{server.port} is not blocked"


async def test_src_add_block_by_mask(
    xfw: XFW,
    protocol: str,
    ip_version: str,
    server: RegularKernelSocketNetworkStateful,
    client: RegularKernelSocketNetworkStateful,
    establish_connection,
    src_defaults,
):
    new_ip = client.generate_new_address()

    await xfw.rules_set(f"""
        xfw {{
            defaults {{ src_ip {ip_version}: {src_defaults }; }}
            src=extended_group {ip_version}.{protocol} : block {{
                {client.mask_format(new_ip)}
            }}
        }}
        """)
    await xfw.rules_patch(f"""
        xfw {{
            src=extended_group/add {ip_version}.{protocol} {{
                {client.mask_formatted}
            }}
        }}
        """)
    assert (
        await check_connection(client, server) is False
    ), f"Client {server.ip_testing}:{server.port} is not blocked"


async def test_src_add_block_by_multiple_mask(
    xfw: XFW,
    protocol: str,
    ip_version: str,
    server: RegularKernelSocketNetworkStateful,
    client: RegularKernelSocketNetworkStateful,
    establish_connection,
    src_defaults: str,
):
    new_ip = client.generate_new_addresses(2)

    await xfw.rules_set(f"""
        xfw {{
            defaults {{ src_ip {ip_version}: {src_defaults }; }}
            src=extended_group {ip_version}.{protocol} : block {{
                {client.mask_format(new_ip[0])}
            }}
        }}
        """)
    await xfw.rules_patch(f"""
        xfw {{
            src=extended_group/add {ip_version}.{protocol} {{
                {client.mask_format(new_ip[1])}
                {client.mask_formatted}
            }}
        }}
        """)
    assert (
        await check_connection(client, server) is False
    ), f"Client {client.ip_testing}:{client.port} is not blocked"


async def test_src_add_block_by_port(
    xfw: XFW,
    protocol: str,
    ip_version: str,
    server: RegularKernelSocketNetworkStateful,
    client: RegularKernelSocketNetworkStateful,
    establish_connection,
    src_defaults,
):
    new_port = client.generate_new_port()

    await xfw.rules_set(f"""
        xfw {{
            defaults {{ src_port {ip_version}: {src_defaults }; }}
            src=extended_group {ip_version}.{protocol} : block {{
                :{new_port}
            }}
        }}
        """)
    await xfw.rules_patch(f"""
        xfw {{
            src=extended_group/add {ip_version}.{protocol} {{
                :{client.port}
            }}
        }}
        """)
    assert (
        await check_connection(client, server) is False
    ), f"Client {server.ip_testing}:{server.port} is not blocked"


async def test_src_add_block_by_multiple_port(
    xfw: XFW,
    protocol: str,
    ip_version: str,
    server: RegularKernelSocketNetworkStateful,
    client: RegularKernelSocketNetworkStateful,
    establish_connection,
    src_defaults: str,
):
    new_port = client.generate_new_ports(2)

    await xfw.rules_set(f"""
        xfw {{
            defaults {{ src_port {ip_version}: {src_defaults }; }}
            src=extended_group {ip_version}.{protocol} : block {{
                :{new_port[0]}
            }}
        }}
        """)
    await xfw.rules_patch(f"""
        xfw {{
            src=extended_group/add {ip_version}.{protocol} {{
                :{new_port[1]}
                :{client.port}
            }}
        }}
        """)
    assert (
        await check_connection(client, server) is False
    ), f"Client {server.ip_testing}:{server.port} is not blocked"


async def test_src_add_block_by_port_range(
    xfw: XFW,
    protocol: str,
    ip_version: str,
    server: RegularKernelSocketNetworkStateful,
    client: RegularKernelSocketNetworkStateful,
    establish_connection,
    src_defaults: str,
):
    new_port = client.generate_new_ports(3)

    await xfw.rules_set(f"""
        xfw {{
            defaults {{ src_port {ip_version}: {src_defaults }; }}
            src=extended_group {ip_version}.{protocol} : block {{
                :{new_port[1]}-{new_port[2]}
            }}
        }}
        """)
    await xfw.rules_patch(f"""
        xfw {{
            src=extended_group/add {ip_version}.{protocol} {{
                :{client.port}-{new_port[0]}
            }}
        }}
        """)
    assert (
        await check_connection(client, server) is False
    ), f"Client {server.ip_testing}:{server.port} is not blocked"


async def test_src_add_block_by_multiple_port_range(
    xfw: XFW,
    protocol: str,
    ip_version: str,
    server: RegularKernelSocketNetworkStateful,
    client: RegularKernelSocketNetworkStateful,
    establish_connection,
    src_defaults: str,
):
    new_port = client.generate_new_ports(5)

    await xfw.rules_set(f"""
        xfw {{
            defaults {{ src_port {ip_version}: {src_defaults }; }}
            src=extended_group {ip_version}.{protocol} : block {{
                :{new_port[3]}-{new_port[4]}
            }}
        }}
        """)
    await xfw.rules_patch(f"""
        xfw {{
            src=extended_group/add {ip_version}.{protocol} {{
                :{new_port[1]}-{new_port[2]},
                :{client.port}-{new_port[0]}
            }}
        }}
        """)
    assert (
        await check_connection(client, server) is False
    ), f"Client {server.ip_testing}:{server.port} is not blocked"


async def test_src_add_block_by_ratelimit(
    xfw: XFW,
    protocol: str,
    ip_version: str,
    server: RegularKernelSocketNetworkStateful,
    client: RegularKernelSocketNetworkStateful,
    establish_connection,
    src_defaults: str,
):
    new_port = client.generate_new_ports(5)

    await xfw.rules_set(f"""
        xfw {{
            ratelimit=test pps=1 bps=500;
            defaults {{ src_port {ip_version}: {src_defaults }; }}
            src=extended_group {ip_version}.{protocol} : ratelimit=test {{
                :{new_port[3]}-{new_port[4]}
            }}
        }}
        """)

    await xfw.rules_patch(f"""
        xfw {{
            src=extended_group/add {ip_version}.{protocol} {{
                :{new_port[1]}-{new_port[2]},
                :{client.port}-{new_port[0]}
            }}
        }}
        """)

    assert (
        await check_connection(client, server) is True
    ), f"Client {server.ip_testing}:{server.port} is not allowed"

    assert (
        await check_connection(client, server) is False
    ), f"Client {server.ip_testing}:{server.port} is not blocked"


async def test_src_add_only_one_protocol_subtype(
    xfw: XFW,
    protocol: str,
    ip_version: str,
    client: RegularKernelSocketNetworkStateful,
    remaining_client_server_group: dict[
        RegularKernelSocketNetworkStateful, RegularKernelSocketNetworkStateful
    ],
):
    new_ip = client.generate_new_address()
    await xfw.rules_set(f"""
        xfw {{
            defaults {{ src_ip ip4: allow; src_ip ip6: allow;}}
            src=extended_group {ip_version}.{protocol} : block  {{
                {client.ip_format(new_ip)}
            }}
        }}
        """)
    await xfw.rules_patch(f"""
        xfw {{
            src=extended_group/add {ip_version}.{protocol} {{
                {client.ip_testing}
            }}
        }}
        """)

    for new_client, new_server in remaining_client_server_group.items():
        assert (
            await check_connection(new_client, new_server) is True
        ), f"Server {new_server.ip_testing}:{new_server.port} is not allowed"


async def test_src_add_block_by_geoip_country(
    xfw_geoip: XFW,
    protocol: str,
    ip_version: str,
    server: RegularKernelSocketNetworkStateful,
    client: RegularKernelSocketNetworkStateful,
    establish_connection,
    src_defaults: str,
):
    await xfw_geoip.rules_set(f"""
        xfw {{
            defaults {{ src_ip {ip_version}: {src_defaults }; }}
            src=extended_group {ip_version}.{protocol} : block {{ us }}
        }}
        """)

    await xfw_geoip.rules_patch(f"""
        xfw {{
            src=extended_group/add {ip_version}.{protocol} {{ rs }}
        }}
        """)

    assert (
        await check_connection(client, server) is False
    ), f"Client {server.ip_testing}:{server.port} is not blocked"
