# SPDX-FileCopyrightText: (c) 2026 Tempesta Technologies, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later

import pytest

from framework.cmp import check_connection
from framework.stateful import RegularKernelSocketNetworkStateful
from framework.xfw import XFW


async def test_src_block_by_ip(
    xfw: XFW,
    protocol: str,
    ip_version: str,
    server: RegularKernelSocketNetworkStateful,
    client: RegularKernelSocketNetworkStateful,
    src_defaults,
    establish_connection: str,
):
    await xfw.rules_set(f"""
        xfw {{
            defaults {{ src_ip {ip_version}: {src_defaults}; }}
            src=extended_group {ip_version}.{protocol} : block {{
                {client.ip_testing}
            }}
        }}
        """)

    assert (
        await check_connection(client, server) is False
    ), f"Client {server.ip_testing}:{server.port} is not blocked"


async def test_src_block_by_multiple_ip(
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
            defaults {{ src_ip {ip_version}: {src_defaults}; }}
            src=extended_group {ip_version}.{protocol} : block {{
                {client.ip_testing}
                {client.ip_format(new_ip)}
            }}
        }}
        """)

    assert (
        await check_connection(client, server) is False
    ), f"Client {server.ip_testing}:{server.port} is not blocked"


async def test_src_block_by_mask(
    xfw: XFW,
    protocol: str,
    ip_version: str,
    server: RegularKernelSocketNetworkStateful,
    client: RegularKernelSocketNetworkStateful,
    establish_connection,
    src_defaults: str,
):
    await xfw.rules_set(f"""
        xfw {{
            defaults {{ src_ip {ip_version}: {src_defaults}; }}
            src=extended_group {ip_version}.{protocol} : block {{
                {client.mask_formatted}
            }}
        }}
        """)

    assert (
        await check_connection(client, server) is False
    ), f"Client {server.ip_testing}:{server.port} is not blocked"


@pytest.mark.parametrize(
    "ip_version,mask",
    [
        pytest.param("ip4", "8.8.8.8", id="ip4-impl"),
        pytest.param("ip4", "8.8.8.8/24", id="ip4-expl"),
        pytest.param("ip4", "8.8.8.8/32", id="ip4-mask"),
        pytest.param("ip6", "2001:4860:4860::8888", id="ip6-impl"),
        pytest.param("ip6", "2001:4860:4860::8888/128", id="ip6-expl"),
        pytest.param("ip6", "2001:4860:4860::8888/120", id="ip6-mask"),
    ],
)
async def test_src_not_block_by_not_matching_mask(
    xfw: XFW,
    protocol: str,
    ip_version: str,
    server: RegularKernelSocketNetworkStateful,
    client: RegularKernelSocketNetworkStateful,
    establish_connection,
    mask: str,
):
    await xfw.rules_set(f"""
        xfw {{
            defaults {{ src_ip {ip_version}: allow; }}
            src=extended_group {ip_version}.{protocol} : block {{
                {mask}
            }}
        }}
        """)

    assert (
        await check_connection(client, server) is True
    ), f"Client {server.ip_testing}:{server.port} is blocked"


async def test_src_block_by_multiple_mask(
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
            defaults {{ src_ip {ip_version}: {src_defaults}; }}
            src=extended_group {ip_version}.{protocol} : block {{
                {client.mask_formatted}
                {client.mask_format(new_ip)}
            }}
        }}
        """)

    assert (
        await check_connection(client, server) is False
    ), f"Client {server.ip_testing}:{server.port} is not blocked"


async def test_src_block_by_port(
    xfw: XFW,
    protocol: str,
    ip_version: str,
    server: RegularKernelSocketNetworkStateful,
    client: RegularKernelSocketNetworkStateful,
    establish_connection,
    src_defaults: str,
):
    await xfw.rules_set(f"""
        xfw {{
            defaults {{ src_port {ip_version}: {src_defaults }; }}
            src=extended_group {ip_version}.{protocol} : block {{
                :{client.port}
            }}
        }}
        """)

    assert (
        await check_connection(client, server) is False
    ), f"Client {server.ip_testing}:{server.port} is not blocked"


async def test_src_block_by_multiple_port(
    xfw: XFW,
    protocol: str,
    ip_version: str,
    server: RegularKernelSocketNetworkStateful,
    client: RegularKernelSocketNetworkStateful,
    establish_connection,
    src_defaults: str,
):
    new_port = client.generate_new_port()

    await xfw.rules_set(f"""
        xfw {{
            defaults {{ src_port {ip_version}: {src_defaults }; }}
            src=extended_group {ip_version}.{protocol} : block {{
                :{client.port}
                :{new_port}
            }}
        }}
        """)

    assert (
        await check_connection(client, server) is False
    ), f"Client {server.ip_testing}:{server.port} is not blocked"


async def test_src_block_by_port_range(
    xfw: XFW,
    protocol: str,
    ip_version: str,
    server: RegularKernelSocketNetworkStateful,
    client: RegularKernelSocketNetworkStateful,
    establish_connection,
    src_defaults: str,
):
    new_port = client.generate_new_port()
    await xfw.rules_set(f"""
        xfw {{
            defaults {{ src_port {ip_version}: {src_defaults }; }}
            src=extended_group {ip_version}.{protocol} : block {{
                :{client.port}-{new_port}
            }}
        }}
        """)

    assert (
        await check_connection(client, server) is False
    ), f"Client {server.ip_testing}:{server.port} is not blocked"


async def test_src_block_by_multiple_port_range(
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
                :{client.port}-{new_port[0]}
                :{new_port[1]}-{new_port[2]}
            }}
        }}
        """)

    assert (
        await check_connection(client, server) is False
    ), f"Client {server.ip_testing}:{server.port} is not blocked"


async def test_src_block_by_geoip_country(
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
            src=extended_group {ip_version}.{protocol} : block {{ rs }}
        }}
        """)

    assert (
        await check_connection(client, server) is False
    ), f"Client {server.ip_testing}:{server.port} is not blocked"


@pytest.mark.skip("ISSUE: too small pps in tests")
async def test_src_block_by_ratelimit_ip(
    xfw: XFW,
    protocol: str,
    ip_version: str,
    server: RegularKernelSocketNetworkStateful,
    client: RegularKernelSocketNetworkStateful,
    src_defaults,
    establish_connection: str,
):
    await xfw.rules_set(f"""
        xfw {{
            ratelimit=test pps=1 bps=500;
            defaults {{ src_ip {ip_version}: {src_defaults}; }}
            src=extended_group {ip_version}.{protocol} : ratelimit=test {{
                {client.ip_testing}
            }}
        }}
        """)

    assert (
        await check_connection(client, server) is True
    ), f"Client {client.ip_testing}:{client.port} is not allowed"

    assert (
        await check_connection(client, server) is False
    ), f"Client {client.ip_testing}:{client.port} is not blocked"


@pytest.mark.skip("ISSUE: too small pps in tests")
async def test_src_block_by_ratelimit_port(
    xfw: XFW,
    protocol: str,
    ip_version: str,
    server: RegularKernelSocketNetworkStateful,
    client: RegularKernelSocketNetworkStateful,
    src_defaults,
    establish_connection: str,
):
    await xfw.rules_set(f"""
        xfw {{
            ratelimit=test pps=1 bps=500;
            defaults {{ src_port {ip_version}: {src_defaults}; }}
            src=extended_group {ip_version}.{protocol} : ratelimit=test {{
                :{client.port}
            }}
        }}
        """)

    assert (
        await check_connection(client, server) is True
    ), f"Client {client.ip_testing}:{client.port} is not allowed"

    assert (
        await check_connection(client, server) is False
    ), f"Client {client.ip_testing}:{client.port} is not blocked"


async def test_src_block_only_one_protocol_subtype(
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
            defaults {{ src_ip ip4: allow; src_ip ip6: allow;}}
            src {ip_version}.{protocol} : block {{
                {client.ip_testing}
            }}
        }}
        """)

    for new_client, new_server in remaining_client_server_group.items():
        assert (
            await check_connection(new_client, new_server) is True
        ), f"Server {new_server.ip_testing}:{new_server.port} is not allowed"


async def test_src_block_by_ip_mapped(
    xfw: XFW,
    udp_ip4_client: RegularKernelSocketNetworkStateful,
    udp_ip4_mapped_ip6_server: RegularKernelSocketNetworkStateful,
):
    await xfw.rules_set(f"""
        xfw {{
            defaults {{ src_ip ip4: allow; }}
            src=extended_group ip4.udp : block {{
                {udp_ip4_client.ip_testing}
            }}
        }}
        """)

    assert (
        await check_connection(udp_ip4_client, udp_ip4_mapped_ip6_server) is False
    ), f"Client {udp_ip4_client.ip_testing} is not blocked"
