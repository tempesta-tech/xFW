# SPDX-FileCopyrightText: (c) 2026 Tempesta Technologies, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later

from framework.stateful import RegularKernelSocketNetworkStateful
from framework.xfw import XFW
from framework.cmp import check_connection


async def test_src_allow_by_ip(
        xfw: XFW,
        protocol: str,
        ip_version: str,
        server: RegularKernelSocketNetworkStateful,
        client: RegularKernelSocketNetworkStateful,
        src_defaults,
        establish_connection: str
):
    await xfw.rules_set(
        f'''
        xfw {{
            defaults {{ src_ip {ip_version}: {src_defaults}; }}
            src=extended_group {ip_version}.{protocol} : allow {{
                {client.ip_testing}
            }}
        }}
        '''
    )

    assert await check_connection(client, server) is True, \
        f'Client {server.ip_testing}:{server.port} is not allowed'


async def test_src_allow_by_multiple_ip(
        xfw: XFW,
        protocol: str,
        ip_version: str,
        server: RegularKernelSocketNetworkStateful,
        client: RegularKernelSocketNetworkStateful,
        establish_connection,
        src_defaults: str
):
    new_ip = client.generate_new_address()

    await xfw.rules_set(
        f'''
        xfw {{
            defaults {{ src_ip {ip_version}: {src_defaults}; }}
            src=extended_group {ip_version}.{protocol} : allow {{
                {client.ip_testing}
                {client.ip_format(new_ip)}
            }}
        }}
        '''
    )

    assert await check_connection(client, server) is True, \
        f'Client {server.ip_testing}:{server.port} is not allowed'


async def test_src_allow_by_mask(
        xfw: XFW,
        protocol: str,
        ip_version: str,
        server: RegularKernelSocketNetworkStateful,
        client: RegularKernelSocketNetworkStateful,
        establish_connection,
        src_defaults: str
):
    await xfw.rules_set(
        f'''
        xfw {{
            defaults {{ src_ip {ip_version}: {src_defaults}; }}
            src=extended_group {ip_version}.{protocol} : allow {{
                {client.mask_formatted}
            }}
        }}
        '''
    )

    assert await check_connection(client, server) is True, \
        f'Client {server.ip_testing}:{server.port} is not allowed'


async def test_src_allow_by_multiple_mask(
        xfw: XFW,
        protocol: str,
        ip_version: str,
        server: RegularKernelSocketNetworkStateful,
        client: RegularKernelSocketNetworkStateful,
        establish_connection,
        src_defaults: str
):
    new_ip = client.generate_new_address()

    await xfw.rules_set(
        f'''
        xfw {{
            defaults {{ src_ip {ip_version}: {src_defaults}; }}
            src=extended_group {ip_version}.{protocol} : allow {{
                {client.mask_formatted}
                {client.mask_format(new_ip)}
            }}
        }}
        '''
    )

    assert await check_connection(client, server) is True, \
        f'Client {server.ip_testing}:{server.port} is not allowed'


async def test_src_allow_by_port(
        xfw: XFW,
        protocol: str,
        ip_version: str,
        server: RegularKernelSocketNetworkStateful,
        client: RegularKernelSocketNetworkStateful,
        establish_connection,
        src_defaults: str
):
    await xfw.rules_set(
        f'''
        xfw {{
            defaults {{ src_port {ip_version}: {src_defaults }; }}
            src=extended_group {ip_version}.{protocol} : allow {{
                :{client.port}
            }}
        }}
        '''
    )

    assert await check_connection(client, server) is True, \
        f'Client {server.ip_testing}:{server.port} is not allowed'


async def test_src_allow_by_multiple_port(
        xfw: XFW,
        protocol: str,
        ip_version: str,
        server: RegularKernelSocketNetworkStateful,
        client: RegularKernelSocketNetworkStateful,
        establish_connection,
        src_defaults: str
):
    new_port = client.generate_new_port()

    await xfw.rules_set(
        f'''
        xfw {{
            defaults {{ src_port {ip_version}: {src_defaults }; }}
            src=extended_group {ip_version}.{protocol} : allow {{
                :{client.port}
                :{new_port}
            }}
        }}
        '''
    )

    assert await check_connection(client, server) is True, \
        f'Client {server.ip_testing}:{server.port} is not allowed'


async def test_src_allow_by_port_range(
        xfw: XFW,
        protocol: str,
        ip_version: str,
        server: RegularKernelSocketNetworkStateful,
        client: RegularKernelSocketNetworkStateful,
        establish_connection,
        src_defaults: str
):
    new_port = client.generate_new_port()
    await xfw.rules_set(
        f'''
        xfw {{
            defaults {{ src_port {ip_version}: {src_defaults }; }}
            src=extended_group {ip_version}.{protocol} : allow {{
                :{client.port}-{new_port}
            }}
        }}
        '''
    )

    assert await check_connection(client, server) is True, \
        f'Client {server.ip_testing}:{server.port} is not allowed'


async def test_src_allow_by_multiple_port_range(
        xfw: XFW,
        protocol: str,
        ip_version: str,
        server: RegularKernelSocketNetworkStateful,
        client: RegularKernelSocketNetworkStateful,
        establish_connection,
        src_defaults: str
):
    new_port = client.generate_new_ports(3)

    await xfw.rules_set(
        f'''
        xfw {{
            defaults {{ src_port {ip_version}: {src_defaults }; }}
            src=extended_group {ip_version}.{protocol} : allow {{
                :{client.port}-{new_port[0]}
                :{new_port[1]}-{new_port[2]}
            }}
        }}
        '''
    )

    assert await check_connection(client, server) is True, \
        f'Client {server.ip_testing}:{server.port} is not allowed'


async def test_src_allow_by_geoip_country(
        xfw_geoip: XFW,
        protocol: str,
        ip_version: str,
        server: RegularKernelSocketNetworkStateful,
        client: RegularKernelSocketNetworkStateful,
        establish_connection,
        src_defaults: str
):
    await xfw_geoip.rules_set(
        f'''
        xfw {{
            defaults {{ src_ip {ip_version}: {src_defaults }; }}
            src=extended_group {ip_version}.{protocol} : allow {{ rs }}
        }}
        '''
    )

    assert await check_connection(client, server) is True, \
        f'Client {server.ip_testing}:{server.port} is not allowed'


async def test_src_allow_by_ratelimit(
        xfw: XFW,
        protocol: str,
        ip_version: str,
        server: RegularKernelSocketNetworkStateful,
        client: RegularKernelSocketNetworkStateful,
        src_defaults,
        establish_connection: str
):
    await xfw.rules_set(
        f'''
        xfw {{
            ratelimit=test pps=5 bps=500;
            defaults {{ src_ip {ip_version}: {src_defaults}; }}
            src=extended_group {ip_version}.{protocol} : ratelimit=test {{
                {client.ip_testing}
            }}
        }}
        '''
    )

    assert await check_connection(client, server) is True, \
        f'Client {server.ip_testing}:{server.port} is not allowed'


async def test_src_allow_only_one_protocol_subtype(
        xfw: XFW,
        protocol: str,
        ip_version: str,
        client: RegularKernelSocketNetworkStateful,
        remaining_client_server_group: dict[RegularKernelSocketNetworkStateful, RegularKernelSocketNetworkStateful],
):
    await xfw.rules_set(
        f"""
        xfw {{
            defaults {{ src_ip ip4: block; src_ip ip6: block;}}
            src {ip_version}.{protocol} : allow {{
                {client.ip_testing}
            }}
        }}
        """
    )

    for new_client, new_server in remaining_client_server_group.items():
        assert await check_connection(new_client, new_server) is False, \
            f'Server {new_server.ip_testing}:{new_server.port} is not blocked'
