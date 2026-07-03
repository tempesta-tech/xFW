# SPDX-FileCopyrightText: (c) 2026 Tempesta Technologies, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later

import asyncio

import pytest

from framework.cmp import check_connection
from framework.stateful import RegularKernelSocketNetworkStateful
from framework.xfw import XFW
from tests.conftest import ip_version


@pytest.fixture
def true_if_allowed(src_defaults: str) -> bool:
    allow = src_defaults == "allow"
    yield allow


@pytest.fixture
def error_message(true_if_allowed, server):
    msg = f"Server {server.ip_testing}:{server.port} is not blocked"

    if true_if_allowed:
        msg = f"Server {server.ip_testing}:{server.port} is not allowed"

    yield msg


@pytest.mark.skip("ISSUE: 253")
async def test_src_add_block_by_multiple_port_range_with_crossing_port_ranges(
    xfw: XFW,
    protocol: str,
    ip_version: str,
    server: RegularKernelSocketNetworkStateful,
    client: RegularKernelSocketNetworkStateful,
    establish_connection,
    src_defaults: str,
):
    new_port = client.generate_new_ports(4)

    await xfw.rules_set(f"""
        xfw {{
            defaults {{ src_ip ip4: {src_defaults}; src_ip ip6: {src_defaults}; }}
            src=extended_group {ip_version}.{protocol} : block {{
                :{new_port[2]}-{new_port[3]}
            }}
        }}
        """)
    await xfw.rules_patch(f"""
        xfw {{
            src=extended_group/add {ip_version}.{protocol} : block {{
                :{new_port[1]}-{new_port[2]},
                :{client.port}-{new_port[0]}
            }}
        }}
        """)
    assert (
        await check_connection(client, server) is False
    ), f"Client {server.ip_testing}:{server.port} is not blocked"


async def test_src_block_by_port_range_with_spaced_dash_between_ports(
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
            defaults {{ src_ip {ip_version}: {src_defaults}; }}
            src=extended_group {ip_version}.{protocol} : block {{
                :{client.port} - {new_port}
            }}
        }}
        """)

    assert (
        await check_connection(client, server) is False
    ), f"Client {server.ip_testing}:{server.port} is not blocked"


async def test_src_change_ratelimit(
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
                ratelimit=a pps=0 bps=0;
                ratelimit=b pps=10 bps=1000;
                defaults {{ src_ip {ip_version}: {src_defaults}; }}
                src=extended_group {ip_version}.{protocol} : ratelimit=a {{
                    {client.ip_testing}
                }}
            }}
        """)

    assert (
        await check_connection(client, server) is False
    ), f"Server {server.ip_testing}:{server.port} is not blocked"

    await xfw.rules_patch(f"""
        xfw {{
            src=extended_group {ip_version}.{protocol} : ratelimit=b {{
                {client.ip_testing}
            }}
        }}
        """)

    # Wait until the retransmission from the previous message is handled.
    # Correct sleep with -1 second when #520 is closed.
    # Also old src ratelimits continue to work one more second after
    # reconfiguration so until #8 is done, we need +1 seconds here.
    await asyncio.sleep(2)

    assert (
        await check_connection(client, server) is True
    ), f"Server {server.ip_testing}:{server.port} is not allowed"


async def test_src_change_ratelimit_value(
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
                ratelimit=a pps=0 bps=0;
                defaults {{ src_ip {ip_version}: {src_defaults}; }}
                src=extended_group {ip_version}.{protocol} : ratelimit=a {{
                    {client.ip_testing}
                }}
            }}
        """)

    assert (
        await check_connection(client, server) is False
    ), f"Server {server.ip_testing}:{server.port} is not blocked"

    await xfw.rules_patch(f"""
        xfw {{
            ratelimit=b pps=10 bps=1000;
            src=extended_group {ip_version}.{protocol} : ratelimit=b {{
                {client.ip_testing}
            }}
        }}
        """)

    # Wait until the retransmission from the previous message is handled.
    # Correct sleep with -1 second when #520 is closed.
    # Also old src ratelimits continue to work one more second after
    # reconfiguration so until #8 is done, we need +1 seconds here.
    await asyncio.sleep(2)

    assert (
        await check_connection(client, server) is True
    ), f"Server {server.ip_testing}:{server.port} is not allowed"


async def test_src_switch_ratelimit_to_another_rule(
    xfw: XFW,
    protocol: str,
    ip_version: str,
    server: RegularKernelSocketNetworkStateful,
    client: RegularKernelSocketNetworkStateful,
    establish_connection,
    src_defaults: str,
    true_if_allowed: bool,
    error_message: str,
):

    await xfw.rules_set(f"""
            xfw {{
                ratelimit=a pps=10 bps=1000;
                defaults {{ src_ip {ip_version}: block; }}
                src=extended_group {ip_version}.{protocol} : ratelimit=a {{
                    {client.ip_testing}
                }}
            }}
        """)
    assert await check_connection(client, server) is True, "Server is not allowed"

    await xfw.rules_patch(f"""
        xfw {{
            src=extended_group {ip_version}.{protocol} : {src_defaults} {{
                {client.ip_testing}
            }}
        }}
        """)

    # Wait until the retransmission from the previous message is handled.
    # Correct sleep with -1 second when #520 is closed.
    # Also old src ratelimits continue to work one more second after
    # reconfiguration so until #8 is done, we need +1 seconds here.
    await asyncio.sleep(2)

    # we receive 3 times allowed or blocked, where ratelimit is 1
    assert await check_connection(client, server) is true_if_allowed, error_message
    assert await check_connection(client, server) is true_if_allowed, error_message
    assert await check_connection(client, server) is true_if_allowed, error_message


async def test_src_block_port_range_and_allow_some_of_them(
    xfw: XFW,
    protocol: str,
    ip_version: str,
    server: RegularKernelSocketNetworkStateful,
    client: RegularKernelSocketNetworkStateful,
):
    client.port = 53

    await server.start()
    await client.start()

    with pytest.raises(ValueError):
        await xfw.rules_set(f"""
                xfw {{
                    defaults {{ src_port: block; }}
                    ratelimit=test pps=100 bps=10000;
                    
                    src=dangerous_clients {ip_version}.{protocol} : block {{
                        :1-49152
                    }}
                    
                    src=dns {ip_version}.{protocol} : ratelimit=test {{
                        :{client.port}
                    }}
                }}
            """)
        assert await check_connection(client, server) is False, "Client is allowed"


async def test_recommended_config(
    xfw: XFW,
    tcp_ip4_server: RegularKernelSocketNetworkStateful,
    tcp_ip4_client: RegularKernelSocketNetworkStateful,
):
    tcp_ip4_client.port = 10000
    await tcp_ip4_server.start()
    await tcp_ip4_client.start()

    await xfw.rules_set(f"""
        xfw {{
            # Block by default all Incoming traffic
            defaults {{ 
                src_port ip4: block;
            }}

            # Anti DNS-Reflection
            dns_filter;
            # Anti TCP Broken Packets
            tcp_anomaly_filter;
            # Anti SYN-ACK, RST Flood
            tcp_auth_filter; 
            
            # Ratelimit the APP
            ratelimit=whitelisted_rl pps=10000 bps=10000000;
            dst=MY_UDP_APP ip4.tcp : ratelimit=whitelisted_rl {{
                 {tcp_ip4_server.ip_testing}:{tcp_ip4_server.port}
            }}
            # Anti SYN Flood
            ratelimit=syn_rl pps=100 bps=100000;
            tcp_flags syn : ratelimit=syn_rl;

            # Anti RST Flood
            ratelimit=rst_rl pps=100 bps=100000;
            tcp_flags rst : ratelimit=rst_rl;
            
            # Restricted whitelist sources

            # Block all system and user ports, allow only dynamic
            
            # Allow also DNS, HTTP, HTTPS to host regular services
            ratelimit=whitelisted_app_rl  pps=10000 bps=10000000;
            src=allowed_apps_tcp ip4.tcp : ratelimit=whitelisted_app_rl {{
                :32768-65535,
                :22,
                :80,
                :443,
                :{tcp_ip4_client.port}
            }}
            src=allowed_apps_udp ip4.udp : ratelimit=whitelisted_app_rl {{
                :32768-65535,
                :53
            }}
        }}
        """)
    assert await check_connection(tcp_ip4_client, tcp_ip4_server) is True, "Client is blocked"
