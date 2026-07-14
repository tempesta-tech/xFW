# SPDX-FileCopyrightText: (c) 2026 Tempesta Technologies, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later

"""
IPv4/ICMP Request/Response Types
https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml

IPv6/ICMP Reqeust/Response Types
https://www.iana.org/assignments/icmpv6-parameters/icmpv6-parameters.xhtml
"""

import asyncio

import pytest

from framework.asyn import IcmpRawClient, UdpServer
from framework.xfw import XFW

ICMP_IPV4_ECHO_REPLY = 0
ICMP_IPV4_ECHO_REQUEST = 8
ICMP_IPV6_ECHO_REQUEST = 128
ICMP_IPV6_ECHO_REPLY = 129
ICMP_IPV6_NEIGHBOR_SOLICITATION = 135
ICMP_IPV6_NEIGHBOR_ADVERTISEMENT = 136

ICMP_BLOCKING_TYPES = [
    ICMP_IPV4_ECHO_REPLY,
    ICMP_IPV4_ECHO_REQUEST,
    ICMP_IPV6_ECHO_REQUEST,
    ICMP_IPV6_ECHO_REPLY,
    ICMP_IPV6_NEIGHBOR_SOLICITATION,
    ICMP_IPV6_NEIGHBOR_ADVERTISEMENT,
]
ICMP_BLOCKING_TYPES_STR = ", ".join(map(str, ICMP_BLOCKING_TYPES))


async def test_allowed(
    xfw: XFW,
    udp_server: UdpServer,
    icmp_raw_client: IcmpRawClient,
    start_udp_server_and_icmp_clients,
):
    await xfw.rules_set("xfw { }")

    await icmp_raw_client.ping()
    assert await icmp_raw_client.pong()


async def test_default_block(
    xfw: XFW,
    ip_version: str,
    udp_server: UdpServer,
    icmp_raw_client: IcmpRawClient,
    start_udp_server_and_icmp_clients,
):
    await xfw.rules_set(f"xfw {{ defaults {{ icmp: block; }} }}")

    await icmp_raw_client.ping()
    assert await icmp_raw_client.pong() is False


async def test_allow_by_type(
    xfw: XFW,
    ip_version: str,
    udp_server: UdpServer,
    icmp_raw_client: IcmpRawClient,
    start_udp_server_and_icmp_clients,
):
    await xfw.rules_set(f"""
        xfw {{ 
            defaults {{ icmp {ip_version}: block;}}
            icmp {ip_version}: allow {{ {ICMP_BLOCKING_TYPES_STR} }}
        }}
        """)

    await icmp_raw_client.ping()
    assert await icmp_raw_client.pong() is True


async def test_block_by_type(
    xfw: XFW,
    ip_version: str,
    udp_server: UdpServer,
    icmp_raw_client: IcmpRawClient,
    start_udp_server_and_icmp_clients,
):
    await xfw.rules_set(f"""
        xfw {{ 
            defaults {{ icmp: allow; }}
            icmp {ip_version}: block {{ {ICMP_BLOCKING_TYPES_STR} }}
        }}
        """)

    await icmp_raw_client.ping()
    assert await icmp_raw_client.pong() is False


@pytest.mark.fail_in_gate_mode("ISSUE: 456, 39")
async def test_default_ratelimit(
    xfw: XFW,
    ip_version: str,
    udp_server: UdpServer,
    icmp_raw_client: IcmpRawClient,
    start_udp_server_and_icmp_clients,
):
    await xfw.rules_set(f"""
        xfw {{
            ratelimit=test pps=5 bps=5000;
            defaults {{ icmp: ratelimit=test; }}
        }}
        """)

    await asyncio.gather(*[icmp_raw_client.ping() for _ in range(10)])
    requests = await asyncio.gather(*[icmp_raw_client.pong() for _ in range(10)])

    assert len([request for request in requests if request]) == 5


@pytest.mark.skip("ISSUE: 39 (xFW)")
async def test_block_by_ratelimit(
    xfw: XFW,
    ip_version: str,
    udp_server: UdpServer,
    icmp_raw_client: IcmpRawClient,
    start_udp_server_and_icmp_clients,
):
    echo_request = {"ip4": ICMP_IPV4_ECHO_REQUEST, "ip6": ICMP_IPV6_ECHO_REQUEST}.get(ip_version)

    await xfw.rules_set(f"""
        xfw {{
            ratelimit=test pps=5 bps=5000;
            defaults {{ icmp: allow; }}
            icmp {ip_version}: ratelimit=test {{ {echo_request} }}
        }}
        """)

    await asyncio.gather(*[icmp_raw_client.ping() for _ in range(10)])
    requests = await asyncio.gather(*[icmp_raw_client.pong() for _ in range(10)])
    assert len([request for request in requests if request]) == 5


async def test_block_by_src_filter(
    xfw: XFW,
    ip_version: str,
    udp_server: UdpServer,
    icmp_raw_client: IcmpRawClient,
    start_udp_server_and_icmp_clients,
):
    await xfw.rules_set(f"""
        xfw {{
            defaults {{ icmp: allow; src_ip: block; }}
        }}
        """)

    await icmp_raw_client.ping()
    assert await icmp_raw_client.pong() is False, "ICMP packet is not blocked by src filter"
