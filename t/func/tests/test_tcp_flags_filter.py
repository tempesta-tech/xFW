# SPDX-FileCopyrightText: (c) 2026 Tempesta Technologies, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later

import asyncio

import pytest
from scapy.layers.inet import TCP

from framework.asyn import TcpRawClient, TcpRawServer
from framework.stateful import RegularKernelSocketNetworkStateful
from framework.xfw import XFW


@pytest.fixture
def packets(tcp_raw_client: TcpRawClient) -> dict[str, TCP]:
    rst_packet = tcp_raw_client.valid_syn_packet
    rst_packet.flags = "R"

    return {
        "syn": tcp_raw_client.valid_syn_packet,
        "rst": rst_packet,
    }


@pytest.fixture(params=["syn", "rst"])
def blocking_packet_name(request) -> str:
    return request.param


@pytest.fixture
def blocking_packet(
    packets: dict[str, TCP], blocking_packet_name: str, tcp_raw_client: TcpRawClient
) -> TCP:
    if blocking_packet_name == "syn":
        return packets["syn"]

    return packets["rst"]


@pytest.fixture
def non_blocking_packet(
    packets: dict[str, TCP],
    blocking_packet_name: str,
) -> TCP:
    if blocking_packet_name == "syn":
        return packets["rst"]

    return packets["syn"]


async def test_block_by_ratelimit(
    blocking_packet_name: str,
    blocking_packet: TCP,
    non_blocking_packet: TCP,
    xfw: XFW,
    tcp_raw_server: TcpRawServer,
    tcp_raw_client: TcpRawClient,
    start_tcp_raw_server_and_raw_clients,
):
    """
    Verify that specific TCP flags configured with pps=0 ratelimit
    correctly block matching packets.
    """
    await xfw.rules_set(f"""
        xfw {{
            ratelimit=test pps=0 bps=1000;
            tcp_flags {blocking_packet_name} : ratelimit=test;
        }}
        """)

    await tcp_raw_client.send_packet(blocking_packet)
    assert await tcp_raw_server.receive_block()


async def test_change_ratelimit(
    blocking_packet_name: str,
    blocking_packet: TCP,
    xfw: XFW,
    tcp_raw_server: TcpRawServer,
    tcp_raw_client: TcpRawClient,
    start_tcp_raw_server_and_raw_clients,
):
    """
    Verify that updating a ratelimit profile to pps=0
    correctly blocks subsequent matching packets.
    """
    await xfw.rules_set(f"""
        xfw {{
            ratelimit=test pps=100 bps=1000;
            tcp_flags {blocking_packet_name} : ratelimit=test;
        }}
        """)

    await tcp_raw_client.send_packet(blocking_packet)
    assert await tcp_raw_server.receive_packet()

    await xfw.rules_set(f"""
        xfw {{
            ratelimit=test pps=0 bps=1000;
            tcp_flags {blocking_packet_name} : ratelimit=test;
        }}
        """)

    await tcp_raw_client.send_packet(blocking_packet)
    assert await tcp_raw_server.receive_packet() is None


async def test_del_ratelimit(
    blocking_packet_name: str,
    blocking_packet: TCP,
    xfw: XFW,
    tcp_raw_server: TcpRawServer,
    tcp_raw_client: TcpRawClient,
    start_tcp_raw_server_and_raw_clients,
):
    """
    Verify that removing a TCP flags rule via tcp_flags/del operation
    correctly unblocks matching packets.
    """
    await xfw.rules_set(f"""
        xfw {{ 
            ratelimit=test pps=0 bps=1000;
            tcp_flags {blocking_packet_name} : ratelimit=test; 
        }}
        """)
    await xfw.rules_patch(f"""
        xfw {{ 
            tcp_flags/del {blocking_packet_name}; 
        }}
        """)

    await tcp_raw_client.send_packet(blocking_packet)
    assert await tcp_raw_server.receive_packet()
