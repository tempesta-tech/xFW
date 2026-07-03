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


async def test_normal_connection(
    xfw: XFW,
    tcp_server: RegularKernelSocketNetworkStateful,
    tcp_raw_client: TcpRawClient,
    start_tcp_server_and_raw_clients,
):
    await xfw.rules_set("""
        xfw { 
            ratelimit=test pps=1000 bps=1000;
            tcp_flags syn : ratelimit=test; 
            tcp_flags rst : ratelimit=test; 
        }
        """)

    assert await tcp_raw_client.handshake() is True
    assert await tcp_raw_client.close_connection() is True


async def test_block(
    blocking_packet_name: str,
    blocking_packet: TCP,
    non_blocking_packet: TCP,
    xfw: XFW,
    tcp_raw_server: TcpRawServer,
    tcp_raw_client: TcpRawClient,
    start_tcp_raw_server_and_raw_clients,
):
    await xfw.rules_set(f"""
        xfw {{
            ratelimit=test pps=5 bps=1000;
            tcp_flags {blocking_packet_name} : ratelimit=test;
        }}
        """)

    await asyncio.gather(*[tcp_raw_client.send(blocking_packet) for _ in range(10)])
    assert await tcp_raw_server.receive_many_packets(10) == 5

    await asyncio.gather(*[tcp_raw_client.send(non_blocking_packet) for _ in range(10)])
    assert await tcp_raw_server.receive_many_packets(10) == 10


async def test_change_limits(
    blocking_packet_name: str,
    blocking_packet: TCP,
    non_blocking_packet: TCP,
    xfw: XFW,
    tcp_raw_server: TcpRawServer,
    tcp_raw_client: TcpRawClient,
    start_tcp_raw_server_and_raw_clients,
):
    await xfw.rules_set(f"""
        xfw {{
            ratelimit=test pps=7 bps=1000;
            tcp_flags {blocking_packet_name} : ratelimit=test;
        }}
        """)

    await xfw.rules_set(f"""
        xfw {{
            ratelimit=test pps=4 bps=1000;
            tcp_flags {blocking_packet_name} : ratelimit=test;
        }}
        """)
    await asyncio.gather(*[tcp_raw_client.send(blocking_packet) for _ in range(10)])
    requests = await asyncio.gather(*[tcp_raw_server.receive() for _ in range(10)])
    assert len([request for request in requests if request]) == 4

    await asyncio.gather(*[tcp_raw_client.send(non_blocking_packet) for _ in range(10)])
    requests = await asyncio.gather(*[tcp_raw_server.receive() for _ in range(10)])
    assert len([request for request in requests if request]) == 10


async def test_unblock(
    blocking_packet_name: str,
    blocking_packet: TCP,
    xfw: XFW,
    tcp_raw_server: TcpRawServer,
    tcp_raw_client: TcpRawClient,
    start_tcp_raw_server_and_raw_clients,
):
    await xfw.rules_set(f"""
        xfw {{ 
            ratelimit=test pps=5 bps=1000;
            tcp_flags {blocking_packet_name} : ratelimit=test; 
        }}
        """)
    await xfw.rules_patch(f"""
        xfw {{ 
            tcp_flags/del {blocking_packet_name}; 
        }}
        """)

    await asyncio.gather(*[tcp_raw_client.send(blocking_packet) for _ in range(10)])
    assert await tcp_raw_server.receive_many_packets() == 10
