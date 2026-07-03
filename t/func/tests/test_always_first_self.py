# SPDX-FileCopyrightText: (c) 2026 Tempesta Technologies, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later

import asyncio

import pytest
from scapy.layers.inet import TCP

from framework.asyn import (
    DnsUdpClient,
    DnsUdpServer,
    IcmpRawClient,
    TcpClient,
    TcpRawClient,
    TcpRawServer,
    TcpServer,
    UdpRawClient,
    UdpServer,
)
from framework.cmp import check_connection
from framework.stateful import RegularKernelSocketNetworkStateful
from framework.utils import client_cloner


@pytest.mark.nic_e1000_warmup
async def test_warmup_nic_e1000(
    tcp_server: TcpServer, tcp_client: TcpClient, start_tcp_server_and_clients
):
    assert check_connection(tcp_client, tcp_server) is True


async def test_server_client_connection(
    protocol: str,
    ip_version: str,
    server: RegularKernelSocketNetworkStateful,
    client: RegularKernelSocketNetworkStateful,
    establish_connection,
):
    assert (
        await check_connection(client, server) is True
    ), f"Server ({server.ip}:{server.port}) is not available"


async def test_raw_tcp_client_with_handshake(
    tcp_server: RegularKernelSocketNetworkStateful,
    tcp_raw_client: TcpRawClient,
    start_tcp_server_and_raw_clients,
):
    assert await tcp_raw_client.handshake() is True

    await tcp_raw_client.send(TCP(flags="PA") / b"test_data_1")
    response = await tcp_raw_client.receive()
    assert tcp_raw_client.has_flag(
        response, "A"
    ), f"Unexpected reply packet with flags = {response.flags}. Expected A"

    await tcp_raw_client.send(TCP(flags="PA") / b"test_data_2")
    response = await tcp_raw_client.receive()
    assert tcp_raw_client.has_flag(
        response, "A"
    ), f"Unexpected reply packet with flags = {response.flags}. Expected A"

    assert await tcp_raw_client.close_connection() is True


async def test_raw_udp_client_and_server(
    udp_server: UdpServer, udp_raw_client: UdpRawClient, start_udp_server_and_raw_clients
):
    await udp_raw_client.ping()

    response = await udp_server.receive()
    assert response == "ping"


async def test_icmp_raw_client(
    udp_server: UdpServer, icmp_raw_client: IcmpRawClient, start_udp_server_and_icmp_clients
):
    await icmp_raw_client.ping()
    assert await icmp_raw_client.pong()


async def test_raw_tcp_server_and_client_communication(
    tcp_raw_client: TcpRawClient, tcp_raw_server: TcpRawServer, start_tcp_raw_server_and_raw_clients
):
    assert await asyncio.gather(
        tcp_raw_client.handshake(),
        tcp_raw_server.handshake(),
    ) == [True, True], "Client and server can not establish connection"

    assert await asyncio.gather(
        tcp_raw_client.send_data("test_data_1"), tcp_raw_server.receive_data()
    ) == [True, "test_data_1"], "Server have not received the data"

    assert await asyncio.gather(
        tcp_raw_client.close_connection(),
        tcp_raw_server.close_connection(),
    ) == [True, True], "Client and server can not correctly close the connection"


async def test_dns_udp_client_server(
    dns_udp_server: DnsUdpServer,
    dns_udp_client: DnsUdpClient,
    start_dns_udp_server_and_clients,
):
    await dns_udp_client.send_message()
    assert await dns_udp_server.receive_message() == "google.com."


async def test_raw_socket_tcp_traffic_collisions(
    tcp_raw_client: TcpRawClient,
    tcp_server: TcpServer,
):
    tcp_raw_client_2 = client_cloner(tcp_raw_client, 1)[0]

    await tcp_server.start()
    await tcp_raw_client.start()
    await tcp_raw_client_2.start()

    await tcp_raw_client.send(tcp_raw_client.valid_syn_packet)
    assert await tcp_raw_client_2.receive() is None
    assert await tcp_raw_client.receive() is not None

    await tcp_raw_client_2.stop()
