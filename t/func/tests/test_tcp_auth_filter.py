# SPDX-FileCopyrightText: (c) 2026 Tempesta Technologies, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later

import asyncio
import socket

import pytest
from scapy.layers.inet import TCP

from config import ConfigSettings
from framework.asyn import TcpClient, TcpRawClient, TcpRawServer, TcpServer
from framework.cmp import check_connection
from framework.fabrics import client_fabric, server_fabric
from framework.xfw import XFW


@pytest.fixture(scope="session", params=["A", "R"], ids=["ACK", "RST"])
def tcp_flag(request) -> str:
    return request.param


async def test_normal_connection(
    xfw: XFW, tcp_server: TcpServer, tcp_raw_client: TcpRawClient, start_tcp_server_and_raw_clients
):
    """
    It's possible to establish a new connection if
    the filter is turned on
    """
    await xfw.rules_set("xfw { tcp_auth_filter; }")

    assert await tcp_raw_client.handshake() is True
    assert await tcp_raw_client.close_connection() is True


async def test_send_data_after_filter_turned_on(
    xfw: XFW, tcp_server: TcpServer, tcp_client: TcpClient, start_tcp_server_and_clients
):
    """
    It's possible to communicate if the connection
    was established before the filter is turned on
    """
    assert await check_connection(tcp_client, tcp_server) is True

    await xfw.rules_set("xfw { tcp_auth_filter; }")
    assert await check_connection(tcp_client, tcp_server) is True


async def test_block_tcp_flood_from_non_existing_session(
    tcp_flag: str,
    xfw: XFW,
    tcp_raw_server: TcpRawServer,
    tcp_raw_client: TcpRawClient,
    start_tcp_raw_server_and_raw_clients,
):
    """
    Any NON-SYN packets should be blocked if the
    connection was not established with the turned on filter
    """
    await xfw.rules_set("xfw { tcp_auth_filter; }")
    await tcp_raw_client.send_packet(TCP(flags=tcp_flag))

    assert (
        await tcp_raw_server.receive_block()
    ), f"TCP packet with {tcp_flag} without session is not skipped"


@pytest.mark.long
async def test_block_closed_session(
    tcp_flag: str,
    xfw: XFW,
    tcp_raw_server: TcpRawServer,
    tcp_raw_client: TcpRawClient,
    start_tcp_raw_server_and_raw_clients,
):
    """
    If we close the connection with turned on filter,
    the NON-SYN packets should be blocked
    """
    await xfw.rules_set("xfw { tcp_auth_filter; }")

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

    await tcp_raw_client.send_packet(TCP(flags="P") / b"111")
    response = await tcp_raw_server.receive_packet()
    assert response is not None, (
        f"TCP packet with payload immediately after connection close is allowed as the "
        f"session stores till timeout"
    )

    await asyncio.sleep(65)

    await tcp_raw_client.send_packet(TCP(flags="P") / b"111")
    assert (
        await tcp_raw_server.receive_block()
    ), f"TCP packet with payload should be skipped as the connection session is cleared"

    await tcp_raw_client.send_packet(TCP(flags=tcp_flag))
    assert (
        await tcp_raw_server.receive_block()
    ), f"TCP packet with {tcp_flag} without session is not skipped"


async def test_block_reset_session(
    tcp_flag: str,
    xfw: XFW,
    tcp_raw_server: TcpRawServer,
    tcp_raw_client: TcpRawClient,
    start_tcp_raw_server_and_raw_clients,
):
    """
    If we reset the connection with turned on filter,
    the NON-SYN packets should be blocked
    """
    await xfw.rules_set("xfw { tcp_auth_filter; }")

    assert await asyncio.gather(
        tcp_raw_client.handshake(),
        tcp_raw_server.handshake(),
    ) == [True, True], "Client and server can not establish connection"

    assert await asyncio.gather(
        tcp_raw_client.send_data("test_data_1"), tcp_raw_server.receive_data()
    ) == [True, "test_data_1"], "Server has not received the data"

    assert await asyncio.gather(
        tcp_raw_client.reset_send(),
        tcp_raw_server.reset_receive(),
    ) == [True, True], "Server has not received client RST packet"

    await tcp_raw_client.send_packet(TCP(flags="P") / b"111")
    assert (
        await tcp_raw_server.receive_block()
    ), f"TCP packet with payload immediately after connection close is not allowed"

    await tcp_raw_client.send_packet(TCP(flags=tcp_flag))
    assert (
        await tcp_raw_server.receive_block()
    ), f"TCP packet with {tcp_flag} without session is not skipped"


async def test_unblock_non_existing_session(
    xfw: XFW,
    tcp_raw_server: TcpRawServer,
    tcp_raw_client: TcpRawClient,
    start_tcp_raw_server_and_raw_clients,
):
    """
    Turning off the filter have to release the flood
    packets
    """
    await xfw.rules_set("xfw { tcp_auth_filter; }")
    await xfw.rules_patch("xfw { tcp_auth_filter/del; }")

    await tcp_raw_client.send_packet(TCP(flags="A"))

    response = await tcp_raw_server.receive_tcp_flags()
    assert response == "A", f"TCP packet with A without session is not allowed"


async def test_connection_under_filter_resetting(
    xfw: XFW, tcp_server: TcpServer, tcp_client: TcpClient, start_tcp_server_and_clients
):
    """
    If we have the established connection the turning off and
    then turning on the filter should not effect the opened
    connection.
    """
    assert await check_connection(tcp_client, tcp_server) is True

    await xfw.rules_patch("xfw { tcp_auth_filter; }")
    assert await check_connection(tcp_client, tcp_server) is True

    await xfw.rules_patch("xfw { tcp_auth_filter/del; }")
    assert await check_connection(tcp_client, tcp_server) is True

    await xfw.rules_set("xfw { tcp_auth_filter; }")
    assert await check_connection(tcp_client, tcp_server) is True


async def test_clean_stored_session_after_xfw_restart(
    xfw: XFW,
    tcp_server: TcpServer,
    tcp_client: TcpClient,
    start_tcp_server_and_clients,
):
    """
    Restarting the XFW with turned on filter should reset all
    sessions
    """
    await xfw.rules_set("xfw { tcp_auth_filter; }")
    assert await check_connection(tcp_client, tcp_server) is True

    await xfw.restart()
    await xfw.rules_set("xfw { tcp_auth_filter; }")
    assert await check_connection(tcp_client, tcp_server) is False


async def test_allow_tcp_flood_after_connection(
    tcp_flag: str,
    xfw: XFW,
    tcp_raw_server: TcpRawServer,
    tcp_raw_client: TcpRawClient,
    start_tcp_raw_server_and_raw_clients,
):
    """
    Test active filtering for connected users
    """

    await xfw.rules_set("xfw { tcp_auth_filter; }")
    assert await asyncio.gather(
        tcp_raw_client.handshake(),
        tcp_raw_server.handshake(),
    ) == [True, True], "Client and server can not establish connection"

    await tcp_raw_client.send_packet(TCP(flags=tcp_flag))
    assert (
        await tcp_raw_server.receive_tcp_flags() == tcp_flag
    ), f"TCP packet with {tcp_flag} with session is not allowed"


async def test_reset_one_connection_does_not_break_another(
    xfw: XFW,
    tcp_server: TcpServer,
    tcp_client: TcpClient,
    config: ConfigSettings,
    logging_level: int,
    rpc_connection,
):
    """
    Resetting one authenticated TCP connection must not remove the
    authentication state of another connection with the same client
    endpoint but a different server address.
    """
    await xfw.rules_set("xfw { tcp_auth_filter; }")

    first_server_ip, second_server_ip = tcp_server.generate_new_addresses(2)
    server_ip_param = "ipv4" if tcp_server.socket_family == socket.AF_INET else "ipv6"

    first_server = server_fabric(
        config=config,
        logging_level=logging_level,
        rpc_connection=rpc_connection,
        local_class=type(tcp_server),
        remote_class=type(tcp_server),
        port=tcp_server.port,
        echo_mode=True,
        **{server_ip_param: first_server_ip},
    )

    second_server = server_fabric(
        config=config,
        logging_level=logging_level,
        rpc_connection=rpc_connection,
        local_class=type(tcp_server),
        remote_class=type(tcp_server),
        port=tcp_server.port,
        echo_mode=True,
        **{server_ip_param: second_server_ip},
    )

    #
    # Both connections intentionally use the same client IP:port.
    # They differ only by the server address.
    #
    #   client_ip:port -> server1_ip:port
    #   client_ip:port -> server2_ip:port
    #
    first_client = client_fabric(
        config=config,
        logging_level=logging_level,
        local_class=type(tcp_client),
        port=tcp_client.port + 1,
        remote_ip=first_server.ip,
        remote_port=first_server.port,
        reuse_addr=True,
    )

    second_client = client_fabric(
        config=config,
        logging_level=logging_level,
        local_class=type(tcp_client),
        port=tcp_client.port + 1,
        remote_ip=second_server.ip,
        remote_port=second_server.port,
        reuse_addr=True,
    )

    await first_server.start()
    await second_server.start()
    await first_client.start()
    await second_client.start()

    try:
        assert first_client.ip == second_client.ip
        assert first_client.port == second_client.port

        assert first_client.remote_ip != second_client.remote_ip
        assert first_client.remote_port == second_client.remote_port

        # Establish and verify both independent TCP connections.
        await first_client.ping_pong()
        await second_client.ping_pong()

        #
        # Reset only the first connection.
        #
        # With the old endpoint-only TCP AUTH key, both connections had
        # the same authentication key on the server-to-client path:
        #
        #   client_ip:port
        #
        # Therefore, resetting the first connection could remove the
        # authentication state used by the second one.
        #
        first_client.use_rst_for_connection_closing()
        first_client.transport.abort()

        await asyncio.sleep(0)

        # Must use the already established second connection.
        # No reconnect is allowed here.
        await second_client.ping_pong()

    finally:
        await first_client.stop()
        await second_client.stop()
        await first_server.stop()
        await second_server.stop()
