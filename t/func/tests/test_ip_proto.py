# SPDX-FileCopyrightText: (c) 2026 Tempesta Technologies, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later
import pytest


async def test_block_by_default_gre(
    xfw, gre_raw_client, gre_raw_server, start_gre_server_and_gre_clients, flush_arp_cache
):
    """Verify that xFW block GRE packets by default."""
    await xfw.rules_set("xfw { }")
    await gre_raw_client.ping()
    assert await gre_raw_server.receive_block()


async def test_allow_icmp_by_default(xfw, icmp_raw_client, udp_server, flush_arp_cache):
    """Verify that xFW allow ICMP and ICMPv6 packets by default."""
    await udp_server.start()
    await icmp_raw_client.start()

    await xfw.rules_set("xfw { }")

    await icmp_raw_client.ping_pong()


@pytest.mark.parametrize(
    "dynamic_client,dynamic_server",
    [
        pytest.param("tcp_client", "tcp_server", id="tcp"),
        pytest.param("udp_client", "udp_server", id="udp"),
    ],
    indirect=["dynamic_client", "dynamic_server"],
)
async def test_allow_by_default(xfw, dynamic_client, dynamic_server, flush_arp_cache):
    """Verify that xFW allow TCP/UDP packets by default."""
    await dynamic_server.start()
    await dynamic_client.start()

    await xfw.rules_set("xfw { }")

    await dynamic_client.ping()
    assert await dynamic_server.pong()

    await dynamic_server.ping()
    assert await dynamic_client.pong()


@pytest.mark.parametrize(
    "dynamic_client,dynamic_server,proto_config",
    [
        pytest.param("tcp_client", "tcp_server", "1, 6, 58", id="tcp"),
        pytest.param("udp_client", "udp_server", "1, 17, 58", id="udp"),
        pytest.param("gre_raw_client", "gre_raw_server", "47, 58", id="gre"),
        pytest.param("icmp_raw_client", "icmp_raw_client", "1, 58", id="icmp"),
    ],
    indirect=["dynamic_client", "dynamic_server"],
)
async def test_allow(xfw, dynamic_client, dynamic_server, proto_config, flush_arp_cache):
    """
    Verify that xFW allows packet type with ip_proto correct {<proto_type>, 58}.
    58 - allows ICMPv6 that requires for IPv6.
    """
    await dynamic_server.start()
    await dynamic_client.start()

    await xfw.rules_set(f"xfw {{ ip_proto {{ {proto_config} }} }}")

    await dynamic_client.ping()
    await dynamic_server.pong()

    await dynamic_server.ping()
    await dynamic_client.pong()


@pytest.mark.parametrize(
    "dynamic_client,dynamic_server,proto_config",
    [
        pytest.param("tcp_client", "tcp_server", "1, 17, 47, 58", id="tcp"),
        pytest.param("udp_client", "udp_server", "1, 6, 47, 58", id="udp"),
        pytest.param("gre_raw_client", "gre_raw_server", "1, 6, 17, 58", id="gre"),
        pytest.param("icmp_raw_client", "udp_server", "6, 17, 47", id="icmp"),
    ],
    indirect=["dynamic_client", "dynamic_server"],
)
async def test_block(xfw, dynamic_client, dynamic_server, proto_config, flush_arp_cache):
    """
    Verify that xFW blocks an undeclared proto.
    """
    await dynamic_server.start()
    await dynamic_client.start()

    await xfw.rules_set(f"xfw {{ ip_proto {{ {proto_config} }} }}")

    await dynamic_client.ping()
    assert await dynamic_server.receive_block()


@pytest.mark.parametrize(
    "packet_method",
    [
        pytest.param("prepare_tcp_packet", id="tcp"),
        pytest.param("prepare_udp_packet", id="udp"),
        pytest.param("prepare_icmp_packet", id="icmp"),
    ],
)
async def test_ignore_internal_packets(
    xfw,
    gre_raw_client,
    gre_raw_server,
    start_gre_server_and_gre_clients,
    flush_arp_cache,
    packet_method,
):
    """
    Verify that xFW ignores internal packets encapsulated within GRE.

    Ensures that the xfw does not inspect inner payloads (e.g., TCP, UDP) inside the GRE tunnel.
    """
    await xfw.rules_set("xfw { ip_proto {47, 58} }")

    client_packet = getattr(gre_raw_client, packet_method)("ping")
    await gre_raw_client.send_packet(client_packet)
    await gre_raw_server.receive_expected_packet(client_packet)

    server_packet = getattr(gre_raw_server, packet_method)("pong")
    await gre_raw_server.send_packet(server_packet)
    await gre_raw_client.receive_expected_packet(server_packet)
