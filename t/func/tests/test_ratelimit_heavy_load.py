# SPDX-FileCopyrightText: (c) 2026 Tempesta Technologies, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later

import asyncio

import pytest
from scapy.layers.inet import TCP, UDP

from framework.asyn import TcpRawClient, TcpRawServer, UdpRawClient
from framework.cmp import RatelimitChecker
from framework.stateful import RegularKernelSocketNetworkStateful
from framework.xfw import XFW, XFWRatelimit, XFWRatelimits

ICMP_IPV4_ECHO_REQUEST = 8
ICMP_IPV6_ECHO_REQUEST = 128


@pytest.fixture(scope="session")
def xfw_block_ratelimit() -> XFWRatelimit:
    return XFWRatelimit(
        name="block",
        pps=0,
        bps=0,
    )


@pytest.fixture(scope="session")
def xfw_high_ratelimit() -> XFWRatelimit:
    return XFWRatelimit(
        name="high",
        pps=1000,
        bps=100000,
    )


@pytest.fixture(scope="session")
def xfw_low_pps_ratelimit() -> XFWRatelimit:
    return XFWRatelimit(
        name="low_pps",
        pps=100,
        bps=100000,
    )


@pytest.fixture(scope="session")
def xfw_low_bps_ratelimit() -> XFWRatelimit:
    return XFWRatelimit(
        name="low_bps",
        pps=1000,
        bps=1000,
    )


@pytest.fixture(scope="session")
def xfw_ratelimits(
    xfw_block_ratelimit,
    xfw_high_ratelimit,
    xfw_low_pps_ratelimit,
    xfw_low_bps_ratelimit,
) -> XFWRatelimits:
    return XFWRatelimits(
        block=xfw_block_ratelimit,
        high=xfw_high_ratelimit,
        low_pps=xfw_low_pps_ratelimit,
        low_bps=xfw_low_bps_ratelimit,
    )


@pytest.fixture(scope="function")
def udp_raw_server(
    udp_server: RegularKernelSocketNetworkStateful,
) -> tuple[RegularKernelSocketNetworkStateful]:
    return udp_server


@pytest.fixture
async def xfw_with_ratelimits(xfw: XFW, xfw_ratelimits: XFWRatelimits) -> XFW:
    limits = "".join(
        f"ratelimit={limit.name} pps={limit.pps} bps={limit.bps};\n" for limit in xfw_ratelimits
    )

    await xfw.rules_set(f"xfw {{\n {limits} }}\n")
    yield xfw


@pytest.fixture
def ratelimit_checker(config) -> RatelimitChecker:
    return RatelimitChecker(config)


@pytest.mark.fail_in_gate_mode("ISSUE: 456")
async def test_icmp_default_ratelimit(
    xfw_with_ratelimits,
    ip_version,
    udp_server,
    icmp_raw_client,
    start_udp_server_and_icmp_clients,
    xfw_low_pps_ratelimit,
    ratelimit_checker,
):
    """
    Verify ICMP ratelimit enforcement under load
    when configured in the defaults section.
    """

    await xfw_with_ratelimits.rules_patch(f"""
        xfw {{
            defaults {{ icmp: ratelimit={xfw_low_pps_ratelimit.name}; }}
        }}
        """)

    await ratelimit_checker.check_pps_ratelimit(
        client=icmp_raw_client,
        limit=xfw_low_pps_ratelimit,
    )


async def test_icmp_ratelimit_override_default_rule(
    xfw_with_ratelimits,
    ip_version,
    udp_server,
    icmp_raw_client,
    start_udp_server_and_icmp_clients,
    xfw_low_pps_ratelimit,
    ratelimit_checker,
):
    """
    Verify that the ratelimit overrides the default action and restricts traffic.
    """
    await xfw_with_ratelimits.rules_patch(f"""
        xfw {{
            defaults {{ icmp: allow; }}
            icmp {ip_version}: ratelimit={xfw_low_pps_ratelimit.name} {{
                {ICMP_IPV4_ECHO_REQUEST}, {ICMP_IPV6_ECHO_REQUEST}
            }}
        }}
        """)

    await ratelimit_checker.check_pps_ratelimit(
        client=icmp_raw_client,
        limit=xfw_low_pps_ratelimit,
    )


async def __check_limits_tcp(
    tcp_raw_server: TcpRawServer,
    tcp_raw_client: TcpRawClient,
    xfw_low_pps_ratelimit,
    ratelimit_checker,
):
    await tcp_raw_client.start()
    await tcp_raw_server.start()

    assert await asyncio.gather(
        tcp_raw_client.handshake(),
        tcp_raw_server.handshake(),
    ) == [True, True], "Client and server can not establish connection"

    async def send_tcp_segment(msg: str = "") -> None:
        await tcp_raw_client.send_packet(TCP(flags="PA") / b"ping")
        packet = await tcp_raw_server.receive_packet()
        assert packet is not None, msg

    await ratelimit_checker.check_pps_ratelimit(
        client=tcp_raw_client, limit=xfw_low_pps_ratelimit, function=send_tcp_segment
    )


async def __check_limits_udp(
    udp_server: RegularKernelSocketNetworkStateful,
    udp_raw_client: UdpRawClient,
    xfw_low_pps_ratelimit,
    ratelimit_checker,
):
    await udp_server.start()
    await udp_raw_client.start()

    async def send_udp_datagram(msg: str = "") -> None:
        await udp_raw_client.send_packet(UDP() / b"ping")
        received = await udp_server.receive_block()
        assert received is not True, msg

    await ratelimit_checker.check_pps_ratelimit(
        client=udp_raw_client, limit=xfw_low_pps_ratelimit, function=send_udp_datagram
    )


async def test_dst_ratelimit(
    xfw_with_ratelimits,
    protocol,
    ip_version,
    tcp_raw_server: TcpRawServer,
    tcp_raw_client: TcpRawClient,
    udp_raw_server: RegularKernelSocketNetworkStateful,
    udp_raw_client: UdpRawClient,
    xfw_low_pps_ratelimit,
    ratelimit_checker,
):
    """
    Verify that the destination-based ratelimit restricts TCP/UDP
    traffic within the allowed range.
    """
    server = locals()[f"{protocol}_raw_server"]
    client = locals()[f"{protocol}_raw_client"]
    server.echo_mode = True

    await xfw_with_ratelimits.rules_patch(f"""
        xfw {{
            defaults {{ dst: block; }}
            dst=extended_group {ip_version}.{protocol} : ratelimit={xfw_low_pps_ratelimit.name} {{
                {server.ip_testing}:{server.port}
            }}
        }}
        """)

    await globals()[f"__check_limits_{protocol}"](
        server, client, xfw_low_pps_ratelimit, ratelimit_checker
    )


async def test_src_ratelimit_by_ip(
    xfw_with_ratelimits,
    protocol,
    ip_version,
    tcp_raw_server: TcpRawServer,
    tcp_raw_client: TcpRawClient,
    udp_raw_server: RegularKernelSocketNetworkStateful,
    udp_raw_client: UdpRawClient,
    xfw_low_pps_ratelimit,
    ratelimit_checker,
):
    """
    Verify that the source-based ratelimit by IP restricts TCP/UDP
    traffic within the allowed range.
    """
    server = locals()[f"{protocol}_raw_server"]
    client = locals()[f"{protocol}_raw_client"]
    server.echo_mode = True

    await xfw_with_ratelimits.rules_patch(f"""
        xfw {{
            defaults {{ src_ip {ip_version}.{protocol}: block; }}
            src=extended_group {ip_version}.{protocol} : ratelimit={xfw_low_pps_ratelimit.name} {{
                {client.ip_testing}
            }}
        }}
        """)

    await globals()[f"__check_limits_{protocol}"](
        server, client, xfw_low_pps_ratelimit, ratelimit_checker
    )


async def test_src_ratelimit_by_port(
    xfw_with_ratelimits,
    protocol,
    ip_version,
    tcp_raw_server: TcpRawServer,
    tcp_raw_client: TcpRawClient,
    udp_raw_server: RegularKernelSocketNetworkStateful,
    udp_raw_client: UdpRawClient,
    xfw_low_pps_ratelimit,
    ratelimit_checker,
):
    """
    Verify that the source-based ratelimit by port restricts TCP/UDP
    traffic within the allowed range.
    """
    server = locals()[f"{protocol}_raw_server"]
    client = locals()[f"{protocol}_raw_client"]
    server.echo_mode = True

    await xfw_with_ratelimits.rules_patch(f"""
        xfw {{
            defaults {{ src_port {ip_version}.{protocol}: block; }}
            src=extended_group {ip_version}.{protocol} : ratelimit={xfw_low_pps_ratelimit.name} {{
                :{client.port}
            }}
        }}
        """)

    await globals()[f"__check_limits_{protocol}"](
        server, client, xfw_low_pps_ratelimit, ratelimit_checker
    )


async def test_block_tcp_syn_flood_by_ratelimit(
    xfw_with_ratelimits,
    tcp_raw_server,
    tcp_raw_client,
    start_tcp_raw_server_and_raw_clients,
    xfw_low_pps_ratelimit,
    ratelimit_checker,
):
    """
    Verify that TCP SYN flood traffic is restricted according to the ratelimit rule.
    """
    await xfw_with_ratelimits.rules_patch(f"""
        xfw {{
            tcp_flags syn : ratelimit={xfw_low_pps_ratelimit.name};
        }}
        """)

    async def send_and_check_tcp_syn(msg: str = "") -> None:
        await tcp_raw_client.send_packet(tcp_raw_client.valid_syn_packet)
        packet = await tcp_raw_server.receive_packet()
        assert packet is not None, msg
        assert tcp_raw_server.has_flag(packet, "S"), msg

    await ratelimit_checker.check_pps_ratelimit(
        client=tcp_raw_client, limit=xfw_low_pps_ratelimit, function=send_and_check_tcp_syn
    )


async def test_block_tcp_rst_flood_by_ratelimit(
    xfw_with_ratelimits,
    tcp_raw_server,
    tcp_raw_client,
    start_tcp_raw_server_and_raw_clients,
    xfw_low_pps_ratelimit,
    ratelimit_checker,
):
    """
    Verify that TCP RST flood traffic is restricted according to the ratelimit rule.
    """
    await xfw_with_ratelimits.rules_patch(f"""
        xfw {{
            tcp_flags rst : ratelimit={xfw_low_pps_ratelimit.name};
        }}
        """)

    async def send_and_check_tcp_rst(msg: str = "") -> None:
        await tcp_raw_client.reset_send()
        packet = await tcp_raw_server.receive_packet()
        assert packet is not None, msg
        assert tcp_raw_server.has_flag(packet, "R"), msg

    await ratelimit_checker.check_pps_ratelimit(
        client=tcp_raw_client, limit=xfw_low_pps_ratelimit, function=send_and_check_tcp_rst
    )
