# SPDX-FileCopyrightText: (c) 2026 Tempesta Technologies, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later
import pytest

from framework.cmp import check_connection
from framework.stateful import RegularKernelSocketNetworkStateful
from framework.xfw import XFW


@pytest.fixture(scope="function")
def clients_tracked_by_dst_filter(
    tcp_ip4_client,
    tcp_ip6_client,
    udp_ip4_client,
    udp_ip6_client,
) -> tuple[RegularKernelSocketNetworkStateful]:
    return (
        tcp_ip4_client,
        tcp_ip6_client,
        udp_ip4_client,
        udp_ip6_client,
    )


@pytest.fixture(scope="function")
def servers_tracked_by_dst_filter(
    tcp_ip4_server,
    tcp_ip6_server,
    udp_ip4_server,
    udp_ip6_server,
) -> tuple[RegularKernelSocketNetworkStateful]:
    return (
        tcp_ip4_server,
        tcp_ip6_server,
        udp_ip4_server,
        udp_ip6_server,
    )


@pytest.fixture(scope="function")
def allowed_clients_tracked_by_dst_filter(
    request, ip_version, ip_versions, protocols
) -> tuple[RegularKernelSocketNetworkStateful]:
    return [
        request.getfixturevalue(f"{protocol}_{ip_}_client")
        for protocol in protocols
        for ip_ in ip_versions
        if ip_version != ip_
    ]


@pytest.fixture(scope="function")
def allowed_servers_tracked_by_dst_filter(
    request, ip_version, ip_versions, protocols
) -> tuple[RegularKernelSocketNetworkStateful]:
    return [
        request.getfixturevalue(f"{protocol}_{ip_}_server")
        for protocol in protocols
        for ip_ in ip_versions
        if ip_version != ip_
    ]


@pytest.fixture(scope="function")
def blocked_clients_tracked_by_dst_filter(
    request, ip_version, ip_versions, protocols
) -> tuple[RegularKernelSocketNetworkStateful]:
    return [
        request.getfixturevalue(f"{protocol}_{ip_version}_client")
        for protocol in protocols
        for ip_ in ip_versions
        if ip_version != ip_
    ]


@pytest.fixture(scope="function")
def blocked_servers_tracked_by_dst_filter(
    request, ip_version, ip_versions, protocols
) -> tuple[RegularKernelSocketNetworkStateful]:
    return [
        request.getfixturevalue(f"{protocol}_{ip_version}_server")
        for protocol in protocols
        for ip_ in ip_versions
        if ip_version != ip_
    ]


async def test_global_allow(
    xfw: XFW,
    clients_tracked_by_dst_filter: tuple[RegularKernelSocketNetworkStateful],
    servers_tracked_by_dst_filter: tuple[RegularKernelSocketNetworkStateful],
):
    """
    The test verifies that when the default policy is set to `dst: allow`,
    network traffic flows seamlessly in all directions between all pairs
    of clients and servers.
    """
    await xfw.rules_set(f"xfw {{ defaults {{ dst: allow; }} }}")
    for client, server in zip(clients_tracked_by_dst_filter, servers_tracked_by_dst_filter):
        assert await check_connection(client, server), f"Server ({server}) is unexpected allowed"

        assert await check_connection(server, client), f"Client ({client}) is unexpected allowed"


async def test_global_block(
    xfw: XFW,
    clients_tracked_by_dst_filter: tuple[RegularKernelSocketNetworkStateful],
    servers_tracked_by_dst_filter: tuple[RegularKernelSocketNetworkStateful],
):
    """
    This test ensures that when the default policy is set to `dst: block`,
    all network traffic between the configured clients and servers is dropped.
    """
    await xfw.rules_set(f"xfw {{ defaults {{ dst: block; }} }}")
    for client, server in zip(clients_tracked_by_dst_filter, servers_tracked_by_dst_filter):
        assert not await check_connection(
            client, server
        ), f"Server ({server.ip_testing}:{server.port}) is unexpected allowed"


async def test_allow(
    xfw: XFW,
    ip_version: str,
    allowed_clients_tracked_by_dst_filter: tuple[RegularKernelSocketNetworkStateful],
    allowed_servers_tracked_by_dst_filter: tuple[RegularKernelSocketNetworkStateful],
    blocked_clients_tracked_by_dst_filter: tuple[RegularKernelSocketNetworkStateful],
    blocked_servers_tracked_by_dst_filter: tuple[RegularKernelSocketNetworkStateful],
):
    """
    This test ensures that when the default policy is set to `dst <ip_version>: block`,
    traffic for the blocked ip version is correctly dropped.
    """
    await xfw.rules_set(f"xfw {{ defaults {{ dst {ip_version}: block; }} }}")

    for client, server in zip(
        allowed_clients_tracked_by_dst_filter, allowed_servers_tracked_by_dst_filter
    ):
        assert await check_connection(client, server), f"Server ({server}) is not allowed"

        assert await check_connection(server, client), f"Client ({client}) is not allowed"

    for client, server in zip(
        blocked_clients_tracked_by_dst_filter, blocked_servers_tracked_by_dst_filter
    ):
        assert not await check_connection(
            client, server
        ), f"Server ({server}) is unexpected allowed"
