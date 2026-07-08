# SPDX-FileCopyrightText: (c) 2026 Tempesta Technologies, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later

import pytest
from pytest import FixtureRequest

from config import ConfigSettings
from framework.asyn import *
from framework.stateful import RegularKernelSocketNetworkStateful


@pytest.fixture
def server(
    config: ConfigSettings, request: FixtureRequest, protocol: str, ip_version: str
) -> RegularKernelSocketNetworkStateful:
    return request.getfixturevalue(f"{protocol}_{ip_version}_server")


@pytest.fixture
def client(request: FixtureRequest, protocol, ip_version) -> RegularKernelSocketNetworkStateful:
    return request.getfixturevalue(f"{protocol}_{ip_version}_client")


@pytest.fixture(scope="function")
def dynamic_client(request: pytest.FixtureRequest, ip_version) -> SocketBaseNetworkStateful:
    """
    Dynamically returns a client instance based on test parameters.

    How it works:
    1. Receives the target fixture name as a string via `request.param`.
    2. Uses `getfixturevalue` to dynamically resolve and initialize that fixture.
    3. Depend on `ip_version` to ensure the correct IP context is applied.
    """
    return request.getfixturevalue(request.param)


@pytest.fixture(scope="function")
def dynamic_server(request: pytest.FixtureRequest, ip_version) -> SocketBaseNetworkStateful:
    """
    Dynamically returns a server instance based on test parameters.

    How it works:
    1. Receives the target fixture name as a string via `request.param`.
    2. Uses `getfixturevalue` to dynamically resolve and initialize that fixture.
    3. Depend on `ip_version` to ensure the correct IP context is applied.
    """
    return request.getfixturevalue(request.param)


@pytest.fixture
async def establish_connection(client, server):
    await server.start()
    await client.start()
    yield


@pytest.fixture
def remaining_client_server_group(
    client: RegularKernelSocketNetworkStateful,
    server: RegularKernelSocketNetworkStateful,
    udp_ip4_client: RegularKernelSocketNetworkStateful,
    udp_ip4_server: RegularKernelSocketNetworkStateful,
    udp_ip6_client: RegularKernelSocketNetworkStateful,
    udp_ip6_server: RegularKernelSocketNetworkStateful,
    tcp_ip4_client: RegularKernelSocketNetworkStateful,
    tcp_ip4_server: RegularKernelSocketNetworkStateful,
    tcp_ip6_client: RegularKernelSocketNetworkStateful,
    tcp_ip6_server: RegularKernelSocketNetworkStateful,
) -> dict[RegularKernelSocketNetworkStateful, RegularKernelSocketNetworkStateful]:
    group = {
        udp_ip4_client: udp_ip4_server,
        udp_ip6_client: udp_ip6_server,
        tcp_ip4_client: tcp_ip4_server,
        tcp_ip6_client: tcp_ip6_server,
    }
    group.pop(client)
    yield group
