# SPDX-FileCopyrightText: (c) 2026 Tempesta Technologies, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later
from typing import AsyncGenerator

import pytest
from pytest import FixtureRequest

from config import ConfigSettings
from framework.asyn import *
from framework.asyn import (
    DnsUdpV4Client,
    DnsUdpV4Server,
    DnsUdpV4ServerRemote,
    DnsUdpV6Client,
    DnsUdpV6Server,
    DnsUdpV6ServerRemote,
)
from framework.fabrics import client_fabric, server_fabric
from framework.rpc.client import RpcClient


@pytest.fixture
async def dns_udp_ip4_server(
    xfw_mode,
    config: ConfigSettings,
    logging_level: int,
    rpc_connection: Optional[RpcClient],
) -> AsyncGenerator[DnsUdpV4Server, None]:
    # mark: HARDCODED_53_PORT
    # XFW currently hardcoded to 53 port
    # port=config.backend_port,

    new_server = server_fabric(
        xfw_mode=xfw_mode,
        config=config,
        logging_level=logging_level,
        rpc_connection=rpc_connection,
        local_class=DnsUdpV4Server,
        remote_class=DnsUdpV4ServerRemote,
        port=53,
    )
    yield new_server
    await new_server.stop()


@pytest.fixture
async def dns_udp_ip6_server(
    xfw_mode,
    config: ConfigSettings,
    logging_level: int,
    rpc_connection: Optional[RpcClient],
) -> AsyncGenerator[DnsUdpV6Server, None]:
    # mark: HARDCODED_53_PORT
    # XFW currently hardcoded to 53 port
    # port=config.backend_port,

    new_server = server_fabric(
        xfw_mode=xfw_mode,
        config=config,
        logging_level=logging_level,
        rpc_connection=rpc_connection,
        local_class=DnsUdpV6Server,
        remote_class=DnsUdpV6ServerRemote,
        port=53,
    )
    yield new_server
    await new_server.stop()


@pytest.fixture
async def dns_udp_ip4_client(
    xfw_mode,
    config: ConfigSettings,
    logging_level: int,
) -> AsyncGenerator[DnsUdpV4Client, None]:
    # mark: HARDCODED_53_PORT
    # XFW currently hardcoded to 53 port
    # remote_port=config.backend_port,
    new_client = client_fabric(
        xfw_mode=xfw_mode,
        config=config,
        logging_level=logging_level,
        local_class=DnsUdpV4Client,
        remote_port=53,
    )
    yield new_client
    await new_client.stop()


@pytest.fixture
async def dns_udp_ip6_client(
    xfw_mode,
    config: ConfigSettings,
    logging_level: int,
) -> AsyncGenerator[DnsUdpV6Client, None]:
    # mark: HARDCODED_53_PORT
    # XFW currently hardcoded to 53 port
    # remote_port=config.backend_port,
    new_client = client_fabric(
        xfw_mode=xfw_mode,
        config=config,
        logging_level=logging_level,
        local_class=DnsUdpV6Client,
        remote_port=53,
    )
    yield new_client
    await new_client.stop()


@pytest.fixture
def dns_udp_server(request: FixtureRequest, ip_version: str) -> DnsUdpServer:
    return request.getfixturevalue(f"dns_udp_{ip_version}_server")


@pytest.fixture
def dns_udp_client(request: FixtureRequest, ip_version: str) -> DnsUdpClient:
    return request.getfixturevalue(f"dns_udp_{ip_version}_client")


@pytest.fixture
async def start_dns_udp_server_and_clients(dns_udp_server, dns_udp_client):
    await dns_udp_server.start()
    await dns_udp_client.start()
    yield
