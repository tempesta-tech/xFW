# SPDX-FileCopyrightText: (c) 2026 Tempesta Technologies, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later

import pytest
from pytest import FixtureRequest

from config import ConfigSettings
from framework.asyn import *
from framework.fabrics import client_fabric, server_fabric
from framework.rpc.client import RpcClient


@pytest.fixture
async def udp_ip4_server(
    config: ConfigSettings, logging_level: int, rpc_connection: Optional[RpcClient]
) -> UdpServer:
    new_server = await server_fabric(
        config=config,
        logging_level=logging_level,
        rpc_connection=rpc_connection,
        local_class=UdpV4Server,
    )
    yield new_server
    await new_server.stop()


@pytest.fixture
async def udp_ip6_server(
    config: ConfigSettings, logging_level: int, rpc_connection: Optional[RpcClient]
) -> UdpServer:
    new_server = await server_fabric(
        config=config,
        logging_level=logging_level,
        rpc_connection=rpc_connection,
        local_class=UdpV6Server,
    )
    yield new_server
    await new_server.stop()


@pytest.fixture
async def udp_ip4_client(
    config: ConfigSettings,
    logging_level: int,
) -> UdpClient:
    new_client = client_fabric(
        config=config,
        logging_level=logging_level,
        local_class=UdpV4Client,
    )
    yield new_client
    await new_client.stop()


@pytest.fixture
async def udp_ip4_raw_client(
    config: ConfigSettings,
    logging_level: int,
) -> UdpRawClient:
    new_client = client_fabric(
        config=config,
        logging_level=logging_level,
        local_class=UdpIpV4RawClient,
    )
    yield new_client
    await new_client.stop()


@pytest.fixture
async def udp_ip6_client(
    config: ConfigSettings,
    logging_level: int,
) -> UdpClient:
    new_client = client_fabric(
        config=config,
        logging_level=logging_level,
        local_class=UdpV6Client,
    )
    yield new_client
    await new_client.stop()


@pytest.fixture
async def udp_ip4_mapped_ip6_server(
    config: ConfigSettings,
    logging_level: int,
    rpc_connection,
) -> UdpServer:
    new_server = await server_fabric(
        config=config,
        logging_level=logging_level,
        local_class=UdpV6ServerMappedIP,
        rpc_connection=rpc_connection,
        force_ip4=True,
    )
    yield new_server
    await new_server.stop()


@pytest.fixture
async def udp_ip6_raw_client(
    config: ConfigSettings,
    logging_level: int,
) -> UdpRawClient:
    new_client = client_fabric(
        config=config,
        logging_level=logging_level,
        local_class=UdpIpV6RawClient,
    )
    yield new_client
    await new_client.stop()


@pytest.fixture
def udp_server(config: ConfigSettings, request: FixtureRequest, ip_version: str) -> UdpServer:
    return request.getfixturevalue(f"udp_{ip_version}_server")


@pytest.fixture
def udp_client(request: FixtureRequest, ip_version) -> UdpClient:
    return request.getfixturevalue(f"udp_{ip_version}_client")


@pytest.fixture
def udp_raw_client(request: FixtureRequest, ip_version) -> UdpRawClient:
    return request.getfixturevalue(f"udp_{ip_version}_raw_client")


@pytest.fixture
async def start_udp_server_and_clients(udp_server, udp_client):
    await udp_server.start()
    await udp_client.start()
    yield


@pytest.fixture
async def start_udp_server_and_raw_clients(udp_server, udp_raw_client):
    await udp_server.start()
    await udp_raw_client.start()
    yield
