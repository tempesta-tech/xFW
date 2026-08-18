# SPDX-FileCopyrightText: (c) 2026 Tempesta Technologies, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later

import pytest
from pytest import FixtureRequest

from config import ConfigSettings
from framework.asyn import *
from framework.fabrics import client_fabric, server_fabric
from framework.rpc.client import RpcClient


@pytest.fixture
async def tcp_ip4_server(
    config: ConfigSettings, logging_level: int, rpc_connection: Optional[RpcClient]
) -> TcpServer:
    new_server = server_fabric(
        config=config,
        logging_level=logging_level,
        rpc_connection=rpc_connection,
        local_class=TcpV4Server,
        remote_class=TcpV4ServerRemote,
    )
    yield new_server
    await new_server.stop()


@pytest.fixture
async def tcp_ip4_raw_server(
    config: ConfigSettings, logging_level: int, rpc_connection: Optional[RpcClient]
) -> TcpRawServer:
    new_server = server_fabric(
        config=config,
        logging_level=logging_level,
        rpc_connection=rpc_connection,
        local_class=TcpIpV4RawServer,
        remote_class=TcpIpV4RawServerRemote,
    )
    yield new_server
    await new_server.stop()


@pytest.fixture
async def tcp_ip6_server(
    config: ConfigSettings, logging_level: int, rpc_connection: Optional[RpcClient]
) -> TcpServer:
    new_server = server_fabric(
        config=config,
        logging_level=logging_level,
        rpc_connection=rpc_connection,
        local_class=TcpV6Server,
        remote_class=TcpV6ServerRemote,
    )
    yield new_server
    await new_server.stop()


@pytest.fixture
async def tcp_ip6_raw_server(
    config: ConfigSettings, logging_level: int, rpc_connection: Optional[RpcClient]
) -> TcpRawServer:
    new_server = server_fabric(
        config=config,
        logging_level=logging_level,
        rpc_connection=rpc_connection,
        local_class=TcpIpV6RawServer,
        remote_class=TcpIpV6RawServerRemote,
    )
    yield new_server
    await new_server.stop()


@pytest.fixture
async def tcp_ip4_client(
    config: ConfigSettings,
    logging_level: int,
) -> TcpClient:
    new_client = client_fabric(
        config=config,
        logging_level=logging_level,
        local_class=TcpV4Client,
    )
    yield new_client
    await new_client.stop()


@pytest.fixture
async def tcp_ip4_raw_client(
    config: ConfigSettings,
    logging_level: int,
) -> TcpRawClient:
    new_client = client_fabric(
        config=config,
        logging_level=logging_level,
        local_class=TcpIpV4RawClient,
    )
    yield new_client
    await new_client.stop()


@pytest.fixture
async def tcp_ip6_client(
    config: ConfigSettings,
    logging_level: int,
) -> TcpClient:
    new_client = client_fabric(
        config=config,
        logging_level=logging_level,
        local_class=TcpV6Client,
    )
    yield new_client
    await new_client.stop()


@pytest.fixture
async def tcp_ip6_raw_client(
    config: ConfigSettings,
    logging_level: int,
) -> TcpRawClient:
    new_client = client_fabric(
        config=config,
        logging_level=logging_level,
        local_class=TcpIpV6RawClient,
    )
    yield new_client
    await new_client.stop()


@pytest.fixture
def tcp_server(config: ConfigSettings, request: FixtureRequest, ip_version: str) -> TcpServer:
    return request.getfixturevalue(f"tcp_{ip_version}_server")


@pytest.fixture
def tcp_raw_server(request: FixtureRequest, ip_version) -> TcpRawServer:
    return request.getfixturevalue(f"tcp_{ip_version}_raw_server")


@pytest.fixture
def tcp_client(request: FixtureRequest, ip_version) -> TcpClient:
    return request.getfixturevalue(f"tcp_{ip_version}_client")


@pytest.fixture
def tcp_raw_client(request: FixtureRequest, ip_version) -> TcpRawClient:
    return request.getfixturevalue(f"tcp_{ip_version}_raw_client")


@pytest.fixture
async def start_tcp_server_and_clients(tcp_server, tcp_client):
    await tcp_server.start()
    await tcp_client.start()
    yield


@pytest.fixture
async def start_tcp_server_and_raw_clients(tcp_server, tcp_raw_client):
    await tcp_server.start()
    await tcp_raw_client.start()
    yield


@pytest.fixture
async def start_tcp_raw_server_and_raw_clients(tcp_raw_server, tcp_raw_client):
    await tcp_raw_server.start()
    await tcp_raw_client.start()
    yield
