# SPDX-FileCopyrightText: (c) 2026 Tempesta Technologies, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later
from typing import AsyncGenerator

import pytest
from pytest import FixtureRequest

from config import ConfigSettings
from framework.asyn import *
from framework.asyn import (
    TcpIpV4RawServer,
    TcpIpV4RawServerRemote,
    TcpV4Server,
    TcpV4ServerRemote,
    TcpV6Server,
    TcpV6ServerRemote,
)
from framework.fabrics import client_fabric, server_fabric
from framework.rpc.client import RpcClient


@pytest.fixture
async def tcp_ip4_server(
    xfw_mode: str, config: ConfigSettings, logging_level: int, rpc_connection: Optional[RpcClient]
) -> AsyncGenerator[TcpV4Server, None]:
    new_server = server_fabric(
        xfw_mode=xfw_mode,
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
    xfw_mode: str, config: ConfigSettings, logging_level: int, rpc_connection: Optional[RpcClient]
) -> AsyncGenerator[TcpIpV4RawServer, None]:
    new_server = server_fabric(
        xfw_mode=xfw_mode,
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
    xfw_mode: str, config: ConfigSettings, logging_level: int, rpc_connection: Optional[RpcClient]
) -> AsyncGenerator[TcpV6Server, None]:
    new_server = server_fabric(
        xfw_mode=xfw_mode,
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
    xfw_mode: str, config: ConfigSettings, logging_level: int, rpc_connection: Optional[RpcClient]
) -> AsyncGenerator[TcpRawServer, None]:
    new_server = server_fabric(
        xfw_mode=xfw_mode,
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
    xfw_mode: str,
    config: ConfigSettings,
    logging_level: int,
) -> AsyncGenerator[TcpClient, None]:
    new_client = client_fabric(
        xfw_mode=xfw_mode,
        config=config,
        logging_level=logging_level,
        local_class=TcpV4Client,
    )
    yield new_client
    await new_client.stop()


@pytest.fixture
async def tcp_ip4_raw_client(
    xfw_mode: str,
    config: ConfigSettings,
    logging_level: int,
) -> AsyncGenerator[TcpRawClient, None]:
    new_client = client_fabric(
        xfw_mode=xfw_mode,
        config=config,
        logging_level=logging_level,
        local_class=TcpIpV4RawClient,
    )
    yield new_client
    await new_client.stop()


@pytest.fixture
async def tcp_ip6_client(
    xfw_mode: str,
    config: ConfigSettings,
    logging_level: int,
) -> AsyncGenerator[TcpClient, None]:
    new_client = client_fabric(
        xfw_mode=xfw_mode,
        config=config,
        logging_level=logging_level,
        local_class=TcpV6Client,
    )
    yield new_client
    await new_client.stop()


@pytest.fixture
async def tcp_ip6_raw_client(
    xfw_mode: str,
    config: ConfigSettings,
    logging_level: int,
) -> AsyncGenerator[TcpRawClient, None]:
    new_client = client_fabric(
        xfw_mode=xfw_mode,
        config=config,
        logging_level=logging_level,
        local_class=TcpIpV6RawClient,
    )
    yield new_client
    await new_client.stop()


@pytest.fixture
def tcp_server(
    xfw_mode: str, config: ConfigSettings, request: FixtureRequest, ip_version: str
) -> TcpServer:
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
