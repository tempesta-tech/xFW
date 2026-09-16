# SPDX-FileCopyrightText: (c) 2026 Tempesta Technologies, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later
from typing import AsyncGenerator

import pytest
from pytest import FixtureRequest

from config import ConfigSettings
from framework.asyn import *
from framework.fabrics import client_fabric, server_fabric
from framework.rpc.client import RpcClient


@pytest.fixture
async def udp_ip4_server(
    xfw_mode: str, config: ConfigSettings, logging_level: int, rpc_connection: Optional[RpcClient]
) -> AsyncGenerator[UdpServer, None]:
    new_server = server_fabric(
        xfw_mode=xfw_mode,
        config=config,
        logging_level=logging_level,
        rpc_connection=rpc_connection,
        local_class=UdpV4Server,
        remote_class=UdpV4ServerRemote,
    )
    yield new_server
    await new_server.stop()


@pytest.fixture
async def udp_ip6_server(
    xfw_mode: str, config: ConfigSettings, logging_level: int, rpc_connection: Optional[RpcClient]
) -> AsyncGenerator[UdpServer, None]:
    new_server = server_fabric(
        xfw_mode=xfw_mode,
        config=config,
        logging_level=logging_level,
        rpc_connection=rpc_connection,
        local_class=UdpV6Server,
        remote_class=UdpV6ServerRemote,
    )
    yield new_server
    await new_server.stop()


@pytest.fixture
async def udp_ip4_client(
    xfw_mode: str,
    config: ConfigSettings,
    logging_level: int,
) -> AsyncGenerator[UdpClient, None]:
    new_client = client_fabric(
        xfw_mode=xfw_mode,
        config=config,
        logging_level=logging_level,
        local_class=UdpV4Client,
    )
    yield new_client
    await new_client.stop()


@pytest.fixture
async def udp_ip4_raw_client(
    xfw_mode: str,
    config: ConfigSettings,
    logging_level: int,
) -> AsyncGenerator[UdpRawClient, None]:
    new_client = client_fabric(
        xfw_mode=xfw_mode,
        config=config,
        logging_level=logging_level,
        local_class=UdpIpV4RawClient,
    )
    yield new_client
    await new_client.stop()


@pytest.fixture
async def udp_ip6_client(
    xfw_mode: str,
    config: ConfigSettings,
    logging_level: int,
) -> AsyncGenerator[UdpClient, None]:
    new_client = client_fabric(
        xfw_mode=xfw_mode,
        config=config,
        logging_level=logging_level,
        local_class=UdpV6Client,
    )
    yield new_client
    await new_client.stop()


@pytest.fixture
async def udp_ip4_mapped_ip6_server(
    xfw_mode: str,
    config: ConfigSettings,
    logging_level: int,
    rpc_connection,
) -> AsyncGenerator[UdpServer, None]:
    new_server = server_fabric(
        xfw_mode=xfw_mode,
        config=config,
        logging_level=logging_level,
        local_class=UdpV6ServerMappedIP,
        rpc_connection=rpc_connection,
        remote_class=UdpV6ServerRemote,
        force_ip4=True,
    )
    yield new_server
    await new_server.stop()


@pytest.fixture
async def udp_ip6_raw_client(
    xfw_mode: str,
    config: ConfigSettings,
    logging_level: int,
) -> AsyncGenerator[UdpRawClient, None]:
    new_client = client_fabric(
        xfw_mode=xfw_mode,
        config=config,
        logging_level=logging_level,
        local_class=UdpIpV6RawClient,
    )
    yield new_client
    await new_client.stop()


@pytest.fixture
def udp_server(
    xfw_mode: str, config: ConfigSettings, request: FixtureRequest, ip_version: str
) -> UdpServer:
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
