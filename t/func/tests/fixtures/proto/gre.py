# SPDX-FileCopyrightText: (c) 2026 Tempesta Technologies, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later

import pytest
from pytest import FixtureRequest

from config import ConfigSettings
from framework.asyn import *
from framework.fabrics import client_fabric, server_fabric
from framework.rpc.client import RpcClient


@pytest.fixture
async def gre_ip4_raw_client(
    config: ConfigSettings,
    logging_level: int,
) -> BaseGreRawStateful:
    new_client = client_fabric(
        config=config,
        logging_level=logging_level,
        local_class=GreRawV4Client,
    )
    yield new_client
    await new_client.stop()


@pytest.fixture
async def gre_ip6_raw_client(
    config: ConfigSettings,
    logging_level: int,
) -> BaseGreRawStateful:
    new_client = client_fabric(
        config=config,
        logging_level=logging_level,
        local_class=GreRawV6Client,
    )
    yield new_client
    await new_client.stop()


@pytest.fixture
async def gre_ip4_raw_server(
    config: ConfigSettings, logging_level: int, rpc_connection: Optional[RpcClient]
) -> UdpServer:
    new_server = server_fabric(
        config=config,
        logging_level=logging_level,
        rpc_connection=rpc_connection,
        local_class=GreRawV4Server,
        remote_class=GreRawV4Server,
    )
    yield new_server
    await new_server.stop()


@pytest.fixture
async def gre_ip6_raw_server(
    config: ConfigSettings, logging_level: int, rpc_connection: Optional[RpcClient]
) -> UdpServer:
    new_server = server_fabric(
        config=config,
        logging_level=logging_level,
        rpc_connection=rpc_connection,
        local_class=GreRawV6Server,
        remote_class=GreRawV6Server,
    )
    yield new_server
    await new_server.stop()


@pytest.fixture
def gre_raw_client(request: FixtureRequest, ip_version) -> BaseGreRawStateful:
    return request.getfixturevalue(f"gre_{ip_version}_raw_client")


@pytest.fixture
def gre_raw_server(request: FixtureRequest, ip_version) -> BaseGreRawStateful:
    return request.getfixturevalue(f"gre_{ip_version}_raw_server")


@pytest.fixture
async def start_gre_server_and_gre_clients(gre_raw_server, gre_raw_client):
    await gre_raw_server.start()
    await gre_raw_client.start()
    yield
