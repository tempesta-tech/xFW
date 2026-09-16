# SPDX-FileCopyrightText: (c) 2026 Tempesta Technologies, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later
from typing import AsyncGenerator

import pytest

from config import ConfigSettings
from framework.asyn import *
from framework.asyn import EtherRawClient
from framework.fabrics import client_fabric, server_fabric
from framework.rpc.client import RpcClient


@pytest.fixture
async def ether_raw_client(
    xfw_mode,
    config: ConfigSettings,
    logging_level: int,
) -> AsyncGenerator[EtherRawClient, None]:
    new_client = client_fabric(
        xfw_mode=xfw_mode,
        config=config,
        logging_level=logging_level,
        local_class=EtherRawClient,
        force_ip4=True,
    )
    yield new_client
    await new_client.stop()


@pytest.fixture
async def ether_raw_server(
    xfw_mode,
    config: ConfigSettings,
    logging_level: int,
    rpc_connection: Optional[RpcClient],
) -> AsyncGenerator[EtherRawServer, None]:
    new_client = server_fabric(
        xfw_mode=xfw_mode,
        config=config,
        logging_level=logging_level,
        rpc_connection=rpc_connection,
        local_class=EtherRawServer,
        remote_class=EtherRawServerRemote,
        force_ip4=True,
    )
    yield new_client
    await new_client.stop()
