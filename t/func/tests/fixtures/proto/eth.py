# SPDX-FileCopyrightText: (c) 2026 Tempesta Technologies, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later

import pytest

from config import ConfigSettings
from framework.asyn import *
from framework.fabrics import client_fabric, server_fabric
from framework.rpc.client import RpcClient


@pytest.fixture
async def ether_raw_client(
    config: ConfigSettings,
    logging_level: int,
):
    new_client = client_fabric(
        config=config,
        logging_level=logging_level,
        local_class=EtherRawClient,
        force_ip4=True,
    )
    yield new_client
    await new_client.stop()


@pytest.fixture
async def ether_raw_server(
    config: ConfigSettings,
    logging_level: int,
    rpc_connection: Optional[RpcClient],
):
    new_client = server_fabric(
        config=config,
        logging_level=logging_level,
        rpc_connection=rpc_connection,
        local_class=EtherRawServer,
        remote_class=EtherRawServerRemote,
        force_ip4=True,
    )
    yield new_client
    await new_client.stop()
