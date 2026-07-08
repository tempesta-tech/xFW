# SPDX-FileCopyrightText: (c) 2026 Tempesta Technologies, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later

import pytest

from config import ConfigSettings, TestingModel
from framework.rpc.client import RpcClient


@pytest.fixture(autouse=True, scope="session")
async def rpc_connection(config: ConfigSettings, conf_logger) -> RpcClient:
    if config.testing_model == TestingModel.same_host:
        yield
        return

    server = f"{config.rpc_host}:{config.rpc_port}"
    rpc_client = RpcClient(host=config.rpc_host, port=config.rpc_port)

    conf_logger.info(f"establishing connection to RPC Server {server}")
    await rpc_client.run()

    yield rpc_client

    await rpc_client.shutdown_server()
    await rpc_client.shutdown()

    conf_logger.info(f"closed connection to RPC Server {server}")
