# SPDX-FileCopyrightText: (c) 2026 Tempesta Technologies, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later
import asyncio
from typing import Any, AsyncGenerator

import pytest

from config import ConfigSettings, TestingModel
from framework.rpc.client import RpcClient


@pytest.fixture(autouse=True, scope="session")
async def rpc_connection(
    config: ConfigSettings, conf_logger
) -> AsyncGenerator[RpcClient | None, Any]:
    if config.testing_model == TestingModel.same_host:
        yield None
        return

    server = f"{config.rpc_host}:{config.rpc_port}"
    rpc_client = RpcClient(host=config.rpc_host, port=config.rpc_port)

    conf_logger.info(f"establishing connection to RPC Server {server}")
    conf_logger.info(f"current event loop id = {id(asyncio.get_running_loop())}")
    await rpc_client.run()

    yield rpc_client

    await rpc_client.shutdown_server()
    await rpc_client.shutdown()

    conf_logger.info(f"closed connection to RPC Server {server}")
