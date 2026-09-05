# SPDX-FileCopyrightText: (c) 2026 Tempesta Technologies, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later
import asyncio
from typing import Any, AsyncGenerator

import pytest

from config import ConfigSettings
from framework.asyn import *
from framework.clickhouse import ClickhouseClient
from framework.fabrics import xfw_fabric
from framework.rpc.client import RpcClient
from framework.xfw import XFW, XFWRemote


@pytest.fixture(scope="session")
async def xfw_global(
    config: ConfigSettings,
    logging_level: int,
    rpc_connection: Optional[RpcClient],
    clickhouse_global: ClickhouseClient,
) -> AsyncGenerator[XFW | XFWRemote, Any]:
    xfw = xfw_fabric(
        config=config,
        logging_level=logging_level,
        rpc_connection=rpc_connection,
        local_class=XFW,
        remote_class=XFWRemote,
        geo=True,
        clickhouse_client=clickhouse_global,
    )
    try:
        await xfw.start()
        yield xfw
    finally:
        await xfw.stop()


async def __start_xfw_if_not_running(xfw_instance: XFW):
    if not xfw_instance.is_running:
        await xfw_instance.start()


async def __restart_or_reset(xfw_instance: XFW, xfw_use_rule_reset: bool):
    if not xfw_use_rule_reset:
        return await xfw_instance.restart()

    if not xfw_instance.is_running:
        return None

    return await xfw_instance.rules_reset()


@pytest.fixture
async def xfw(
    xfw_global: XFW,
    xfw_use_rule_reset: bool,
) -> AsyncGenerator[XFW | XFWRemote, Any]:
    await __start_xfw_if_not_running(xfw_global)

    yield xfw_global

    await __restart_or_reset(xfw_global, xfw_use_rule_reset)


@pytest.fixture
async def xfw_paused(
    xfw_global: XFW, xfw_use_rule_reset: bool, config: ConfigSettings
) -> AsyncGenerator[XFW | XFWRemote, Any]:
    """
    Some of the tests in a fast mode require a pause.
    For instance, some of the ratelimits requires
    some time to reset the traffic block
    """
    await __start_xfw_if_not_running(xfw_global)
    await asyncio.sleep(config.fast_mode_xfw_paused_timeout_sec)

    yield xfw_global

    await __restart_or_reset(xfw_global, xfw_use_rule_reset)


@pytest.fixture
async def xfw_restarted(
    xfw_global: XFW, xfw_use_rule_reset: bool, config: ConfigSettings
) -> AsyncGenerator[XFW | XFWRemote, Any]:
    """
    Some of the tests in a fast mode require
    the xfw restart, for instance to drop
    the tcp connection
    """
    await xfw_global.restart()

    yield xfw_global

    await __restart_or_reset(xfw_global, xfw_use_rule_reset)
