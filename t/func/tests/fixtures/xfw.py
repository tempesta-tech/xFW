# SPDX-FileCopyrightText: (c) 2026 Tempesta Technologies, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later
from typing import AsyncGenerator

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
) -> AsyncGenerator[XFW, None]:
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


@pytest.fixture(scope="session")
def xfw_syncookie_config(xfw_global) -> str:
    return f"""{{
        "devices": "{xfw_global.network_interface}",
        "devices-mode": "skb",
        "verbose": true,
        "mgr-args": "--listen {xfw_global.ipv4} --port {xfw_global.port}",
        "sysctl-tcp-max-syn-backlog": 1,
        "sysctl-tcp-syncookies": 2
        }}"""


@pytest.fixture
async def xfw(
    xfw_global: XFW,
    xfw_use_rule_reset: bool,
) -> AsyncGenerator[XFW, None]:
    if not xfw_global.is_running:
        await xfw_global.start()

    yield xfw_global

    await xfw_global.stop_or_reset(xfw_use_rule_reset)


@pytest.fixture
async def xfw_paused(
    xfw_global: XFW, xfw_use_rule_reset: bool, config: ConfigSettings
) -> AsyncGenerator[XFW, None]:
    """
    Some of the tests in a fast mode require a pause.
    For instance, some of the ratelimits requires
    some time to reset the traffic block
    """
    if not xfw_global.is_running:
        await xfw_global.start()
    await asyncio.sleep(config.fast_mode_xfw_paused_timeout_sec)

    yield xfw_global

    await xfw_global.stop_or_reset(xfw_use_rule_reset)


@pytest.fixture
async def xfw_restarted(
    xfw_global: XFW, xfw_use_rule_reset: bool, config: ConfigSettings
) -> AsyncGenerator[XFW, None]:
    """
    Some of the tests in a fast mode require
    the xfw restart, for instance to drop
    the tcp connection
    """
    await xfw_global.restart()

    yield xfw_global

    await xfw_global.stop_or_reset(xfw_use_rule_reset)


@pytest.fixture
async def xfw_with_forced_syncookie(
    xfw_global, xfw_use_rule_reset, xfw_syncookie_config
) -> AsyncGenerator[XFW, None]:
    original_config = xfw_global.config
    xfw_global.config = xfw_syncookie_config
    original_mode = await xfw_global.syncookies_value_get()
    await xfw_global.restart()

    yield xfw_global

    await xfw_global.stop_or_reset(xfw_use_rule_reset)
    xfw_global.config = original_config
    await xfw_global.syncookies_value_set(original_mode)
