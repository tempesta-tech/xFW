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


@pytest.fixture
async def xfw(
    config: ConfigSettings,
    logging_level: int,
    rpc_connection: Optional[RpcClient],
    clickhouse_client: ClickhouseClient,
) -> AsyncGenerator[XFW, None]:
    xfw = xfw_fabric(
        config=config,
        logging_level=logging_level,
        rpc_connection=rpc_connection,
        local_class=XFW,
        remote_class=XFWRemote,
        clickhouse_client=clickhouse_client,
    )
    try:
        await xfw.start()
        yield xfw
    finally:
        await xfw.stop()


@pytest.fixture
async def xfw_geoip(
    config: ConfigSettings,
    logging_level: int,
    rpc_connection: Optional[RpcClient],
    clickhouse_client: ClickhouseClient,
) -> AsyncGenerator[XFW, None]:
    xfw = xfw_fabric(
        config=config,
        logging_level=logging_level,
        rpc_connection=rpc_connection,
        local_class=XFW,
        remote_class=XFWRemote,
        geo=True,
        clickhouse_client=clickhouse_client,
    )

    try:
        await xfw.start()
    except AssertionError as e:
        await xfw.stop()
        pytest.fail(f"The XFW service have not started in time. Error: {e}")

    yield xfw
    await xfw.stop()


@pytest.fixture
async def xfw_with_forced_syncookie(xfw: XFW) -> AsyncGenerator[XFW, None]:
    """
    While `sysctl-tcp-syncookies: 2` is not practical, it's required for the
    test to get a deterministic kernel behavior always requireing a syncookie
    generation.
    """
    original_mode = await xfw.syncookies_value_get()
    await xfw.set_config(f"""{{
        "devices": "{xfw.network_interface}",
        "devices-mode": "skb",
        "verbose": true,
        "mgr-args": "--listen {xfw.ipv4} --port {xfw.port}",
        "sysctl-tcp-max-syn-backlog": 1,
        "sysctl-tcp-syncookies": 2
        }}""")
    await xfw.restart()

    yield xfw

    await xfw.stop()
    await xfw.syncookies_value_set(original_mode)
