# SPDX-FileCopyrightText: (c) 2026 Tempesta Technologies, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later

import pytest

from config import ConfigSettings
from framework.asyn import *
from framework.clickhouse import ClickhouseClient
from framework.fabrics import xfw_fabric
from framework.rpc.client import RpcClient
from framework.xfw import XFW


@pytest.fixture
async def xfw(
    config: ConfigSettings,
    logging_level: int,
    rpc_connection: Optional[RpcClient],
    clickhouse_client: ClickhouseClient,
) -> XFW:
    xfw = await xfw_fabric(
        config=config,
        logging_level=logging_level,
        rpc_connection=rpc_connection,
        local_class=XFW,
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
) -> XFW:
    xfw = await xfw_fabric(
        config=config,
        logging_level=logging_level,
        rpc_connection=rpc_connection,
        local_class=XFW,
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
