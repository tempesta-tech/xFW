# SPDX-FileCopyrightText: (c) 2026 Tempesta Technologies, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later
from typing import Any, AsyncGenerator

import pytest

from config import ConfigSettings
from framework.clickhouse import ClickhouseClient
from framework.logger import get_logger


@pytest.fixture(scope="session")
async def clickhouse_global(
    config: ConfigSettings,
    logging_level: int,
) -> AsyncGenerator[ClickhouseClient, Any]:
    new_client = ClickhouseClient(
        host=config.tfw_logger_clickhouse_host,
        binary_port=config.tfw_logger_clickhouse_binary_port,
        http_port=config.tfw_logger_clickhouse_http_port,
        user=config.tfw_logger_clickhouse_user,
        password=config.tfw_logger_clickhouse_password,
        database=config.tfw_logger_clickhouse_db,
        table=ClickhouseClient.gen_new_table_name(),
        logger=get_logger("clickhouse", level=logging_level),
    )
    await new_client.connect()

    yield new_client


@pytest.fixture
async def clickhouse_client(clickhouse_global: ClickhouseClient):
    await clickhouse_global.table_drop()
    yield clickhouse_global
