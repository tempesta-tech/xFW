# SPDX-FileCopyrightText: (c) 2026 Tempesta Technologies, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later

import asyncio
import logging
import os
import tarfile
from io import BytesIO

import httpx
import pytest

from config import ConfigSettings
from framework.logger import get_logger


@pytest.fixture
def event_loop(event_loop_policy: asyncio.AbstractEventLoopPolicy) -> asyncio.AbstractEventLoop:
    return event_loop_policy.get_event_loop()


@pytest.fixture(scope="session")
def config() -> ConfigSettings:
    settings = ConfigSettings()
    yield settings


@pytest.fixture(scope="session")
def logging_level(config) -> int:
    root_logger = logging.getLogger()
    # Take config.log_level if set, otherwise root_logger.level
    config_level = config.log_level or root_logger.level
    # Return the minimum (more detailed) between config and root
    return min(config_level, root_logger.level)


@pytest.fixture(scope="session")
def conf_logger(logging_level) -> logging.Logger:
    logger = get_logger("root", level=logging_level)
    logger.propagate = False

    logger = get_logger("pytest-conf", level=logging_level)
    yield logger


@pytest.fixture(scope="session", autouse=True)
async def prepare_geolite2_country_db(config: ConfigSettings, conf_logger):
    if os.path.exists(config.xfw_geolite2_country_db_path):
        conf_logger.info("Skipped downloading GeoIP2-Country.mmdb. " "File already exists")
        return

    async with httpx.AsyncClient() as client:
        response = await client.get(config.xfw_geolite2_country_db_url)

    if response.status_code != 200:
        raise FileExistsError("Can not download GeoIP DB from Nexus")

    file = BytesIO(response.content)
    tar = tarfile.open(fileobj=file)
    mmdb_filename = [key for key in tar.getnames() if "mmdb" in key]

    if not len(mmdb_filename):
        raise FileNotFoundError("Can not find mmdb file in geolite2 db archive")

    mmdb_filename = mmdb_filename[0]
    mmdb = tar.extractfile(mmdb_filename)

    with open(config.xfw_geolite2_country_db_path, "wb") as f:
        f.write(mmdb.read())

    conf_logger.info("Downloaded GeoIP2-Country.mmdb")
