# SPDX-FileCopyrightText: (c) 2026 Tempesta Technologies, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later

import pytest

from config import ConfigSettings
from framework.asyn import *
from framework.fabrics import client_fabric


@pytest.fixture
async def traffic_replay_client(
    config: ConfigSettings,
    logging_level: int,
) -> TrafficReplayClient:
    new_client = client_fabric(
        config=config,
        logging_level=logging_level,
        local_class=TrafficReplayClient,
        force_ip4=True,
        tcpreplay_exec_file=config.tcpreplay_exec_file,
        tcprewrite_exec_file=config.tcprewrite_exec_file,
    )
    yield new_client
    await new_client.stop()
