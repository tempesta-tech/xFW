# SPDX-FileCopyrightText: (c) 2026 Tempesta Technologies, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later

import pytest

from config import ConfigSettings
from framework.asyn import *
from framework.fabrics import client_fabric


@pytest.fixture
async def icmp_ip4_raw_client(
    config: ConfigSettings,
    logging_level: int,
) -> IcmpRawClient:
    new_client = client_fabric(
        config=config,
        logging_level=logging_level,
        local_class=IcmpRawV4Client,
    )
    yield new_client
    await new_client.stop()


@pytest.fixture
async def icmp_ip6_raw_client(
    config: ConfigSettings,
    logging_level: int,
) -> IcmpRawClient:
    new_client = client_fabric(
        config=config,
        logging_level=logging_level,
        local_class=IcmpRawV6Client,
    )
    yield new_client
    await new_client.stop()


@pytest.fixture
def icmp_raw_client(request: pytest.FixtureRequest, ip_version) -> IcmpRawClient:
    return request.getfixturevalue(f"icmp_{ip_version}_raw_client")


@pytest.fixture
async def start_udp_server_and_icmp_clients(udp_server, icmp_raw_client):
    await udp_server.start()
    await icmp_raw_client.start()
    yield
