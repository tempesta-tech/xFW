# SPDX-FileCopyrightText: (c) 2026 Tempesta Technologies, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later

import asyncio

import pytest

from framework.asyn import GreRawV4Client, GreRawV6Client, UdpServer
from framework.xfw import XFW


async def run_gre_test(xfw, gre_raw_client, rule: str):
    await xfw.rules_set(rule)

    await gre_raw_client.send_packet(b"XDP_GRE_TEST")
    return await gre_raw_client.receive()


@pytest.mark.parametrize("ip_version", ["ip4", "ip6"])
async def test_default_ip_proto_with_gre_requests(
    xfw: XFW, ip_version: str, gre_raw_client, start_udp_server_and_gre_clients
):
    response = await run_gre_test(xfw, gre_raw_client, "xfw { }")
    assert response is None


@pytest.mark.skip("ISSUE: 543")
@pytest.mark.parametrize("ip_version", ["ip4", "ip6"])
async def test_ip_proto_with_gre_requests(
    xfw: XFW, ip_version: str, gre_raw_client, start_udp_server_and_gre_clients
):
    response = await run_gre_test(xfw, gre_raw_client, "xfw { ip_proto {47} }")
    assert response is not None
