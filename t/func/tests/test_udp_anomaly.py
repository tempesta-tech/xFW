# SPDX-FileCopyrightText: (c) 2026 Tempesta Technologies, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later

import pytest
from scapy.layers.inet import UDP

from framework.asyn import UdpRawClient
from framework.stateful import RegularKernelSocketNetworkStateful
from framework.xfw import XFW, XfwMode


async def test_normal_connection(
    xfw: XFW,
    udp_server: RegularKernelSocketNetworkStateful,
    udp_raw_client: UdpRawClient,
    start_udp_server_and_raw_clients,
):
    await xfw.rules_set("xfw { }")
    await udp_raw_client.send_packet(b"Hello :)")

    assert await udp_server.receive_message() == "Hello :)"
