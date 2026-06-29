# SPDX-FileCopyrightText: (c) 2026 Tempesta Technologies, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later

import pytest

from framework.stateful import RegularKernelSocketNetworkStateful
from framework.asyn import UdpRawClient
from framework.xfw import XFW
from scapy.layers.inet import UDP


async def test_normal_connection(
        xfw: XFW,
        udp_server: RegularKernelSocketNetworkStateful,
        udp_raw_client: UdpRawClient,
        start_udp_server_and_raw_clients
):
    await xfw.rules_set('xfw { }')
    await udp_raw_client.send(UDP() / b'Hello :)')

    response = await udp_server.receive()
    assert response == 'Hello :)'


@pytest.mark.parametrize(
    'port_type',
    ['sport', 'dport'],
    ids=['src', 'dst']
)
async def test_zero_port_is_blocked(
        port_type: str,
        xfw: XFW,
        udp_server: RegularKernelSocketNetworkStateful,
        udp_raw_client: UdpRawClient,
        start_udp_server_and_raw_clients
):
    udp_raw_client.auto_add_host = False

    packet = UDP()
    packet.sport = udp_raw_client.port
    packet.dport = udp_server.port

    setattr(packet, port_type, 0)

    await xfw.rules_set('xfw { }')
    await udp_raw_client.send(packet / 'Hello :)')

    response = await udp_server.receive()
    assert response is None, f'Zero {port_type} port is not blocked'
