# SPDX-FileCopyrightText: (c) 2026 Tempesta Technologies, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later

import asyncio
import socket
import time
from asyncio import gather
from ctypes import Structure, c_uint16, c_uint32
from typing import Optional

import pytest
from scapy.all import Raw
from scapy.layers.inet import ETH_P_IP, IP, UDP, Ether
from scapy.layers.l2 import Dot1Q

from framework.asyn.ether_raw_client import EtherRawClient
from framework.asyn.ether_raw_server import EtherRawServer
from framework.utils import server_cloner
from framework.xfw import XFW

SOL_PACKET = 263
PACKET_AUXDATA = 8
ETH_802_1Q = 0x8100
ETH_802_QnQ = 0x88A8
ETH_802_UNKNOWN_PROTO = 0x8101


class tpacket_auxdata(Structure):
    _fields_ = [
        ("tp_status", c_uint32),
        ("tp_len", c_uint32),
        ("tp_snaplen", c_uint32),
        ("tp_mac", c_uint16),
        ("tp_net", c_uint16),
        ("tp_vlan_tci", c_uint16),
        ("tp_vlan_tpid", c_uint16),
    ]


class Ether802Dot1QServer(EtherRawServer):
    async def sock_recvmsg(self):
        """
        Simple realization of sock.recvmsg that is
        missing in asyncio
        """
        try:
            return self.socket.recvmsg(65000, 65000)

        except BlockingIOError:
            self.logger.warning(f"The server received unexpected `BlockingIOError`")
            return None

    def set_socket_options(self, sock: socket.socket):
        """
        Turn on additional meta info
        """
        super().set_socket_options(sock)
        sock.setsockopt(SOL_PACKET, PACKET_AUXDATA, 1)

    async def receive_message(
        self, message: bytes
    ) -> tuple[Optional[Ether], Optional[tpacket_auxdata]]:
        start_at = time.time()
        packet = ""
        while time.time() - start_at < self.timeout:
            data = await self.sock_recvmsg()

            if not data:
                continue

            packet, *info = data

            if message not in packet:
                await asyncio.sleep(self.message_polling_interval)
                continue
            self.logger.info(f"The expected L2 packet is received - {packet}")

            headers = tpacket_auxdata.from_buffer_copy(info[0][0][2])
            return packet, headers

        if packet and message not in packet:
            self.logger.info(
                f"The expected L2 package is missing from the received ones - {packet}"
            )
        self.logger.info("The expected L2 packet was not received - the timeout was exceeded")
        return None, None

    async def receive_block(self) -> bool:
        start_at = time.time()
        while time.time() - start_at < self.timeout:
            try:
                data = self.socket.recvmsg(65000, 65000)

                if data:
                    packet, *info = data
                    self.logger.info(f"The server received unexpected data - {packet}")
                await asyncio.sleep(self.message_polling_interval)
                continue

            except BlockingIOError:
                self.logger.info(f"The server received expected `BlockingIOError`")
                return True
        self.logger.info("The server did not receive the expected block.")
        return False


@pytest.fixture
async def ether_802_dot_1q_server(ether_raw_server: EtherRawServer):
    server = server_cloner(ether_raw_server, fabric=Ether802Dot1QServer, amount=1)[0]
    yield server
    await server.stop()


@pytest.mark.parametrize(
    "test_ok, ether_type, vlan",
    [
        pytest.param(True, ETH_802_1Q, Dot1Q(vlan=10, prio=3, dei=0, type=ETH_P_IP), id="1-tag"),
        pytest.param(
            True,
            ETH_802_QnQ,
            (
                Dot1Q(vlan=100, prio=1, dei=0, type=ETH_802_1Q)
                / Dot1Q(vlan=10, prio=2, dei=0, type=ETH_P_IP)
            ),
            id="2-tags",
        ),
        pytest.param(
            False,
            ETH_802_1Q,
            (
                Dot1Q(vlan=200, prio=1, dei=0, type=ETH_802_1Q)
                / Dot1Q(vlan=100, prio=2, dei=0, type=ETH_802_1Q)
                / Dot1Q(vlan=10, prio=3, dei=0, type=ETH_P_IP)
            ),
            id="3-tags",
        ),
        pytest.param(
            False,
            ETH_802_QnQ,
            (
                Dot1Q(vlan=100, prio=1, dei=0, type=ETH_802_UNKNOWN_PROTO)
                / Dot1Q(vlan=10, prio=2, dei=0, type=ETH_P_IP)
            ),
            id="broken-tag",
        ),
    ],
)
async def test_send_multiple_vlan(
    test_ok: bool,
    ether_type: int,
    vlan: Dot1Q,
    xfw: XFW,
    ether_raw_client: EtherRawClient,
    ether_802_dot_1q_server: Ether802Dot1QServer,
):
    await ether_802_dot_1q_server.start()
    await ether_raw_client.start()
    ether_802_dot_1q_server.timeout = 1.0

    src_mac, dst_mac = await gather(
        ether_raw_client.get_mac_address(), ether_802_dot_1q_server.get_mac_address()
    )
    packet = (
        Ether(dst=dst_mac, src=src_mac, type=ether_type)
        / vlan
        / IP(src=ether_raw_client.ip, dst=ether_802_dot_1q_server.ip)
        / UDP(sport=ether_raw_client.port, dport=ether_802_dot_1q_server.port)
        / Raw(b"payload")
    )
    await xfw.rules_set("xfw {}")

    await ether_raw_client.send_packet(packet)

    if test_ok:
        data = await ether_802_dot_1q_server.receive_message(b"payload")
        assert data is not None

        packet, info = data

        assert packet is not None
        assert info is not None
        assert info.tp_vlan_tpid == ether_type
    else:
        assert await ether_802_dot_1q_server.receive_block()
