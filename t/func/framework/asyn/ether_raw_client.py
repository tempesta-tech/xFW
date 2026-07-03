# SPDX-FileCopyrightText: (c) 2026 Tempesta Technologies, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later

import asyncio
import socket
from typing import Optional

from scapy.all import Raw
from scapy.layers.l2 import Ether

from framework.stateful import SocketBaseNetworkStateful


class EtherRawClient(SocketBaseNetworkStateful):
    socket_family = socket.PF_PACKET
    socket_type = socket.SOCK_RAW
    socket_proto = None

    async def receive(self, *_, **__) -> Optional[bytes]:
        try:
            data = await asyncio.wait_for(self.loop.sock_recv(self.socket, 8096), self.timeout)
            self.logger.debug(f"received data {data}")
            return data
        except asyncio.TimeoutError:
            self.logger.debug(f"timeout")
            return None

    @property
    def bind_params(self):
        return self.network_interface, 0

    async def send_packet(self, packet: Ether):
        await self.loop.sock_sendall(self.socket, bytes(packet))
        self.logger.info(f"Sending L2 packet {packet}")

    async def send(self, data: str, src_mac: str, dst_mac: str):
        packet = Ether(dst=dst_mac, src=src_mac, type=self.socket_proto) / Raw(load=data.encode())
        await self.send_packet(packet)

    async def set_sock_proto(self, proto: int):
        self.socket_proto = proto

    async def set_remote_ip(self, remote_ip: int):
        self.remote_ip = remote_ip
