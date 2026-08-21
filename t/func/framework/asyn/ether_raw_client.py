# SPDX-FileCopyrightText: (c) 2026 Tempesta Technologies, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later

import asyncio
import socket
from typing import Optional

from scapy.all import Raw
from scapy.layers.inet6 import (
    ICMPv6MLReport,
    ICMPv6MLReport2,
    ICMPv6ND_NA,
    ICMPv6ND_NS,
    ICMPv6ND_RA,
    ICMPv6ND_RS,
)
from scapy.layers.l2 import ARP, Ether

from framework.stateful import SocketBaseNetworkStateful

_SYSTEM_LAYERS = (
    ARP,  # IPv4 ARP
    ICMPv6ND_NS,  # IPv6 Neighbor Solicitation
    ICMPv6ND_NA,  # IPv6 Neighbor Advertisement
    ICMPv6ND_RS,
    ICMPv6ND_RA,
    ICMPv6MLReport,
    ICMPv6MLReport2,
)


class EtherRawClient(SocketBaseNetworkStateful):
    socket_family = socket.PF_PACKET
    socket_type = socket.SOCK_RAW

    @property
    def ping_message(self) -> bytes:
        return b""

    def create_packet(self, data: str, src_mac: str, dst_mac: str) -> Ether:
        return Ether(dst=dst_mac, src=src_mac, type=self.socket_proto) / Raw(load=data.encode())

    def decode_data(self, data: bytes) -> Ether:
        return Ether(data)

    async def _receive(self) -> Optional[bytes]:
        """Low-level method to receive a raw message from the remote side."""
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

    async def _send(self, packet: bytes) -> None:
        """Low-level method to send raw binary data to the remote side."""
        await self.loop.sock_sendall(self.socket, bytes(packet))
        self.logger.info(f"Sending L2 packet {packet}")

    async def send_packet(self, packet: Ether) -> None:
        await self._send(bytes(packet))

    async def receive_packet(self) -> Optional[Ether]:
        """
        Receive raw network data and reconstruct it into a Scapy packet.

        Retrieves raw binary data from the network using the internal low-level
        `_receive` method

        Skip system packets.
        """
        raw_data = await self._receive()

        if raw_data is None:
            return None

        packet = self.decode_data(raw_data)

        # we should skip system packets like ARP for ICMP
        if any(packet.haslayer(layer) for layer in _SYSTEM_LAYERS):
            return await self.receive_packet()
        return packet

    async def set_sock_proto(self, proto: int):
        self.socket_proto = proto

    async def set_remote_ip(self, remote_ip: int):
        self.remote_ip = remote_ip
