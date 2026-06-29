# SPDX-FileCopyrightText: (c) 2026 Tempesta Technologies, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later
import asyncio
import abc
import socket
import typing

from scapy.layers.l2 import GRE
from scapy.packet import Packet

from framework.stateful import RawClientNetworkStateful, IP4Mixin, IP6Mixin


class GreRawClient(RawClientNetworkStateful, abc.ABC):
    socket_type = socket.SOCK_RAW
    socket_proto = socket.IPPROTO_GRE
    packet_class = GRE

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.log_requests = True
        self.last_request: typing.Optional[Packet] = None
        self.last_response: typing.Optional[Packet] = None

    def create_packet(self, payload: Packet) -> Packet:
        return self.packet_class() / payload

    def decode_data(self, data: bytes) -> Packet:
        return GRE(data)

    async def send(self, packet: Packet) -> int:
        if self.log_requests:
            self.logger.info(f"{self} sending GRE '{packet.summary()}'")

        self.last_request = packet

        return await asyncio.wait_for(
            self.loop.sock_sendto(
                self.socket,
                bytes(packet),
                self.get_sendto_dst()
            ),
            timeout=self.timeout
        )

    async def receive(self, buffer_len: int = 4096) -> typing.Optional[Packet]:
        try:
            data, _ = await asyncio.wait_for(
                self.loop.sock_recvfrom(self.socket, buffer_len),
                timeout=self.timeout
            )
        except asyncio.TimeoutError:
            if self.log_requests:
                self.logger.info(f"{self} timeout - no GRE data received")
            return None

        decoded = self.decode_data(data)
        self.last_response = decoded

        if self.log_requests:
            self.logger.info(f"{self} received GRE packet")

        return decoded

    async def send_payload(self, payload: Packet, wrap: bool = True) -> int:
        packet = self.create_packet(payload) if wrap else payload
        return await self.send(packet)


class GreRawV4Client(GreRawClient, IP4Mixin):
    def get_sendto_dst(self) -> tuple:
        return self.remote_ip, 0


class GreRawV6Client(GreRawClient, IP6Mixin):
    def get_sendto_dst(self) -> tuple:
        return self.remote_ip, 0, 0, 0