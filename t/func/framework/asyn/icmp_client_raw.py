# SPDX-FileCopyrightText: (c) 2026 Tempesta Technologies, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later

import asyncio
import socket
import typing
from abc import ABC

from scapy.layers.inet import ICMP, IP
from scapy.layers.inet6 import ICMPv6EchoRequest
from scapy.packet import Packet

from framework.stateful import IP4Mixin, IP6Mixin, RawClientNetworkStateful

__all__ = ["IcmpRawClient", "IcmpRawV4Client", "IcmpRawV6Client"]


class IcmpRawClient(RawClientNetworkStateful, ABC):
    socket_family: socket.AddressFamily
    socket_type = socket.SOCK_RAW

    packet_class: Packet
    echo_request_type: int
    echo_response_types: set[int]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.log_requests = True
        self.last_request: typing.Optional[ICMP] = None
        self.last_response: typing.Optional[ICMP] = None

    def create_packet(self, packet: Packet) -> Packet:
        return packet

    async def send(self, packet: ICMP) -> int:
        if self.log_requests:
            self.logger.info(f'{self} sending to {self.remote_ip}:{self.remote_port} "{packet}"')

        self.last_request = packet

        return await asyncio.wait_for(
            self.loop.sock_sendto(self.socket, bytes(self.last_request), self.get_sendto_dst()),
            timeout=self.timeout,
        )

    async def receive(self, buffer_len: int = 1024) -> typing.Optional[ICMP]:
        try:
            response = await asyncio.wait_for(
                self.loop.sock_recvfrom(self.socket, buffer_len), timeout=self.timeout
            )
        except asyncio.TimeoutError:
            if self.log_requests:
                self.logger.info(f"{self} timeout - no data received")

            return None

        data, _ = response
        decoded = self.decode_data(data)

        self.last_response = decoded[ICMP]

        if self.log_requests:
            self.logger.info(f'received from {self.ip_testing} "{self.last_response}"')

        return self.last_response

    async def ping(self):
        await self.send(self.packet_class(type=self.echo_request_type))

    async def pong(self) -> bool:
        response = await self.receive()

        if not response:
            return False

        return response.code in self.echo_response_types


class IcmpRawV4Client(IcmpRawClient, IP4Mixin):
    socket_proto = socket.IPPROTO_ICMP
    packet_class = ICMP
    echo_request_type = 8
    echo_response_types = {0}

    def get_sendto_dst(self) -> tuple:
        return self.remote_ip, 0

    def decode_data(self, data: bytes) -> ICMP:
        return IP(data)[ICMP]


class IcmpRawV6Client(IcmpRawClient, IP6Mixin):
    socket_proto = socket.IPPROTO_ICMPV6
    packet_class = ICMPv6EchoRequest
    echo_request_type = 128
    echo_response_types = {129, 136}

    def get_sendto_dst(self) -> tuple:
        return self.remote_ip, 0, 0, 0

    def decode_data(self, data: bytes) -> ICMP:
        return ICMP(data)

    async def pong(self) -> bool:
        response = await self.receive()

        if not response:
            return False

        return response.type in self.echo_response_types
