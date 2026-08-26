# SPDX-FileCopyrightText: (c) 2026 Tempesta Technologies, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later

import socket
from abc import ABC

from scapy.layers.inet import ICMP, IP
from scapy.layers.inet6 import ICMPv6EchoRequest
from scapy.packet import Packet

from framework.stateful import IP4Mixin, IP6Mixin, RawSocketNetworkStateful

__all__ = ["IcmpRawClient", "IcmpRawV4Client", "IcmpRawV6Client"]


class IcmpRawClient(RawSocketNetworkStateful):
    socket_family: socket.AddressFamily

    packet_class: Packet
    echo_request_type: int
    echo_response_types: set[int]

    @property
    def ping_message(self) -> bytes:
        return bytes(self.packet_class(type=self.echo_request_type))

    def create_packet(self, packet: Packet) -> Packet:
        return packet

    async def pong(self) -> bool:
        response = await self.receive_packet()

        if not response:
            return False

        if isinstance(self.packet_class(), ICMPv6EchoRequest):
            return response.type in self.echo_response_types
        elif isinstance(self.packet_class(), ICMP):
            return response.code in self.echo_response_types
        else:
            return False


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
