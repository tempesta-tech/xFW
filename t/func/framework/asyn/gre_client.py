# SPDX-FileCopyrightText: (c) 2026 Tempesta Technologies, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later
import abc
import asyncio
import socket
import typing

from scapy.layers.l2 import GRE
from scapy.packet import Packet

from framework.stateful import IP4Mixin, IP6Mixin, RawSocketNetworkStateful


class GreRawClient(RawSocketNetworkStateful, abc.ABC):
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


class GreRawV4Client(GreRawClient, IP4Mixin):
    def get_sendto_dst(self) -> tuple:
        return self.remote_ip, 0


class GreRawV6Client(GreRawClient, IP6Mixin):
    def get_sendto_dst(self) -> tuple:
        return self.remote_ip, 0, 0, 0
