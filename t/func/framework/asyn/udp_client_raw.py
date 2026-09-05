# SPDX-FileCopyrightText: (c) 2026 Tempesta Technologies, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later

import asyncio
import socket
import typing
from abc import ABC

from scapy.layers.inet import IP, TCP, UDP, Ether
from scapy.packet import Packet

from framework.stateful import IP4Mixin, IP6Mixin, RawSocketNetworkStateful

__all__ = ["UdpRawClient", "UdpIpV4RawClient", "UdpIpV6RawClient"]


class UdpRawClient(RawSocketNetworkStateful):
    socket_proto = socket.IPPROTO_UDP

    def __init__(self, *args, auto_add_host: bool = True, **kwargs):
        super().__init__(*args, **kwargs)
        self.auto_add_host = auto_add_host

    def create_packet(self, packet: Packet | str | bytes) -> Packet:
        packet = packet.encode() if isinstance(packet, str) else packet

        if isinstance(packet, bytes):
            packet = UDP() / packet

        if self.auto_add_host:
            packet.sport = self.port
            packet.dport = self.remote_port

        return packet

    async def _receive(self) -> typing.Optional[bytes]:
        await super()._receive()

        if not self.decode_data(self.last_response).haslayer(UDP):
            self.logger.warning(f"{self} skipped caught data: {Ether(self.last_response)}")
            return await self._receive()

        return self.last_response


class UdpIpV4RawClient(UdpRawClient, IP4Mixin):
    def set_socket_options(self, sock: socket.socket):
        super().set_socket_options(sock)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    def create_packet(self, packet: UDP | str | bytes) -> UDP:
        return IP(src=self.ip, dst=self.remote_ip) / super().create_packet(packet)

    def get_sendto_dst(self):
        return self.remote_ip, self.remote_port

    def decode_data(self, data: bytes):
        return IP(data)


class UdpIpV6RawClient(UdpRawClient, IP6Mixin):
    def set_socket_options(self, sock: socket.socket):
        super().set_socket_options(sock)
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_CHECKSUM, 6)

    def create_packet(self, packet: UDP | str | bytes) -> UDP:
        return super().create_packet(packet)

    def get_sendto_dst(self):
        return self.remote_ip, 0, 0, 0

    def decode_data(self, data: bytes):
        return UDP(data)
