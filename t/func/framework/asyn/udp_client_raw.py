# SPDX-FileCopyrightText: (c) 2026 Tempesta Technologies, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later

import asyncio
import socket
import typing
from abc import ABC

from scapy.layers.inet import IP, TCP, Ether, UDP

from framework.stateful import RawClientNetworkStateful, IP6Mixin, IP4Mixin


__all__ = ['UdpRawClient', 'UdpIpV4RawClient', 'UdpIpV6RawClient']


class UdpRawClient(RawClientNetworkStateful, ABC):
    socket_type = socket.SOCK_RAW
    socket_proto = socket.IPPROTO_UDP

    async def send(self, packet: UDP) -> int:
        if self.auto_add_host:
            packet.sport = self.port
            packet.dport = self.remote_port

        scapy_packet = self.create_packet(packet)
        self.logger.info(f'{self} sending to {self.remote_ip}:{self.remote_port} "{scapy_packet}"')

        return await asyncio.wait_for(
            self.loop.sock_sendto(
                self.socket,
                bytes(scapy_packet),
                self.get_sendto_dst()
            ),
            timeout=3
        )

    async def receive(self, buffer_len: int = 1024) -> typing.Optional[TCP]:
        try:
            response = await asyncio.wait_for(
                self.loop.sock_recvfrom(self.socket, buffer_len),
                timeout=3
            )
        except asyncio.TimeoutError:
            self.logger.info(f'{self} timeout - no data received')
            return None

        data, _ = response
        decoded = self.decode_data(data)

        if not decoded.haslayer(UDP):
            self.logger.warning(f'{self} skipped caught data: {Ether(data)}')
            return await self.receive()

        self.last_response = decoded[UDP]
        self.logger.info(f'received from {self.ip_testing}:{self.remote_port} "{self.last_response}"')
        return self.last_response

    async def ping(self):
        return await self.send(UDP()/b'ping')


class UdpIpV4RawClient(UdpRawClient, IP4Mixin):
    def set_socket_options(self, sock: socket.socket):
        super().set_socket_options(sock)
        sock.setsockopt(
            socket.IPPROTO_IP,
            socket.IP_HDRINCL,
            1
        )

    def create_packet(self, packet: UDP) -> UDP:
        return IP(src=self.ip, dst=self.remote_ip) / packet

    def get_sendto_dst(self):
        return self.remote_ip, self.remote_port

    def decode_data(self, data: bytes):
        return IP(data)


class UdpIpV6RawClient(UdpRawClient, IP6Mixin):
    def set_socket_options(self, sock: socket.socket):
        super().set_socket_options(sock)
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_CHECKSUM, 6)

    def create_packet(self, packet: UDP) -> UDP:
        return packet

    def get_sendto_dst(self):
        return self.remote_ip, 0, 0, 0

    def decode_data(self, data: bytes):
        return UDP(data)
