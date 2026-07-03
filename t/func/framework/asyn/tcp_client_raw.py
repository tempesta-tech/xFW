# SPDX-FileCopyrightText: (c) 2026 Tempesta Technologies, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later

import socket
from abc import ABC

from scapy.layers.inet import IP, TCP
from scapy.packet import Packet

from framework.asyn.tcp_raw_base import BaseTcpRawStateful
from framework.stateful import IP4Mixin, IP6Mixin, RawSocketNetworkStateful

__all__ = ["TcpRawClient", "TcpIpV4RawClient", "TcpIpV6RawClient"]


class TcpRawClient(BaseTcpRawStateful, RawSocketNetworkStateful, ABC):

    @property
    def valid_syn_packet(self) -> TCP:
        return TCP(
            flags="S",
            seq=32513451,
            window=64240,
            options=[
                ("MSS", 1460),
                ("SAckOK", b""),
                ("Timestamp", (3727125531, 0)),
                ("NOP", None),
                ("WScale", 7),
            ],
        )

    def is_packet_my(self, packet: Packet) -> bool:
        default_filter = super().is_packet_my(packet)

        if not default_filter:
            return False

        if packet[TCP].ack != self.seq:
            return False

        return True

    async def handshake(self, packet: TCP = None) -> bool:
        """
        Note: e1000 and rtl8139 don't start handshake without WScale option
        """
        await self.send(packet or self.valid_syn_packet)

        response = await self.receive()
        assert response is not None, "Server did not replied"
        assert self.has_flag(
            response, "SA"
        ), f"Unexpected reply packet with flags = {response.flags}. Expected SA. Packet: {response}"

        await self.send(TCP(flags="A"))

        return True


class TcpIpV4RawClient(TcpRawClient, IP4Mixin):
    def set_socket_options(self, sock: socket.socket):
        super().set_socket_options(sock)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    def create_packet(self, packet: TCP):
        return IP(src=self.ip, dst=self.remote_ip) / packet

    def get_sendto_dst(self):
        return self.remote_ip, self.remote_port

    def decode_data(self, data: bytes):
        return IP(data)


class TcpIpV6RawClient(TcpRawClient, IP6Mixin):
    def set_socket_options(self, sock: socket.socket):
        super().set_socket_options(sock)
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_CHECKSUM, 16)

    def create_packet(self, packet: TCP):
        return packet

    def get_sendto_dst(self):
        return self.remote_ip, 0, 0, 0

    def decode_data(self, data: bytes):
        return TCP(data)
