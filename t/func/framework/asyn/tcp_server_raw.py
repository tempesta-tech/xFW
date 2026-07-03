# SPDX-FileCopyrightText: (c) 2026 Tempesta Technologies, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later

import asyncio
import socket
from abc import ABC
from typing import Optional

from scapy.layers.inet import IP, TCP, Packet

from framework.asyn.tcp_raw_base import BaseTcpRawStateful
from framework.remote import RemoteServer
from framework.stateful import IP4Mixin, IP6Mixin

__all__ = [
    "TcpRawServer",
    "TcpIpV4RawServer",
    "TcpIpV6RawServer",
    "TcpIpV4RawServerRemote",
    "TcpIpV6RawServerRemote",
]


class TcpRawServer(BaseTcpRawStateful, ABC):
    def set_client_data(self, ip: str, port: int):
        self.remote_port = port
        self.remote_ip = ip

    async def handshake(self, packet: TCP = None) -> bool:
        """
        Note: e1000 and rtl8139 don't start handshake without WScale option
        """
        client_syn = await self.receive()
        assert self.has_flag(client_syn, "S")

        self.set_client_data(ip=self.sender_info[0], port=self.last_response.sport)

        await self.send(TCP(flags="SA", seq=2223334, options=client_syn.options))
        response = await self.receive()
        assert self.has_flag(
            response, "A"
        ), f"Unexpected reply packet with flags = {response}. Expected A Flag"

        return True

    async def close_connection(self) -> bool:
        response = await self.receive()
        assert response is not None, "Client did not start closing connection"

        if not self.has_any_flag(response, {"FA", "AF"}):
            return False

        await self.send(TCP(flags="A"))
        await self.send(TCP(flags="FA"))

        response = await self.receive()

        return self.has_flag(response, "A")

    def is_packet_my(self, packet: Packet) -> bool:
        default_filter = super().is_packet_my(packet)

        if not default_filter:
            return False

        if self.remote_port and packet[TCP].sport != self.remote_port:
            # connection established and we know our client
            return False

        if self.seq and packet[TCP].ack != self.seq:
            return False

        return True

    async def receive_packet(self) -> Optional[str]:
        response = await self.receive()

        if not response:
            return None

        return str(response.flags)

    async def receive_many_packets(self, amount: int = 10) -> int:
        requests = await asyncio.gather(*[self.receive_packet() for _ in range(amount)])
        return len([request for request in requests if request])


class TcpIpV4RawServer(TcpRawServer, IP4Mixin):
    iptables_binary_name = "iptables"
    socket_family = socket.AF_INET

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def set_socket_options(self, sock: socket.socket):
        super().set_socket_options(sock)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    def decode_data(self, data: bytes):
        return IP(data)

    def create_packet(self, packet: TCP):
        return IP(src=self.ip, dst=self.remote_ip) / packet

    def get_sendto_dst(self):
        return self.remote_ip, self.remote_port


class TcpIpV6RawServer(TcpRawServer, IP6Mixin):
    iptables_binary_name = "ip6tables"
    socket_family = socket.AF_INET6

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def set_socket_options(self, sock: socket.socket):
        super().set_socket_options(sock)
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_CHECKSUM, 16)

    def decode_data(self, data: bytes):
        return TCP(data)

    def create_packet(self, packet: TCP):
        return packet

    def get_sendto_dst(self):
        return self.remote_ip, 0, 0, 0


class TcpIpV4RawServerRemote(RemoteServer, TcpIpV4RawServer):
    remote_methods = [
        "run_stop",
        "start",
        "stop",
        "restart",
        "receive_packet",
        "receive_many_packets",
    ]

    def __init__(self, *args, **kwargs):
        RemoteServer.__init__(self, *args, **kwargs)
        TcpIpV4RawServer.__init__(self, *args, **kwargs)


class TcpIpV6RawServerRemote(RemoteServer, TcpIpV6RawServer):
    remote_methods = [
        "run_stop",
        "start",
        "stop",
        "restart",
        "receive_packet",
        "receive_many_packets",
    ]

    def __init__(self, *args, **kwargs):
        RemoteServer.__init__(self, *args, **kwargs)
        TcpIpV6RawServer.__init__(self, *args, **kwargs)
