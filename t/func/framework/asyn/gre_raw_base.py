# SPDX-FileCopyrightText: (c) 2026 Tempesta Technologies, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later

import abc
import socket

from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import GRE
from scapy.packet import Packet, Raw

from framework.stateful import IP4Mixin, IP6Mixin, RawSocketNetworkStateful

__all__ = ["BaseGreRawStateful", "GreIP4Mixin", "GreIP6Mixin"]


class BaseGreRawStateful(RawSocketNetworkStateful, abc.ABC):
    socket_proto = socket.IPPROTO_GRE

    @property
    @abc.abstractmethod
    def _ip_cls(self): ...

    @property
    @abc.abstractmethod
    def _icmp_layer(self) -> ICMP: ...

    @property
    def _ip_layer(self) -> IP | IPv6:
        return self._ip_cls(dst=self.remote_ip, src=self.ip)

    def create_packet(self, packet: Packet | bytes | str) -> GRE:
        """
        Create or modify packet.
        Packet may be any packet (TCP, UDP, etc.).
        """
        if isinstance(packet, str):
            packet = packet.encode("utf-8")

        if isinstance(packet, bytes):
            packet = Raw(load=packet)

        if not isinstance(packet, GRE):
            packet = GRE() / packet

        return packet

    def prepare_tcp_packet(self, payload: str) -> GRE:
        """Prepare correct TCP packet into GRE tunnel."""
        return self.create_packet(
            self._ip_layer / TCP(sport=self.port, dport=self.remote_port) / Raw(payload.encode())
        )

    def prepare_udp_packet(self, payload: str) -> GRE:
        """Prepare correct UDP packet into GRE tunnel."""
        return self.create_packet(
            self._ip_layer / UDP(sport=self.port, dport=self.remote_port) / Raw(payload.encode())
        )

    def prepare_icmp_packet(self, payload: str) -> GRE:
        return self.create_packet(self._ip_layer / self._icmp_layer / Raw(payload.encode()))


class GreIP4Mixin(IP4Mixin, abc.ABC):
    def get_sendto_dst(self) -> tuple:
        return self.remote_ip, 0

    @property
    def bind_params(self) -> tuple:
        return self.ip, 0

    def decode_data(self, data: bytes) -> GRE:
        return self._ip_cls(data)[GRE]

    @property
    def _ip_cls(self):
        return IP

    @property
    def _icmp_layer(self):
        return ICMP(type=8)


class GreIP6Mixin(IP6Mixin, abc.ABC):
    def get_sendto_dst(self) -> tuple:
        return self.remote_ip, 0, 0, 0

    @property
    def bind_params(self) -> tuple:
        return self.ip, 0, 0, 0

    def decode_data(self, data: bytes) -> GRE:
        return GRE(data)

    @property
    def _ip_cls(self):
        return IPv6
