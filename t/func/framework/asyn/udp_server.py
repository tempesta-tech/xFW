# SPDX-FileCopyrightText: (c) 2026 Tempesta Technologies, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later
import ipaddress
import socket
from abc import ABC
from ipaddress import ip_address

from framework.asyn.udp_base import BaseUdpStateful
from framework.remote import RemoteServer
from framework.stateful import IP4Mixin, IP6Mixin

__all__ = [
    "UdpServer",
    "UdpV4Server",
    "UdpV6Server",
    "UdpV6ServerMappedIP",
    "UdpV4ServerRemote",
    "UdpV6ServerRemote",
]


class UdpServer(BaseUdpStateful, ABC): ...


class UdpV4Server(UdpServer, IP4Mixin): ...


class UdpV6Server(UdpServer, IP6Mixin): ...


class UdpV6ServerMappedIP(UdpServer, IP6Mixin):
    @property
    def bind_params(self):
        return "::", self.port, 0, self.scope_id

    def set_socket_options(self, sock: socket.socket):
        super().set_socket_options(sock)

        # turn on ipv4 mapped to ipv6
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)

    @property
    def ip_testing(self):
        address = ipaddress.IPv6Address(f"::ffff:{self.ipv4}")
        return f"[{address.exploded}]"


class UdpV4ServerRemote(RemoteServer, UdpV4Server): ...


class UdpV6ServerRemote(RemoteServer, UdpV6Server): ...
