# SPDX-FileCopyrightText: (c) 2026 Tempesta Technologies, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later
import asyncio
import ipaddress
import logging
import socket
from abc import ABC
from typing import Optional

from framework.asyn.udp_base import BaseUdpProtocol, BaseUdpStateful
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


class UdpServerProtocol(BaseUdpProtocol):
    def __init__(
        self,
        logger: logging.Logger,
        messages: asyncio.Queue[Optional[Exception | bytes]],
    ) -> None:
        super().__init__(logger, messages)
        self.echo_mode = False

    def datagram_received(self, data: bytes, addr: tuple[str, int]):
        super().datagram_received(data, addr)

        if self.echo_mode:
            self.transport.sendto(data, addr)


class UdpServer(BaseUdpStateful, ABC):
    protocol: UdpServerProtocol
    transmitting_protocol = UdpServerProtocol

    def __init__(self, *args, echo_mode: bool = False, **kwargs):
        super().__init__(*args, **kwargs)
        self.echo_mode = echo_mode

    async def on_socket_created(self):
        await super().on_socket_created()
        self.protocol.echo_mode = self.echo_mode

    @property
    def echo_mode(self) -> bool:
        return self._echo_mode

    @echo_mode.setter
    def echo_mode(self, value: bool) -> None:
        self._echo_mode = value

        if self.protocol is not None:
            self.protocol.echo_mode = value


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
        return self.ip_format(self.ipv4)


class UdpV4ServerRemote(RemoteServer, UdpV4Server): ...


class UdpV6ServerRemote(RemoteServer, UdpV6Server): ...
