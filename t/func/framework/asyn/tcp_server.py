# SPDX-FileCopyrightText: (c) 2026 Tempesta Technologies, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later

import asyncio
import logging
import socket
import struct
from abc import ABC
from typing import Optional

from framework.asyn.tcp_base import BaseTcpStateful
from framework.remote import RemoteServer
from framework.stateful import IP4Mixin, IP6Mixin

__all__ = [
    "TcpServer",
    "TcpV4Server",
    "TcpV6Server",
    "TcpServerRemote",
    "TcpV4ServerRemote",
    "TcpV6ServerRemote",
]


class TCPServerProtocol(asyncio.Protocol):
    def __init__(
        self,
        messages: asyncio.Queue[Optional[Exception | bytes]],
        logger: logging.Logger,
        transports,
        echo_mode: bool = False,
    ):
        self.messages = messages
        self.transport = None
        self.logger: logging.Logger = logger
        self.peer_name = None
        self.transports = transports
        self.echo_mode = echo_mode
        self.req_n: int = 0
        self._msg_buffer = bytearray()

    def connection_made(self, transport):
        self.peer_name = transport.get_extra_info("peername")
        self.logger.debug(f"connection from {self.peer_name}")
        self.transport = transport
        self.transports.append(transport)

    def data_received(self, data: bytes) -> None:
        self._msg_buffer.extend(data)

        while True:
            idx = self._msg_buffer.find(b"\n")
            if idx == -1:
                break

            message = self._msg_buffer[:idx] + b"\n"
            del self._msg_buffer[: idx + 1]

            self.req_n += 1
            self.logger.debug(f"received from {self.peer_name}: {message}")
            self.messages.put_nowait(message)

        if self.echo_mode:
            self.transport.write(data)


class ServerTransport(asyncio.Transport):
    def get_protocol(self) -> Optional[TCPServerProtocol]:
        return super().get_protocol()


class TcpServer(BaseTcpStateful, ABC):
    def __init__(self, *args, echo_mode: bool = False, **kwargs):
        super().__init__(*args, **kwargs)
        self.server: asyncio.Server = None
        self.transports: list[ServerTransport] = []
        self.echo_mode = echo_mode
        self._transport = None

    @property
    def echo_mode(self) -> bool:
        return self._echo_mode

    @echo_mode.setter
    def echo_mode(self, value: bool) -> None:
        self._echo_mode = value

        for transport in self.transports:
            transport.get_protocol().echo_mode = value

    @property
    def req_n(self) -> int:
        return sum(transport.get_protocol().req_n for transport in self.transports)

    @property
    def transport(self) -> Optional[ServerTransport]:
        """
        By default server.send replies to the
        last connected client
        """

        if not self.transports:
            return None

        return self.transports[-1]

    @transport.setter
    def transport(self, value):
        self._transport = value

    def set_socket_options(self, sock: socket.socket):
        super().set_socket_options(sock)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)

    async def on_socket_created(self):
        try:
            self.server = await self.loop.create_server(
                protocol_factory=lambda: TCPServerProtocol(
                    messages=self.messages,
                    logger=self.logger,
                    transports=self.transports,
                    echo_mode=self.echo_mode,
                ),
                sock=self.socket,
            )
        except Exception as e:
            raise ConnectionError(f"Can not start TCP server: {e}") from e

        await self.server.start_serving()
        self.logger.debug("server is serving now")

    def close_all_clients_sockets(self):
        for transport in self.transports:
            if transport.is_closing():
                continue

            client_socket = transport.get_extra_info("socket")
            client_socket.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
            transport.abort()
            self.logger.debug(f"closed {client_socket}")

        self.logger.debug(f"closed {len(self.transports)} transports")

    async def run_stop(self):
        self.close_all_clients_sockets()
        self.server.close()
        await super().run_stop()


class TcpV4Server(IP4Mixin, TcpServer): ...


class TcpV6Server(IP6Mixin, TcpServer): ...


class TcpV4ServerRemote(RemoteServer, TcpV4Server): ...


class TcpV6ServerRemote(RemoteServer, TcpV6Server): ...


class TcpServerRemote(RemoteServer): ...
