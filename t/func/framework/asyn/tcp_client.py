# SPDX-FileCopyrightText: (c) 2026 Tempesta Technologies, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later

import asyncio
import logging
from abc import ABC
from typing import Optional

from framework.asyn.tcp_base import BaseTcpStateful
from framework.stateful import IP4Mixin, IP6Mixin

__all__ = ["TcpClient", "TcpV4Client", "TcpV6Client"]


class TCPClientProtocol(asyncio.Protocol):
    def __init__(
        self, messages: asyncio.Queue[Optional[bytes | Exception]], logger: logging.Logger
    ):
        self.transport = None
        self.messages = messages
        self.logger = logger
        self.resp_n: int = 0
        self._msg_buffer = bytearray()

    def connection_made(self, transport):
        self.transport = transport

    def connection_lost(self, exc: Exception | None) -> None:
        self.logger.info(
            f"Connection lost: resp_n={self.resp_n} queue_size={self.messages.qsize()} exc={exc}"
        )
        self.messages.put_nowait(exc)

    def data_received(self, data: bytes) -> None:
        self._msg_buffer.extend(data)

        while True:
            i = self._msg_buffer.find(b"\n")
            if i == -1:
                break

            message = self._msg_buffer[:i] + b"\n"
            del self._msg_buffer[: i + 1]

            self.resp_n += 1
            self.messages.put_nowait(message)


class TcpClient(BaseTcpStateful):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.protocol: Optional[TCPClientProtocol] = None

    @property
    def resp_n(self) -> int:
        return self.protocol.resp_n

    async def on_socket_created(self):
        self.logger.debug(
            f"connecting to server {self.remote_ip}:{self.remote_port}, " f"timeout={self.timeout}"
        )
        await asyncio.wait_for(
            self.loop.sock_connect(sock=self.socket, address=(self.remote_ip, self.remote_port)),
            timeout=self.timeout,
        )

        self.transport, self.protocol = await asyncio.wait_for(
            self.loop.create_connection(
                protocol_factory=lambda: TCPClientProtocol(self.messages, self.logger),
                sock=self.socket,
            ),
            timeout=self.timeout,
        )


class TcpV4Client(TcpClient, IP4Mixin): ...


class TcpV6Client(TcpClient, IP6Mixin): ...
