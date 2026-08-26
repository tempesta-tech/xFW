# SPDX-FileCopyrightText: (c) 2026 Tempesta Technologies, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later

import asyncio
import logging
import socket
from abc import ABC
from typing import Optional

from framework.stateful import RegularKernelSocketNetworkStateful

__all__ = [
    "BaseUdpProtocol",
    "BaseUdpStateful",
]


class BaseUdpProtocol(asyncio.DatagramProtocol):
    def __init__(
        self, logger: logging.Logger, messages: asyncio.Queue[Optional[Exception | bytes]]
    ):
        self.logger: logging.Logger = logger
        self.messages = messages
        self.last_address = None
        self.peer_name = None
        self.transport = None

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.peer_name = transport.get_extra_info("peername")
        self.logger.debug(f"Connection initiated. Peername: {self.peer_name}")
        self.transport = transport

    def connection_lost(self, exc: Exception | None) -> None:
        self.logger.debug("Connection closed")
        self.messages.put_nowait(None)

    def error_received(self, exc: Exception) -> None:
        self.logger.warning(f"UDP error received: {exc}")
        self.messages.put_nowait(exc)

    def datagram_received(self, data: bytes, addr: tuple[str, int]):
        self.messages.put_nowait(data)
        self.last_address = addr
        self.logger.debug(f"received from {addr} : {data}")


class BaseUdpStateful(RegularKernelSocketNetworkStateful):
    protocol: BaseUdpProtocol
    socket_type = socket.SOCK_DGRAM
    socket_proto = socket.IPPROTO_UDP
    transmitting_protocol = BaseUdpProtocol
    transport: asyncio.DatagramTransport

    async def on_socket_created(self):
        self.transport, self.protocol = await self.loop.create_datagram_endpoint(
            protocol_factory=lambda: self.transmitting_protocol(
                self.logger, messages=self.messages
            ),
            sock=self.socket,
        )
