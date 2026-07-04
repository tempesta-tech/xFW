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

    def datagram_received(self, data, addr):
        self.messages.put_nowait(data)
        self.last_address = addr
        self.logger.debug(f"received from {addr} : {data}")


class BaseUdpStateful(RegularKernelSocketNetworkStateful, ABC):
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
