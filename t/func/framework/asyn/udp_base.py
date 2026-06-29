# SPDX-FileCopyrightText: (c) 2026 Tempesta Technologies, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later

import asyncio
import logging
import socket
from abc import ABC

from typing import Optional

from framework.stateful import RegularKernelSocketNetworkStateful

__all__ = ['BaseUdpProtocol', 'BaseUdpStateful',]


class BaseUdpProtocol(asyncio.DatagramProtocol):
    def __init__(self, logger: logging.Logger, messages: asyncio.Queue[Optional[Exception | str]]):
        self.logger: logging.Logger = logger
        self.messages = messages
        self.last_address = None

    def datagram_received(self, data, addr):
        message = data.decode()
        self.messages.put_nowait(message)
        self.last_address = addr
        self.logger.debug(f'received from {addr} : {message}')


class BaseUdpStateful(RegularKernelSocketNetworkStateful, ABC):
    socket_type = socket.SOCK_DGRAM
    socket_proto = socket.IPPROTO_UDP
    transmitting_protocol = BaseUdpProtocol
    transport: asyncio.DatagramTransport

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    async def on_socket_created(self):
        self.transport, self.protocol = await self.loop.create_datagram_endpoint(
            protocol_factory=lambda: self.transmitting_protocol(
                self.logger,
                messages=self.messages
            ),
            sock=self.socket
        )

    async def send_bytes(self, data: bytes):
        self.logger.info(f'sending "{data}" to {self.remote_ip}:{self.remote_port}')
        self.transport.sendto(data, self.destination_address)

    async def send(self, data: str):
        await self.send_bytes(data.encode())
