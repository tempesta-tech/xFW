# SPDX-FileCopyrightText: (c) 2026 Tempesta Technologies, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later

import asyncio
import socket
import struct
from abc import ABC

from framework.stateful import RegularKernelSocketNetworkStateful

__all__ = [
    "BaseTcpStateful",
]


class BaseTcpStateful(RegularKernelSocketNetworkStateful, ABC):
    socket_type = socket.SOCK_STREAM
    transport: asyncio.Transport

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.available_rst_connection_closing: bool = True

    def use_rst_for_connection_closing(self):
        """
        For the TCP protocol use RST flag for connection closing.
        Force the OS to release ip and port quickly.
        """
        if self.socket and self.socket.fileno() == -1:
            self.logger.debug("socket is already closed")
            return

        linger = struct.pack("ii", 1, 0)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, linger)
        self.logger.debug("used rst to close the connection")

    async def run_stop(self):
        if self.available_rst_connection_closing:
            self.use_rst_for_connection_closing()

        return await super().run_stop()
