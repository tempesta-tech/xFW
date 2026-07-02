# SPDX-FileCopyrightText: (c) 2026 Tempesta Technologies, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later

import asyncio
import dataclasses

from framework.logger import *

logger = get_logger("server")


@dataclasses.dataclass
class RpcClient:
    """
    The RPC Client establishes a TCP connection with
    the server and provides reader and writer
    streams for communication.
    """

    host: str
    port: int
    reader: asyncio.StreamReader = None
    writer: asyncio.StreamWriter = None
    shutdown_message: str = "__SHUTDOWN__<<<"

    async def run(self):
        """
        Start the client
        """
        self.reader, self.writer = await asyncio.open_connection(host=self.host, port=self.port)

    async def shutdown(self):
        """
        Stop the client
        """
        self.writer.close()
        await self.writer.wait_closed()

    async def shutdown_server(self):
        """
        Send the special message to stop the server
        """
        self.writer.write(self.shutdown_message.encode())
        await self.writer.drain()
