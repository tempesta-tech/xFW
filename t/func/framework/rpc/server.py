# SPDX-FileCopyrightText: (c) 2026 Tempesta Technologies, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later

# All imports need to prepare the env and preload all reqs

import asyncio
import copy
import dataclasses
import time
import traceback

from framework.logger import *

logger = get_logger("server")

from framework.asyn import *
from framework.cmp import *
from framework.namespaces import *
from framework.networks import *
from framework.utils import *
from framework.xfw import *


@dataclasses.dataclass
class RpcServer:
    """
    The RpcServer receives code via TCP and executes it
    in a persistent context that is preserved throughout the
    entire session.

    Commands are separated by the delimiter '<<<', which allows
    sending multiline code blocks.

    Since the server maintains all variables in a shared context,
    name collisions are possible. Use unique variable names to
    avoid them.

    The two main command types the server can process:
        - with `await`
        - without `await`

    Commands starting with `await` are executed in the server's
    event loop as a newly created coroutine. The result of the
    command is the result of the awaited expression. This is
    typically used for calling async methods or updating properties
    with coroutines. Example:

    ```python
        await server.execute(10, "hello")
    ```

    Commands without await are useful for creating variables,
    instantiating objects, or performing synchronous operations.
    The result of such a block must be assigned to the variable
    res, which is then returned to the client. Multiline example:

    ```python
        server = Server(host="hello", port=1234)
        res = server.start()
    ```

    Currently, only simple return types are supported:
    str, int, bool, None, lists/dicts of these types,
    as well as JSON-serializable objects.

    This covers ~95% of use cases. For the remaining 5%, convert
    complex objects to simple types — e.g., instead of returning
    a full TCP packet object, return a flag indicating receipt,
    or encode the data as JSON/base64.

    The server accepts the special message `__SHUTDOWN__`,
    which shuts it down.
    """

    host: str
    port: int
    cmd_timeout: float
    server: asyncio.Server = None
    stop_if_not_connections_sec: int = 10
    shutdown_message: str = "__SHUTDOWN__"
    client_connected: bool = False
    stop_task: asyncio.Task = None

    async def execute_code(self, global_ctx: dict, code: str) -> tuple[str, str, float]:
        """
        Executes the code synchronously or asynchronously.
        Returns the result or an error.
        """
        start_at = time.time()
        res = None
        cmd = copy.copy(code)

        try:
            if not cmd.startswith("await"):
                local_ctx = {}
                exec(cmd, global_ctx, local_ctx)
                global_ctx.update(local_ctx)
                res = local_ctx.get("res")
            else:
                cmd = f"async def coro(): return {cmd}"
                exec(cmd, global_ctx)
                coro = globals()["coro"]
                # this timeout should be greater then inner
                res = await asyncio.wait_for(coro(), timeout=self.cmd_timeout)
                cmd += "\nawait coro()"

        except Exception:
            res = traceback.format_exc()

        finally:
            return cmd, str(res), time.time() - start_at

    async def handle_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ):
        """
        Accepts new client connections and processes incoming messages.

        Checks for the special `__SHUTDOWN__` message to stop the server.

        Sets the `client_connected` flag to prevent the server from stopping
        if no client has ever connected.
        """
        self.client_connected = True
        addr = writer.get_extra_info("peername")
        formatted_addr = f"{addr[0]}:{addr[1]}"
        logger.info(f"New connection from {formatted_addr}")

        global_ctx = globals()
        global_ctx["loop"] = asyncio.get_event_loop()

        try:
            while True:
                data = await reader.readuntil(b"<<<")

                if not data:
                    break

                data = data[:-3]
                message = data.decode()
                message = message.strip()

                if not message:
                    logger.info(f"{self} Skipped empty string from {formatted_addr}")
                    continue

                if message == self.shutdown_message:
                    logger.info(f"Received {self.shutdown_message} code from {formatted_addr}")
                    writer.close()
                    await writer.wait_closed()
                    return await self.shutdown()

                logger.info(f"================================================")
                logger.info(f"Received code from {formatted_addr}")
                logger.info(f"------------------- CODE -----------------------")

                code, result, exec_time = await self.execute_code(global_ctx, message)

                for line in code.split("\n"):
                    logger.info(line)

                logger.info(f"------------------------------------------------")

                if "Traceback" in result:
                    logger.info(f"Exec.Time={exec_time:.3f}s")
                    logger.info(f"------------------ ERROR -----------------------")
                    for line in result.split("\n"):
                        logger.info(line)
                else:
                    logger.info(f"Exec.Time={exec_time:.3f}s, Result={result}")

                logger.info(f"------------------------------------------------\n\n")

                writer.write(f"{result}>>>".encode())
                await writer.drain()

        except (asyncio.CancelledError, TimeoutError):
            logger.info(f"Client handler for {formatted_addr} cancelled.")

        except asyncio.IncompleteReadError:
            logger.info(f"Client {formatted_addr} closed connection unexpectedly.")

        finally:
            logger.info(f"Closed connection from {formatted_addr}")
            writer.close()
            await writer.wait_closed()

    async def shutdown(self):
        """
        Stop the server
        """
        self.server.close()
        await self.server.wait_closed()

        if self.stop_task and not self.stop_task.done():
            self.stop_task.cancel()

    async def stop_if_nobody_connected(self):
        """
        Checks if any client connection exists and
        stops the server if none do.
        """
        logger.info(
            f"will shut down server after {self.stop_if_not_connections_sec} seconds "
            f"if nobody is connected"
        )
        start_time = time.time()

        while time.time() - start_time < self.stop_if_not_connections_sec:
            if self.client_connected:
                return

            await asyncio.sleep(1)

        logger.info(
            f"server is going to shutdown - nobody connected "
            f"after {self.stop_if_not_connections_sec} seconds"
        )
        await self.shutdown()

    async def run(self):
        """
        Start the server
        """
        self.server = await asyncio.start_server(
            client_connected_cb=self.handle_client, host=self.host, port=self.port
        )

        if self.stop_if_not_connections_sec:
            loop = asyncio.get_event_loop()
            self.stop_task = loop.create_task(self.stop_if_nobody_connected())

        async with self.server:
            await self.server.serve_forever()
