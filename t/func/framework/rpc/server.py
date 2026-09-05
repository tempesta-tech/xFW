# SPDX-FileCopyrightText: (c) 2026 Tempesta Technologies, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later

# All imports need to prepare the env and preload all reqs

import asyncio
import dataclasses
import time
import traceback

from framework.logger import *

logger = get_logger("server")

from framework.asyn import *
from framework.clickhouse import ClickhouseClient
from framework.cmp import *
from framework.namespaces import *
from framework.networks import *
from framework.rpc.protocol import (
    FRAME_END,
    SENTINEL_CLICKHOUSE,
    SENTINEL_LOOP,
    TYPE_ASYNC,
    TYPE_ATTR,
    TYPE_DEF,
    TYPE_NEW,
    TYPE_SHUTDOWN,
    RpcRequest,
    RpcResponse,
    encode_result,
)
from framework.utils import *
from framework.xfw import *


@dataclasses.dataclass
class RpcServer:
    """
    The RpcServer receives structured RPC calls via TCP and executes
    them in a persistent context that is preserved throughout the
    entire session.

    Each request is a JSON object framed by a newline:

        {"id": 1, "type": "def", "target": "obj_...", "name": "ip_format",
         "params": ["2001::2"], "kwargs": {}}

    Types:
        attr     - read ``target.name``
        def      - call ``target.name(*params, **kwargs)``
        async    - await ``target.name(*params, **kwargs)``
        new      - ``target = name(*params, **kwargs)`` in the session context
        shutdown - stop the server

    The matching response is ``{"id": ..., "result": ...}`` (or ``error``).
    The client matches replies by ``id``.

    Currently, only simple return types are supported:
    str, int, bool, None, lists/dicts of these types,
    as well as JSON-serializable objects.
    """

    host: str
    port: int
    cmd_timeout: float
    server: asyncio.Server = None
    stop_if_not_connections_sec: int = 10
    client_connected: bool = False
    stop_task: asyncio.Task = None
    clickhouse_client: ClickhouseClient = None

    def _resolve_kwargs(self, kwargs: dict, global_ctx: dict) -> dict:
        resolved = {}
        for key, value in kwargs.items():
            if value == SENTINEL_LOOP:
                resolved[key] = global_ctx["loop"]
            elif value == SENTINEL_CLICKHOUSE:
                resolved[key] = self.clickhouse_client
            else:
                resolved[key] = value
        return resolved

    async def execute_request(self, global_ctx: dict, req: RpcRequest) -> tuple[str, object, float]:
        """
        Executes a structured RPC request. Returns a log label, the result
        (or a traceback string), and elapsed time.
        """
        start_at = time.time()
        label = f"{req.type} {req.target}.{req.name}".strip(".")

        try:
            kwargs = self._resolve_kwargs(req.kwargs, global_ctx)

            if req.type == TYPE_ATTR:
                res = getattr(global_ctx[req.target], req.name)
            elif req.type == TYPE_DEF:
                res = getattr(global_ctx[req.target], req.name)(*req.params, **kwargs)
            elif req.type == TYPE_ASYNC:
                res = await asyncio.wait_for(
                    getattr(global_ctx[req.target], req.name)(*req.params, **kwargs),
                    timeout=self.cmd_timeout,
                )
            elif req.type == TYPE_NEW:
                cls = global_ctx.get(req.name)
                if cls is None:
                    cls = globals()[req.name]
                global_ctx[req.target] = cls(*req.params, **kwargs)
                res = None
            else:
                raise ValueError(f"unknown rpc type: {req.type}")
        except Exception:
            res = traceback.format_exc()

        return label, res, time.time() - start_at

    async def handle_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ):
        """
        Accepts new client connections and processes incoming messages.

        Checks for the special shutdown request to stop the server.

        Sets the ``client_connected`` flag to prevent the server from stopping
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
                data = await reader.readuntil(FRAME_END.encode())

                if not data:
                    break

                message = data.decode().strip()
                if not message:
                    logger.info(f"{self} Skipped empty string from {formatted_addr}")
                    continue

                req = RpcRequest.decode(message)

                if req.type == TYPE_SHUTDOWN:
                    logger.info(f"Received shutdown from {formatted_addr} id={req.id}")
                    writer.write(RpcResponse(id=req.id, result=None).encode())
                    await writer.drain()
                    writer.close()
                    await writer.wait_closed()
                    return await self.shutdown()

                logger.info(f"================================================")
                logger.info(f"Received call from {formatted_addr}")
                logger.info(f"id={req.id} type={req.type} target={req.target} name={req.name}")
                logger.info(f"params={req.params} kwargs={req.kwargs}")
                logger.info(f"------------------- EXEC -----------------------")

                label, result, exec_time = await self.execute_request(global_ctx, req)

                logger.info(label)
                logger.info(f"------------------------------------------------")

                error = None
                encoded = None
                if isinstance(result, str) and "Traceback" in result:
                    error = result
                    logger.info(f"Exec.Time={exec_time:.3f}s")
                    logger.info(f"------------------ ERROR -----------------------")
                    for line in result.split("\n"):
                        logger.info(line)
                else:
                    encoded = encode_result(result)
                    logger.info(f"Exec.Time={exec_time:.3f}s, Result={encoded}")

                logger.info(f"------------------------------------------------\n\n")

                writer.write(RpcResponse(id=req.id, result=encoded, error=error).encode())
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
        await self.clickhouse_client.connect()

        if self.stop_if_not_connections_sec:
            loop = asyncio.get_event_loop()
            self.stop_task = loop.create_task(self.stop_if_nobody_connected())

        async with self.server:
            await self.server.serve_forever()
