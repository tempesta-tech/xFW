# SPDX-FileCopyrightText: (c) 2026 Tempesta Technologies, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later

import asyncio
import threading
from concurrent.futures import Future
from typing import Any

from framework.logger import *
from framework.rpc.protocol import (
    FRAME_END,
    TYPE_SHUTDOWN,
    RpcRequest,
    RpcResponse,
)

logger = get_logger("rpc-client")


class RpcClient:
    """
    RPC client that owns the TCP connection on a dedicated thread
    and event loop.

    Each call gets a unique incrementing id. Responses are dispatched
    to the caller that owns that id. ``call_sync`` and ``call_async``
    share the same send path.
    """

    def __init__(self, host: str, port: int) -> None:
        self.host = host
        self.port = port

        self._thread: threading.Thread = None
        self._loop: asyncio.AbstractEventLoop = None
        self._ready = threading.Event()
        self._error: BaseException = None
        self._write_lock: asyncio.Lock = None
        self._stopping = False

        self._next_id = 0
        self._id_lock = threading.Lock()
        self._pending: dict[int, Future] = {}
        self._pending_lock = threading.Lock()

        self.reader: asyncio.StreamReader = None
        self.writer: asyncio.StreamWriter = None

    async def run(self) -> None:
        """
        Start the RPC thread and wait until the connection is up.
        """
        await asyncio.get_running_loop().run_in_executor(None, self._start)

    def _start(self) -> None:
        self._thread = threading.Thread(target=self._thread_main, name="rpc-client", daemon=True)
        self._thread.start()
        if not self._ready.wait(timeout=30):
            raise TimeoutError("RPC client failed to connect")
        if self._error:
            raise self._error

    def _thread_main(self) -> None:
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        try:
            self._loop.run_until_complete(self._connect())
            self._loop.call_soon(self._ready.set)
            self._loop.run_forever()
        except Exception as exc:
            self._error = exc
            self._ready.set()
        finally:
            self._fail_pending(ConnectionError("RPC client stopped"))
            self._cancel_pending()
            self._loop.run_until_complete(self._close())
            self._loop.close()

    async def _connect(self) -> None:
        logger.info(f"connecting to {self.host}:{self.port}")
        self._write_lock = asyncio.Lock()
        self.reader, self.writer = await asyncio.open_connection(host=self.host, port=self.port)
        self._loop.create_task(self._reader_loop())
        logger.info(f"connected, loop id = {id(self._loop)}")

    async def _reader_loop(self) -> None:
        try:
            while True:
                data = await self.reader.readuntil(FRAME_END.encode())
                if not data:
                    break

                message = data.decode().strip()
                if not message:
                    continue

                response = RpcResponse.decode(message)
                future = self._pop_pending(response.id)
                if future is None:
                    logger.warning(f"unexpected rpc reply id={response.id}")
                    continue
                if future.done():
                    continue

                if response.error:
                    future.set_result(response.error)
                else:
                    future.set_result(response.result)
        except (asyncio.IncompleteReadError, ConnectionError, OSError) as exc:
            self._fail_pending(exc)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.exception("rpc reader failed")
            self._fail_pending(exc)

    def _alloc_id(self) -> int:
        with self._id_lock:
            self._next_id += 1
            return self._next_id

    def _pop_pending(self, req_id: int) -> Future | None:
        with self._pending_lock:
            return self._pending.pop(req_id, None)

    def _fail_pending(self, exc: BaseException) -> None:
        with self._pending_lock:
            pending = list(self._pending.values())
            self._pending.clear()
        for future in pending:
            if not future.done():
                future.set_exception(exc)

    def _cancel_pending(self) -> None:
        if self._loop is None or self._loop.is_closed():
            return

        pending = asyncio.all_tasks(self._loop)
        for task in pending:
            task.cancel()
        if pending:
            self._loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))

    def _submit(
        self,
        req_type: str,
        target: str = "",
        name: str = "",
        params: list[Any] = None,
        kwargs: dict[str, Any] = None,
    ) -> tuple[int, Future]:
        if self._stopping or self._loop is None or not self._loop.is_running():
            raise RuntimeError("RPC client is not running")

        req_id = self._alloc_id()
        future: Future = Future()
        with self._pending_lock:
            self._pending[req_id] = future

        request = RpcRequest(
            id=req_id,
            type=req_type,
            target=target,
            name=name,
            params=params or [],
            kwargs=kwargs or {},
        )
        asyncio.run_coroutine_threadsafe(self._send(request), self._loop)
        return req_id, future

    async def _send(self, request: RpcRequest) -> None:
        logger.info(
            f"exec id={request.id} type={request.type} "
            f"target={request.target} name={request.name}"
        )
        try:
            async with self._write_lock:
                self.writer.write(request.encode())
                await self.writer.drain()
        except Exception as exc:
            future = self._pop_pending(request.id)
            if future is not None and not future.done():
                future.set_exception(exc)

    def call_sync(
        self,
        req_type: str,
        target: str = "",
        name: str = "",
        params: list[Any] = None,
        kwargs: dict[str, Any] = None,
        timeout: float = None,
    ) -> Any:
        """
        Send a structured call and block until the reply with this id arrives.
        Safe to call from any thread except the RPC thread itself.
        """
        req_id, future = self._submit(req_type, target, name, params, kwargs)
        wait = None if timeout is None else timeout + 1
        try:
            return future.result(timeout=wait)
        except TimeoutError:
            self._pop_pending(req_id)
            raise

    async def call_async(
        self,
        req_type: str,
        target: str = "",
        name: str = "",
        params: list[Any] = None,
        kwargs: dict[str, Any] = None,
        timeout: float = None,
    ) -> Any:
        """
        Send a structured call and await the reply with this id.
        """
        req_id, future = self._submit(req_type, target, name, params, kwargs)
        wait = None if timeout is None else timeout + 1
        try:
            return await asyncio.wait_for(asyncio.wrap_future(future), timeout=wait)
        except TimeoutError:
            self._pop_pending(req_id)
            raise

    async def _close(self) -> None:
        if self.writer is None:
            return

        try:
            self.writer.close()
            await self.writer.wait_closed()
        except Exception:
            pass

        self.reader = None
        self.writer = None

    async def shutdown_server(self) -> None:
        """
        Send the special message to stop the server.
        """
        try:
            await self.call_async(TYPE_SHUTDOWN)
        except (ConnectionError, EOFError, OSError, asyncio.IncompleteReadError):
            logger.debug("RPC server closed the connection on shutdown")

    async def shutdown(self) -> None:
        """
        Stop the RPC thread and close the connection.
        """
        await asyncio.get_running_loop().run_in_executor(None, self._stop)

    def _stop(self) -> None:
        self._stopping = True
        if self._loop is not None:
            try:
                self._loop.call_soon_threadsafe(self._loop.stop)
            except RuntimeError:
                pass
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None
