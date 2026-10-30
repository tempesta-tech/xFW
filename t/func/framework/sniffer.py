# SPDX-FileCopyrightText: (c) 2026 Tempesta Technologies, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later
import asyncio
import logging
import os
import signal
from collections import deque
from contextlib import AsyncExitStack, suppress
from pathlib import Path
from types import TracebackType


class TcpdumpSniffer:
    def __init__(
        self,
        path: str | Path,
        *,
        namespace: str,
        logger: logging.Logger,
    ) -> None:
        self.path = Path(path)
        self.namespace = namespace
        # Only tcpdump diagnostics; packet data goes directly to disk.
        self.lines: deque[str] = deque(maxlen=1000)
        self._logger = logger
        self._process: asyncio.subprocess.Process | None = None
        self._reader: asyncio.Task[None] | None = None
        self._stop_task: asyncio.Task[None] | None = None
        self._ready = asyncio.Event()
        self._listening = False
        self._reader_error: Exception | None = None
        self._exit_stack = AsyncExitStack()

    async def __aenter__(self) -> "TcpdumpSniffer":
        try:
            await self.start()
        finally:
            self._exit_stack.push_async_callback(self.stop)

        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ):
        return await self._exit_stack.__aexit__(exc_type, exc, traceback)

    def _error(self, message: str) -> RuntimeError:
        return RuntimeError(f"{message}\npcap: {self.path}\n" + "\n".join(self.lines))

    async def start(self) -> None:
        command = [
            "ip",
            "netns",
            "exec",
            self.namespace,
            "tcpdump",
            "-i",
            "any",
            "-p",
            "-nn",
            "--immediate-mode",
            "-s",
            "0",
            "-U",
            "-w",
            "-",
        ]

        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("wb") as output:
            self._process = await asyncio.create_subprocess_exec(
                *command,
                stdin=asyncio.subprocess.DEVNULL,
                stdout=output,
                stderr=asyncio.subprocess.PIPE,
                env={**os.environ, "LC_ALL": "C"},
            )
        self._reader = asyncio.create_task(self._read_stderr())

        try:
            await asyncio.wait_for(self._ready.wait(), 5)
        except asyncio.TimeoutError as error:
            raise self._error("Timed out waiting for tcpdump to start") from error

        if self._reader_error is not None:
            raise self._error("Cannot read tcpdump diagnostics") from self._reader_error
        if not self._listening or self._process.returncode is not None:
            raise self._error("tcpdump exited before capture started")

    async def _read_stderr(self) -> None:
        assert self._process is not None
        assert self._process.stderr is not None

        try:
            async for raw_line in self._process.stderr:
                line = raw_line.decode(errors="replace").rstrip()
                self.lines.append(line)
                if "listening on" in line:
                    self._listening = True
                    self._ready.set()
        except Exception as error:
            self._reader_error = error
        finally:
            self._ready.set()

    async def stop(self) -> None:
        if self._process is not None:
            await asyncio.shield(self._real_stop())

    async def _real_stop(self) -> None:
        assert self._process is not None

        if self._process.returncode is None:
            with suppress(ProcessLookupError):
                self._process.send_signal(signal.SIGINT)

        try:
            async with asyncio.timeout(5):
                await self._process.wait()
                if self._reader:
                    await self._reader
        except TimeoutError:
            with suppress(ProcessLookupError):
                self._process.kill()
            await self._process.wait()
            raise self._error("tcpdump required SIGKILL; pcap may be incomplete")

        if self._process.returncode not in (0, -signal.SIGINT):
            raise self._error(f"tcpdump exited unexpectedly: {self._process.returncode}")
        if self._reader_error is not None:
            raise self._error("Cannot read tcpdump diagnostics") from self._reader_error
