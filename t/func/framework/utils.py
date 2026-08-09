# SPDX-FileCopyrightText: (c) 2026 Tempesta Technologies, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later

from __future__ import annotations

import asyncio
import dataclasses
import enum
import functools
import logging
from contextlib import asynccontextmanager
from typing import TYPE_CHECKING, Any, Callable, Coroutine, Optional, Protocol, Type, Union

import backoff
from scapy.layers.inet import TCP
from scapy.layers.inet6 import Raw

from framework.logger import get_logger

if TYPE_CHECKING:
    from framework.stateful import RegularKernelSocketNetworkStateful

logger = get_logger("utils")


class ClonerCallable(Protocol):
    def __call__(
        self,
        cloner: RegularKernelSocketNetworkStateful,
        amount: int,
        fabric: Optional[Type[RegularKernelSocketNetworkStateful]] = None,
    ) -> list[RegularKernelSocketNetworkStateful]: ...


class RetryException(Exception):
    """
    The coroutine has invalid result, need to try
    repeat it again
    """


class RetryNotHelpedException(ValueError):
    """
    After the several times of function repeat it
    does not return expected value
    """


@dataclasses.dataclass
class InvalidMetric:
    name: str
    value: int
    expected: Union[int, tuple[int, int]]


class OsType(enum.IntEnum):
    linux = 0
    mac = 1
    win = 2


async def run_cmd(
    cmd: str,
    logger: logging.Logger,
    wait_for_result: bool = True,
    cwd: str = None,
    log_output=False,
) -> tuple[int, str, str]:
    logger.debug(cmd)
    process = await asyncio.create_subprocess_shell(
        cmd=cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, cwd=cwd
    )

    async def _log_when_done(proc: asyncio.subprocess.Process):
        await proc.wait()

        stdout = await proc.stdout.read()
        stdout = stdout.decode()
        stderr = await proc.stderr.read()
        stderr = stderr.decode()

        if not log_output:
            return proc.returncode, stdout, stderr

        if proc.returncode:
            logger.error(stderr.strip())
        else:
            logger.info(stdout.strip())

        return proc.returncode, stdout, stderr

    if wait_for_result:
        return await _log_when_done(process)

    return process, None, None


@asynccontextmanager
async def run_in_background(
    coroutines: list[Coroutine[Any, Any, Any]], timeout: int = 60
):
    tasks = [asyncio.create_task(coroutine) for coroutine in coroutines]

    yield tasks

    _, pending = await asyncio.wait(tasks, timeout=timeout)

    if not pending:
        return

    raise TimeoutError(f"Task is still undone after {timeout} seconds")


def compare_metrics_diff(
    compare_metrics: list[str],
    all_metrics: dict[str, int],
    diff_metrics: dict[str, Union[int, tuple[int, int]]],
    strict: bool = False,
) -> list[InvalidMetric]:
    not_all_metrics_registered = {i for i in diff_metrics.keys()} - {i for i in compare_metrics}

    if not_all_metrics_registered:
        raise ValueError(
            f"Not all metrics from diff_metrics were registered: {not_all_metrics_registered}"
        )

    invalid_metrics = []

    for metric in compare_metrics:
        if metric not in diff_metrics:
            continue

        is_range = isinstance(diff_metrics[metric], list)

        if is_range:
            if not (diff_metrics[metric][0] <= all_metrics[metric] < diff_metrics[metric][1]):
                invalid_metrics.append(
                    InvalidMetric(
                        name=metric, value=all_metrics[metric], expected=diff_metrics[metric]
                    )
                )
        elif diff_metrics[metric] != all_metrics[metric]:
            invalid_metrics.append(
                InvalidMetric(name=metric, value=all_metrics[metric], expected=diff_metrics[metric])
            )

    if not strict:
        return invalid_metrics

    for metric in all_metrics:
        if metric in diff_metrics:
            continue

        if all_metrics[metric] == 0:
            continue

        invalid_metrics.append(InvalidMetric(name=metric, value=all_metrics[metric], expected=0))

    return invalid_metrics


def metrics_increased(
    metrics: list[str], diff_metrics: dict[str, Union[int, tuple[int, int]]]
) -> bool:
    for metric in metrics:
        if metric not in diff_metrics:
            return False

        if diff_metrics[metric] == 0:
            return False

    return True


async def switch_coroutine():
    await asyncio.sleep(0.001)


def retry_on_failure(exception: Exception, *_, max_time: int = 5):
    def outer_wrapper(func: Callable):
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            try:
                return await backoff.on_exception(
                    wait_gen=backoff.constant,
                    exception=exception,
                    max_time=max_time,
                    logger=None,
                )(func)(*args, **kwargs)
            except RetryException:
                raise RetryNotHelpedException(
                    f"The coroutine {func.__name__} failed after several attempts"
                )

        return wrapper

    return outer_wrapper


def get_tcp_packet(
    flag: str = None,
    seq: int = 32513451,
    window: int = 64240,
    options: list[tuple] = (("MSS", 1460), ("WScale", 7)),
    payload: bytes = None,
) -> TCP:
    packet = TCP(
        flags=flag,
        seq=seq,
        window=window,
        options=options,
    )

    if payload:
        packet = packet / Raw(payload)

    return packet
