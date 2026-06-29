# SPDX-FileCopyrightText: (c) 2026 Tempesta Technologies, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later

import asyncio
import functools

import backoff
import dataclasses
import enum
import logging
from scapy.layers.inet import TCP
from scapy.layers.inet6 import Raw

from contextlib import asynccontextmanager
from typing import Callable, TypeVar, Union
from framework.logger import get_logger

T = TypeVar('T')
logger = get_logger('utils')


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
        log_output = False
) -> tuple[int, str, str]:
    logger.debug(cmd)
    process = await asyncio.create_subprocess_shell(
        cmd=cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        cwd=cwd
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


def client_cloner(
        client: T,
        amount: int,
        fabric = None
) -> list[T]:
    ports = client.generate_new_ports(amount)
    addresses = client.generate_new_addresses(amount)
    class_to_create = client.__class__

    if fabric:
        class_to_create = fabric

    clients = []

    for port, address in zip(ports, addresses):
        clients.append(class_to_create(
            network_interface=client.network_interface,
            ipv4=address if client.ipv4 else None,
            ipv4_mask=client.ipv4_mask if client.ipv4 else None,
            ipv6=address if client.ipv6 else None,
            ipv6_mask=client.ipv6_mask if client.ipv6 else None,
            port=port,
            remote_ip=client.remote_ip,
            remote_port=client.remote_port,
            logger=client.logger,
            namespace=client.namespace,
            testing_model=client.testing_model,
            timeout=client.timeout,
        ))

    return clients


def server_cloner(
        server: T,
        amount: int,
        fabric = None,
) -> list[T]:
    ports = server.generate_new_ports(amount)
    addresses = server.generate_new_addresses(amount)
    class_to_create = server.__class__

    if fabric:
        class_to_create = fabric

    servers = []

    for port, address in zip(ports, addresses):
        servers.append(class_to_create(
            network_interface=server.network_interface,
            ipv4=address if server.ipv4 else None,
            ipv4_mask=server.ipv4_mask if server.ipv4 else None,
            ipv6=address if server.ipv6 else None,
            ipv6_mask=server.ipv6_mask if server.ipv6 else None,
            port=port,
            logger=server.logger,
            testing_model=server.testing_model,
            rpc_connection=server.rpc_connection,
            timeout=server.timeout,
            namespace=server.namespace,
        ))

    return servers



@asynccontextmanager
async def run_in_background(
        coroutines: list[Callable],
        timeout: int = 60
):
    tasks = [asyncio.create_task(coroutine) for coroutine in coroutines]

    yield tasks

    _, pending = await asyncio.wait(tasks, timeout=timeout)

    if not pending:
        return

    raise  TimeoutError(f'Task is still undone after {timeout} seconds')


def compare_metrics_diff(
        compare_metrics: list[str],
        all_metrics: dict[str, int],
        diff_metrics: dict[str, Union[int, tuple[int, int]]],
        strict: bool = False
) -> list[InvalidMetric]:
    not_all_metrics_registered = {i for i in diff_metrics.keys()} - {i for i in compare_metrics}

    if not_all_metrics_registered:
        raise ValueError(f'Not all metrics from diff_metrics were registered: {not_all_metrics_registered}')

    invalid_metrics = []

    for metric in compare_metrics:
        if metric not in diff_metrics:
            continue

        is_range = isinstance(diff_metrics[metric], list)

        if is_range:
            if not (diff_metrics[metric][0] <= all_metrics[metric] < diff_metrics[metric][1]):
                invalid_metrics.append(InvalidMetric(
                    name=metric, value=all_metrics[metric], expected=diff_metrics[metric]))
        elif diff_metrics[metric] != all_metrics[metric]:
            invalid_metrics.append(InvalidMetric(
                name=metric, value=all_metrics[metric], expected=diff_metrics[metric]))

    if not strict:
        return invalid_metrics

    for metric in all_metrics:
        if metric in diff_metrics:
            continue

        if all_metrics[metric] == 0:
            continue

        invalid_metrics.append(InvalidMetric(
            name=metric, value=all_metrics[metric], expected=0
        ))

    return invalid_metrics


def metrics_increased(
        metrics: list[str],
        diff_metrics: dict[str, Union[int, tuple[int, int]]]
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
                    f'The coroutine {func.__name__} failed after several attempts')
        return wrapper
    return outer_wrapper


def get_tcp_packet(
        flag: str = None,
        seq: int = 32513451,
        window: int = 64240,
        options: list[tuple] = (('MSS', 1460), ('WScale', 7)),
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

