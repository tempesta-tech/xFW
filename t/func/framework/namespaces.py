# SPDX-FileCopyrightText: (c) 2026 Tempesta Technologies, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later

import os, ctypes
import asyncio
import logging

try:
    libc = ctypes.CDLL("libc.so.6", use_errno=True)
except OSError as e:
    libc = None


lock = asyncio.Lock()


class NetnsNotSupportError(Exception):
    """
    The Namespace is available only on Linux
    """


class Netns:
    def __init__(self, name: str, logger: logging.Logger):
        if not libc:
            raise NetnsNotSupportError(
                'Network Namespaces is not available on this machine')

        self.name = name
        self.required_namespace = None
        self.current_namespace = None
        self.logger = logger

    async def __aenter__(self):
        if not self.name:
            return

        self.logger.debug(f'entered ns {self.name}')
        await lock.acquire()

        try:
            self.required_namespace  = os.open(f"/var/run/netns/{self.name}", os.O_RDONLY)
            self.current_namespace = os.open("/proc/self/ns/net", os.O_RDONLY)
        except Exception as error:
            lock.release()
            raise ValueError('Can not apply Network Namespace') from error

        if libc.setns(self.required_namespace, 0) != 0:
            lock.release()
            raise OSError(ctypes.get_errno(), "setns t")

    async def __aexit__(self, *_):
        if not self.name:
            return

        self.logger.debug(f'exited ns {self.name}')

        if libc.setns(self.current_namespace, 0) != 0:
            lock.release()
            raise OSError(ctypes.get_errno(), "setns o")

        os.close(self.current_namespace)
        os.close(self.required_namespace)

        lock.release()
