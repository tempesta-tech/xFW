# SPDX-FileCopyrightText: (c) 2026 Tempesta Technologies, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later

import asyncio

from framework.stateful import RegularKernelSocketNetworkStateful


async def check_connection(
    client: RegularKernelSocketNetworkStateful,
    server: RegularKernelSocketNetworkStateful,
    timeout: int = 5,
) -> bool:
    if not server.is_running:
        await server.start()

    if not client.is_running:
        try:
            await asyncio.wait_for(client.start(), timeout)
        except (ConnectionError, TimeoutError):
            return False

    try:
        await asyncio.wait_for(client.send_message(), timeout)

        if not await asyncio.wait_for(server.receive_message(), timeout):
            return False

        return True
    except TimeoutError:
        return False
