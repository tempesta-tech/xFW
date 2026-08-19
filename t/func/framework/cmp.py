# SPDX-FileCopyrightText: (c) 2026 Tempesta Technologies, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later

import asyncio
from typing import Callable, Optional

from config import ConfigSettings
from framework.stateful import SocketBaseNetworkStateful
from framework.xfw import XFWRatelimit


async def check_connection(
    client: SocketBaseNetworkStateful,
    server: SocketBaseNetworkStateful,
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
        await asyncio.wait_for(client.ping(), timeout)

        if not await asyncio.wait_for(server.pong(), timeout):
            return False

        return True
    except TimeoutError:
        return False


class RatelimitChecker:
    def __init__(self, config: ConfigSettings):
        self._config = config

    async def check_pps_ratelimit(
        self,
        client: SocketBaseNetworkStateful,
        limit: XFWRatelimit,
        function: Optional[Callable] = None,
    ) -> None:
        """
        The method generates traffic using the network client and asserts that
        the number of successfully completed messages falls within the expected
        limit, accounting for a warmup period and a margin of error.
        """
        messages_pps = limit.pps * 5
        duration = self._config.load_duration

        assert duration > 1, "The value for duration is too small. Testing is not possible."

        function = function or client.ping_pong
        await function("Client and server cannot establish a connection.")

        results = await client.generate_traffic(
            messages_pps=messages_pps,
            duration=duration,
            function=function,
        )

        completed_n = results.count(None)
        expected_min_completed_n = limit.pps * (duration - 1)  # The client has 1 second to warm up.
        expected_max_completed_n = messages_pps * self._config.ratelimit_tolerance_factor

        assert expected_min_completed_n <= completed_n <= expected_max_completed_n, (
            "The limit does not work as expected. "
            + f"{expected_min_completed_n = }, {completed_n = }, {expected_max_completed_n = }"
        )
