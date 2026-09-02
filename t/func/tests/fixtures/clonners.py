# SPDX-FileCopyrightText: (c) 2026 Tempesta Technologies, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later

from typing import Any

import pytest

from framework.asyn import *
from framework.stateful import SocketBaseNetworkStateful
from framework.utils import ClonerCallable


@pytest.fixture(scope="function")
async def server_cloner() -> ClonerCallable:
    _clones: list[SocketBaseNetworkStateful] = []

    def wrapper(
        cloner: SocketBaseNetworkStateful, amount: int, fabric: Optional[Any] = None
    ) -> list[SocketBaseNetworkStateful]:
        nonlocal _clones

        ports = cloner.generate_new_ports(amount)
        addresses = cloner.generate_new_addresses(amount)

        class_to_create = fabric if fabric else cloner.__class__

        for port, address in zip(ports, addresses):
            _clones.append(
                class_to_create(
                    network_interface=cloner.network_interface,
                    ipv4=address if cloner.ipv4 else None,
                    ipv4_mask=cloner.ipv4_mask if cloner.ipv4 else None,
                    ipv6=address if cloner.ipv6 else None,
                    ipv6_mask=cloner.ipv6_mask if cloner.ipv6 else None,
                    port=port,
                    logger=cloner.logger,
                    testing_model=cloner.testing_model,
                    rpc_connection=cloner.rpc_connection,
                    timeout=cloner.timeout,
                    namespace=cloner.namespace,
                )
            )
        return _clones

    yield wrapper

    await asyncio.gather(*[clone.stop() for clone in _clones], return_exceptions=True)
    _clones.clear()


@pytest.fixture(scope="function")
async def client_cloner(server_cloner) -> ClonerCallable:
    """
    server_cloner: The server cloner fixture. Required to enforce the correct teardown sequence in pytest.

    Note on Lifecycle & Teardown Order:
        Pytest executes fixture teardown blocks (the code after `yield`) in
        reverse order of their initialization (LIFO - Last In, First Out).

        By making `client_cloner` explicitly depend on `server_cloner`, we
        guarantee the following graceful shutdown sequence after each test:

        1. Client Cleanup First: The teardown block in this fixture runs first,
           stopping and cleaning up all active client clones.
        2. Server Cleanup Second: Pytest then proceeds to `server_cloner`'s
           teardown block, shutting down the servers.

        This specific order prevents active clients from attempting to send
        traffic to already closed server sockets, avoiding intermittent
        'ConnectionResetError' exceptions or hung test processes.
    """
    _clones: list[SocketBaseNetworkStateful] = []

    def wrapper(
        cloner: SocketBaseNetworkStateful, amount: int, fabric: Optional[Any] = None
    ) -> list[SocketBaseNetworkStateful]:
        nonlocal _clones

        ports = cloner.generate_new_ports(amount)
        addresses = cloner.generate_new_addresses(amount)

        class_to_create = fabric if fabric else cloner.__class__

        for port, address in zip(ports, addresses):
            _clones.append(
                class_to_create(
                    network_interface=cloner.network_interface,
                    ipv4=address if cloner.ipv4 else None,
                    ipv4_mask=cloner.ipv4_mask if cloner.ipv4 else None,
                    ipv6=address if cloner.ipv6 else None,
                    ipv6_mask=cloner.ipv6_mask if cloner.ipv6 else None,
                    port=port,
                    remote_ip=cloner.remote_ip,
                    remote_port=cloner.remote_port,
                    logger=cloner.logger,
                    namespace=cloner.namespace,
                    testing_model=cloner.testing_model,
                    timeout=cloner.timeout,
                )
            )
        return _clones

    yield wrapper

    await asyncio.gather(*[clone.stop() for clone in _clones], return_exceptions=True)
    _clones.clear()
