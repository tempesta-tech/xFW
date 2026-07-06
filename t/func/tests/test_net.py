# SPDX-FileCopyrightText: (c) 2026 Tempesta Technologies, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later

import pytest

from config import ConfigSettings
from framework.cmp import check_connection
from framework.stateful import RegularKernelSocketNetworkStateful
from framework.xfw import XFW


@pytest.fixture
async def backend_protected(
    server: RegularKernelSocketNetworkStateful,
):
    yield server


@pytest.fixture
async def backend_not_protected(
    backend_protected: RegularKernelSocketNetworkStateful, config: ConfigSettings, server_cloner
) -> RegularKernelSocketNetworkStateful:
    new_server = server_cloner(cloner=backend_protected, amount=1)[0]
    yield new_server
    await new_server.stop()


@pytest.fixture
async def client_protected(
    client: RegularKernelSocketNetworkStateful,
    backend_protected: RegularKernelSocketNetworkStateful,
):
    client.remote_ip = backend_protected.ip
    client.remote_port = backend_protected.port

    yield client


@pytest.fixture
async def client_not_protected(
    client: RegularKernelSocketNetworkStateful,
    backend_not_protected: RegularKernelSocketNetworkStateful,
    client_cloner,
):
    new_client = client_cloner(cloner=client, amount=1)[0]
    new_client.remote_ip = backend_not_protected.ip
    new_client.remote_port = backend_not_protected.port

    yield new_client
    await new_client.stop()


@pytest.fixture
async def connect_protected_clients_and_backends(
    backend_protected: RegularKernelSocketNetworkStateful,
    backend_not_protected: RegularKernelSocketNetworkStateful,
    client_protected: RegularKernelSocketNetworkStateful,
    client_not_protected: RegularKernelSocketNetworkStateful,
):
    await backend_protected.start()
    await client_protected.start()

    await backend_not_protected.start()
    await client_not_protected.start()

    yield


async def test_block(
    xfw: XFW,
    ip_version: str,
    protocol: str,
    backend_protected: RegularKernelSocketNetworkStateful,
    backend_not_protected: RegularKernelSocketNetworkStateful,
    client_protected: RegularKernelSocketNetworkStateful,
    client_not_protected: RegularKernelSocketNetworkStateful,
    connect_protected_clients_and_backends,
):
    await xfw.rules_set(f"""
        xfw {{
            defaults {{ dst: allow; }}

            net {ip_version} {{ {backend_protected.ip_testing} }}
            dst=extended_group {ip_version}.{protocol} : block {{
                {backend_protected.ip_testing}:{backend_protected.port},
            }}
        }}
        """)

    assert (
        await check_connection(
            client=client_protected,
            server=backend_protected,
        )
        is False
    ), "Request to the protected server is not blocked"

    assert (
        await check_connection(
            client=client_not_protected,
            server=backend_not_protected,
        )
        is True
    ), "Request to the non-protected server is blocked"
