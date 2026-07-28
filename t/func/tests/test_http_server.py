# SPDX-FileCopyrightText: (c) 2026 Tempesta Technologies, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later

import asyncio

import pytest
from anyio.pytest_plugin import pytest_pycollect_makeitem

from framework.xfw import XFW


@pytest.fixture
async def xfw_with_updated_port(xfw: XFW):
    new_port = 12345
    old_port = xfw.http_port
    xfw.http_port = new_port
    await xfw.set_http_port(new_port)
    await xfw.restart()

    yield xfw
    xfw.http_port = old_port
    await xfw.set_http_port(old_port)
    await xfw.restart()


async def test_http_server_on_different_port(xfw_with_updated_port: XFW):
    try:
        http_client = xfw_with_updated_port.http_client()
        response = await http_client.get("/metrics")
    finally:
        ...

    assert response is not None
    assert response.status_code == 200


async def test_concurrent_requests(xfw: XFW):
    http_client = xfw.http_client()
    coroutines = [http_client.get("/metrics") for _ in range(100)]
    responses = await asyncio.gather(*coroutines)
    assert len([resp for resp in responses if resp.status_code == 200]) == 100


async def test_keep_alive(xfw: XFW):
    http_client = xfw.http_client()

    async with http_client as client:
        response = await client.get("/metrics", headers={"Connection": "keep-alive"})
        assert response.status_code == 200

        response = await client.get("/metrics", headers={"Connection": "keep-alive"})
        assert response.status_code == 200

        assert len(client._transport._pool.connections) == 1
