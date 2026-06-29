# SPDX-FileCopyrightText: (c) 2026 Tempesta Technologies, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later

import pytest
from framework.stateful import (
    RegularKernelSocketNetworkStateful
)
from framework.xfw import XFW
from framework.cmp import check_connection
from config import ConfigSettings


@pytest.fixture
async def xfw_multiple_nics(xfw: XFW, config: ConfigSettings):
    xfw.network_interface = ' '.join([
        config.backend_interface_host,
        config.client_interface_host
    ])
    await xfw.restart()
    yield xfw


@pytest.mark.skip('ISSUE: 492')
@pytest.mark.only_in_gate_mode
async def test_tc(
        xfw_multiple_nics: XFW,
        protocol: str,
        ip_version: str,
        server: RegularKernelSocketNetworkStateful,
        client: RegularKernelSocketNetworkStateful,
        establish_connection
):
    await xfw_multiple_nics.rules_set(
        """
        xfw {
            defaults { dst: allow; }
        }
        """
    )
    assert await check_connection(client, server) is True

    await xfw_multiple_nics.rules_patch(
        f'''
           xfw {{
               dst {ip_version}.{protocol} : block {{
                   {server.ip_testing}:{server.port}
               }}
           }}
           '''
    )
    assert await check_connection(client, server) is False
    assert await check_connection(server, client) is True

    await xfw_multiple_nics.rules_patch(
        f'''
           xfw {{
               dst {ip_version}.{protocol} : block {{
                   {client.ip_testing}:{client.port}
               }}
           }}
           '''
    )

    assert await check_connection(client, server) is False
    assert await check_connection(server, client) is False


@pytest.mark.only_in_gate_mode
async def test_xdp(
        xfw_multiple_nics: XFW,
        protocol: str,
        ip_version: str,
        server: RegularKernelSocketNetworkStateful,
        client: RegularKernelSocketNetworkStateful,
        establish_connection
):
    await xfw_multiple_nics.rules_set(
        """
        xfw {
            defaults { src_ip: allow; src_port: allow; }
        }
        """
    )
    assert await check_connection(client, server) is True

    await xfw_multiple_nics.rules_patch(
        f'''
           xfw {{
               src {ip_version}.{protocol} : block {{
                   {server.ip_testing}
               }}
           }}
           '''
    )
    assert await check_connection(client, server) is True
    assert await check_connection(server, client) is False

    await xfw_multiple_nics.rules_patch(
        f'''
           xfw {{
               src {ip_version}.{protocol} : block {{
                   {client.ip_testing}
               }}
           }}
           '''
    )
    assert await check_connection(client, server) is False
    assert await check_connection(server, client) is True
