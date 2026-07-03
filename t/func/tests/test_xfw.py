# SPDX-FileCopyrightText: (c) 2026 Tempesta Technologies, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later

import asyncio
import logging
from typing import List

import pytest

from config import ConfigSettings
from framework.asyn import TcpClient, TcpServer
from framework.cmp import check_connection
from framework.stateful import RegularKernelSocketNetworkStateful
from framework.utils import (
    RetryException,
    RetryNotHelpedException,
    client_cloner,
)
from framework.xfw import XFW, State


def rm_tabs_and_new_lines(s: str) -> str:
    return s.replace("\n", "").replace("\t", "")


async def test_xfw_push_config(
    xfw: XFW,
    tcp_ip4_server: RegularKernelSocketNetworkStateful,
    tcp_ip4_client: RegularKernelSocketNetworkStateful,
):
    await tcp_ip4_server.start()
    await tcp_ip4_client.start()
    await xfw.rules_push_config(f"""
        xfw {{
            defaults {{ dst: allow; }}
            dst ip4.tcp : block {{
                {tcp_ip4_server.ip_testing}:{tcp_ip4_server.port}
            }}
        }}
        """)
    assert (
        await check_connection(tcp_ip4_client, tcp_ip4_server) is False
    ), f"IP {tcp_ip4_server} is not blocked"


async def test_xfw_push_config_short(
    xfw: XFW,
    tcp_ip4_server: RegularKernelSocketNetworkStateful,
    tcp_ip4_client: RegularKernelSocketNetworkStateful,
):
    await tcp_ip4_server.start()
    await tcp_ip4_client.start()
    await xfw.rules_push_config_short(f"""
        xfw {{
            defaults {{ dst: allow; }}
            dst ip4.tcp : block {{
                {tcp_ip4_server.ip_testing}:{tcp_ip4_server.port}
            }}
        }}
        """)

    assert (
        await check_connection(tcp_ip4_client, tcp_ip4_server) is False
    ), f"IP {tcp_ip4_server} is not blocked"


async def test_xfw_push_config_inline(
    xfw: XFW,
    tcp_ip4_server: RegularKernelSocketNetworkStateful,
    tcp_ip4_client: RegularKernelSocketNetworkStateful,
):
    await tcp_ip4_server.start()
    await tcp_ip4_client.start()
    await xfw.rules_push_config_inline(f"""
        xfw {{
            defaults {{ dst: allow; }}
            dst ip4.tcp : block {{
                {tcp_ip4_server.ip_testing}:{tcp_ip4_server.port}
            }}
        }}
        """)

    assert (
        await check_connection(tcp_ip4_client, tcp_ip4_server) is False
    ), f"IP {tcp_ip4_server} is not blocked"


async def test_xfw_push_config_inline_no_new_lines(
    xfw: XFW,
    tcp_ip4_server: RegularKernelSocketNetworkStateful,
    tcp_ip4_client: RegularKernelSocketNetworkStateful,
):
    await tcp_ip4_server.start()
    await tcp_ip4_client.start()
    await xfw.rules_push_config_inline(rm_tabs_and_new_lines(f"""
        xfw {{
            defaults {{ dst: allow; }}
            dst ip4.tcp : block {{
                {tcp_ip4_server.ip_testing}:{tcp_ip4_server.port}
            }}
        }}
        """))

    assert (
        await check_connection(tcp_ip4_client, tcp_ip4_server) is False
    ), f"IP {tcp_ip4_server} is not blocked"


async def test_xfw_patch(
    xfw: XFW,
    tcp_ip4_server: RegularKernelSocketNetworkStateful,
    tcp_ip4_client: RegularKernelSocketNetworkStateful,
):
    await tcp_ip4_server.start()
    await tcp_ip4_client.start()
    new_addr = tcp_ip4_server.generate_new_address()
    await xfw.rules_set(f"""
        xfw {{
            defaults {{ dst: allow; }}
            dst=extended_group ip4.tcp : block {{
                {tcp_ip4_server.ip_format(new_addr)}:{tcp_ip4_server.port}
            }}
        }}
        """)
    await xfw.rules_push_patch(f"""
        xfw {{
            dst=extended_group/add ip4.tcp {{
                {tcp_ip4_server.ip_testing}:{tcp_ip4_server.port}
            }}
        }} 
        """)

    assert (
        await check_connection(tcp_ip4_client, tcp_ip4_server) is False
    ), f"IP {tcp_ip4_server} is not blocked"


async def test_xfw_patch_short(
    xfw: XFW,
    tcp_ip4_server: RegularKernelSocketNetworkStateful,
    tcp_ip4_client: RegularKernelSocketNetworkStateful,
):
    await tcp_ip4_server.start()
    await tcp_ip4_client.start()
    new_addr = tcp_ip4_server.generate_new_address()
    await xfw.rules_set(f"""
        xfw {{
            defaults {{ dst: allow; }}
            dst=extended_group ip4.tcp : block {{
                {tcp_ip4_server.ip_format(new_addr)}:{tcp_ip4_server.port}
            }}
        }}
        """)
    await xfw.rules_push_patch_short(f"""
        xfw {{
            dst=extended_group/add ip4.tcp {{
                {tcp_ip4_server.ip_testing}:{tcp_ip4_server.port}
            }}
        }} 
        """)

    assert (
        await check_connection(tcp_ip4_client, tcp_ip4_server) is False
    ), f"IP {tcp_ip4_server} is not blocked"


async def test_xfw_patch_inline(
    xfw: XFW,
    tcp_ip4_server: RegularKernelSocketNetworkStateful,
    tcp_ip4_client: RegularKernelSocketNetworkStateful,
):
    await tcp_ip4_server.start()
    await tcp_ip4_client.start()
    new_addr = tcp_ip4_server.generate_new_address()
    await xfw.rules_set(f"""
        xfw {{
            defaults {{ dst: allow; }}
            dst=extended_group ip4.tcp : block {{
                {tcp_ip4_server.ip_format(new_addr)}:{tcp_ip4_server.port}
            }}
        }}
        """)
    await xfw.rules_push_patch_inline(f"""
        xfw {{
            dst=extended_group/add ip4.tcp {{
                {tcp_ip4_server.ip_testing}:{tcp_ip4_server.port}
            }}
        }} 
        """)

    assert (
        await check_connection(tcp_ip4_client, tcp_ip4_server) is False
    ), f"IP {tcp_ip4_server} is not blocked"


async def test_xfw_patch_inline_no_new_line(
    xfw: XFW,
    tcp_ip4_server: RegularKernelSocketNetworkStateful,
    tcp_ip4_client: RegularKernelSocketNetworkStateful,
):
    await tcp_ip4_server.start()
    await tcp_ip4_client.start()
    new_addr = tcp_ip4_server.generate_new_address()
    await xfw.rules_set(f"""
        xfw {{
            defaults {{ dst: allow; }}
            dst=extended_group ip4.tcp : block {{
                {tcp_ip4_server.ip_format(new_addr)}:{tcp_ip4_server.port}
            }}
        }}
        """.replace("\n", ""))
    await xfw.rules_push_patch_inline(rm_tabs_and_new_lines(f"""
        xfw {{
            dst=extended_group/add ip4.tcp {{
                {tcp_ip4_server.ip_testing}:{tcp_ip4_server.port}
            }}
        }} 
        """))

    assert (
        await check_connection(tcp_ip4_client, tcp_ip4_server) is False
    ), f"IP {tcp_ip4_server} is not blocked"


async def test_zeroed_ipv6(xfw: XFW):
    await xfw.rules_set(f"""
        xfw {{
            src=extended_group ip6.tcp : block {{
                3333:3333:3333:3333:3333:3333:3333:3333,
                ::,
                3000::,
                ::3000,
                3000::3000,
                :3000,
                4000::/126,
                ::4000/126,
                4000::4000/126,
                [5000::],
                [::5000],
                [5000::5000]
            }}

            dst=extended_group ip6.tcp : block {{
                [ffff::]:1000,
                [::ffff]:1000,
                [aaaa::ffff]:1000,
            }}
        }}
        """)

    await xfw.rules_set(f"""
        xfw {{
            src=extended_group ip6.tcp : block {{ 
            ::/126 
            }}
        }}
        """)

    await xfw.rules_set(f"""
        xfw {{
            src=extended_group ip6.tcp : block {{ 
            [::] 
            }}
        }}
        """)


async def test_xfw_geoip(
    xfw_geoip: XFW,
    tcp_ip4_server: RegularKernelSocketNetworkStateful,
    tcp_ip4_client: RegularKernelSocketNetworkStateful,
):
    await tcp_ip4_server.start()
    await tcp_ip4_client.start()

    assert (
        await check_connection(tcp_ip4_client, tcp_ip4_server) is True
    ), f"IP {tcp_ip4_server} is not allowed"


# We use these combinations due to the following reasons:
# We have 2 hot swap maps and
# we need 5 emplacements for the map to get 2 equal values in one map
# Also since we have 2 hotswap maps, we need 2 types of crossing/switching values
# to check if there is no side effects of map swap
@pytest.mark.parametrize(
    "rules_list,connection_established",
    [
        pytest.param(["block", "block", "block", "block", "block"], False, id="same5"),
        pytest.param(
            [
                "block",
                "allow",
                "block",
                "allow",
                "block",
                "allow",
                "block",
                "allow",
                "block",
                "allow",
            ],
            True,
            id="cross10",
        ),
        pytest.param(
            [
                "block",
                "block",
                "allow",
                "allow",
                "block",
                "block",
                "allow",
                "allow",
                "block",
                "block",
            ],
            False,
            id="2cross10",
        ),
    ],
)
async def test_xfw_push_config_multiple_same(
    rules_list: List[str],
    connection_established: bool,
    xfw: XFW,
    protocol: str,
    ip_version: str,
    server: RegularKernelSocketNetworkStateful,
    client: RegularKernelSocketNetworkStateful,
    establish_connection,
):
    for rule in rules_list:
        await xfw.rules_push_config(f"""
            xfw {{
                defaults {{ src_ip: allow; }}
                src {ip_version}.{protocol} : {rule} {{
                    {client.ip_testing}
                }}
            }}
            """)

    assert (
        await check_connection(client, server) is connection_established
    ), f"IP {server} is blocked"


async def test_delete_iface_while_xfw_is_running(
    network_class,
    config: ConfigSettings,
    conf_logger: logging.Logger,
    xfw: XFW,
):
    """
    Prevent BPF duplicates
    """
    network = network_class(logger=conf_logger, config=config)

    await xfw.rules_push_config(" xfw { defaults { dst: allow; } } ")
    await network.destroy()

    await xfw.wait_for_daemon_stop()
    xfw.state = State.stopped

    await network.prepare()
    await xfw.start()
    await xfw.rules_push_config(" xfw { defaults { dst: allow; } } ")


async def test_stop_xfw_while_geodb_loading(xfw_geoip: XFW):
    """
    Stop xfw while it is starting with GeoIP enabled.

    This bug is flooding into log file, be careful about it.
    """
    await xfw_geoip.stop()
    xfw_geoip.retry_daemon_start = False
    start_finished = asyncio.Event()

    async def run_apocalypse():
        while not start_finished.is_set():
            await asyncio.sleep(0.1)
            await xfw_geoip.stop()

    async def run_unsuccessful_start():
        try:
            with pytest.raises((RetryException, RetryNotHelpedException)) as exc_info:
                await xfw_geoip.start()

            assert "daemon" in str(
                exc_info.value
            ) or "wait_for_grpc_connection_ready failed" in str(exc_info.value)
        finally:
            start_finished.set()

    await asyncio.gather(run_unsuccessful_start(), run_apocalypse())


@pytest.mark.parametrize(
    "restart_type, rule, function",
    [
        pytest.param("restart", "", "ping_pong", id="allow-restart"),
        pytest.param("stop-start", "", "ping_pong", id="allow-stop-start"),
    ],
)
async def test_restart_under_traffic(
    restart_type: str,
    rule: str,
    function: str,
    xfw: XFW,
    tcp_server: TcpServer,
    tcp_client: TcpClient,
):
    messages_pps = 0
    load_duration = 10
    load_duration_middle = load_duration / 2
    tasks = []
    clients = client_cloner(
        client=tcp_client,
        amount=10,
    )

    tcp_server.echo_mode = True
    tcp_server.log_request = False
    await tcp_server.start()

    for client in clients:
        client.timeout = 5
        client.log_request = False
        await client.start()

    for client in clients:
        tasks.append(
            asyncio.create_task(
                client.generate_traffic(
                    messages_pps=messages_pps,
                    duration=load_duration,
                    function=getattr(client, function),
                )
            )
        )

    await asyncio.sleep(load_duration_middle)
    await xfw.rules_push_config(f"xfw {{ {rule} }}")
    if restart_type == "stop-start":
        await xfw.stop()
        await xfw.start()

    elif restart_type == "restart":
        await xfw.restart_daemon()

    await asyncio.gather(*tasks)
    client_responses = sum(client.resp_n for client in clients)
    server_requests = tcp_server.req_n
    assert (
        client_responses == server_requests
    ), f"Server got {server_requests} requests and clients got {client_responses} responses"


async def test_restart(xfw: XFW):
    await xfw.rules_push_config(" xfw { defaults { dst: allow; } } ")
    await xfw.restart_daemon()
    await xfw.rules_push_config(" xfw { defaults { dst: allow; } } ")
    await xfw.restart_daemon()
    await xfw.rules_push_config(" xfw { defaults { dst: allow; } } ")
