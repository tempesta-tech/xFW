# SPDX-FileCopyrightText: (c) 2026 Tempesta Technologies, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later

import asyncio

from framework.metrics import PrometheusMetricsDiff
from framework.xfw import XFW


def _get_expected_bytes_n(packets_n: int, protocol: str, ip_version: str) -> int:
    match protocol, ip_version:
        case "tcp", "ip4":
            return 71 * packets_n
        case "tcp", "ip6":
            return 91 * packets_n
        case "udp", "ip4":
            return 47 * packets_n
        case "udp", "ip6":
            return 67 * packets_n
        case _:
            raise ValueError(f"Unsupported protocol/ip combo: {protocol}, {ip_version}")


async def test_src_ip(
    metric_analyzer,
    ip_version,
    protocol,
    xfw: XFW,
    server,
    client,
    client_cloner,
):
    packets_n = 10
    bytes_n = _get_expected_bytes_n(packets_n, protocol, ip_version)
    client_2 = client_cloner(cloner=client, amount=1)[0]

    await server.start()
    await client.start()
    await client_2.start()

    await xfw.rules_set(
        f"xfw {{ src {ip_version}.{protocol}: allow {{ {client.ip_testing}, {client_2.ip_testing} }} }}"
    )

    async with metric_analyzer.expected_metrics_diff(
        xfw,
        expected_metrics=PrometheusMetricsDiff(
            xfw_src_ip_allowed_packets=packets_n,
            xfw_src_ip_allowed_bytes=bytes_n,
        ),
    ):
        await asyncio.gather(
            *[client.ping() for _ in range(int(packets_n / 2))]
            + [client_2.ping() for _ in range(int(packets_n / 2))]
        )
        await asyncio.gather(*[server.receive_message() for _ in range(packets_n)])


async def test_src_port(
    metric_analyzer,
    ip_version,
    protocol,
    xfw: XFW,
    server,
    client,
    client_cloner,
):
    packets_n = 10
    bytes_n = _get_expected_bytes_n(packets_n, protocol, ip_version)
    client_2 = client_cloner(cloner=client, amount=1)[0]

    await server.start()
    await client.start()
    await client_2.start()

    await xfw.rules_set(
        f"xfw {{ src {ip_version}.{protocol}: allow {{ :{client.port}, :{client_2.port} }} }}"
    )

    async with metric_analyzer.expected_metrics_diff(
        xfw,
        expected_metrics=PrometheusMetricsDiff(
            xfw_src_port_allowed_packets=packets_n,
            xfw_src_port_allowed_bytes=bytes_n,
        ),
    ):
        await asyncio.gather(
            *[client.ping() for _ in range(int(packets_n / 2))]
            + [client_2.ping() for _ in range(int(packets_n / 2))]
        )
        await asyncio.gather(*[server.receive_message() for _ in range(packets_n)])
