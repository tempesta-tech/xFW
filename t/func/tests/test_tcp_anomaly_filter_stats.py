# SPDX-FileCopyrightText: (c) 2026 Tempesta Technologies, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later

import asyncio

import pytest
from scapy.layers.inet import TCP

from framework.asyn import (
    TcpIpV4RawClient,
    TcpIpV6RawClient,
    TcpRawClient,
    TcpV4Server,
    TcpV6Server,
)
from framework.utils import compare_metrics_diff, get_tcp_packet
from framework.xfw import XFW


@pytest.fixture
def stats_counters() -> list[str]:
    return [
        "xfw_tcp_anom_bad_flags_packets",
        "xfw_tcp_anom_bad_flags_bytes",
        "xfw_tcp_anom_syn_bad_seq_packets",
        "xfw_tcp_anom_syn_bad_seq_bytes",
        "xfw_tcp_anom_syn_no_options_packets",
        "xfw_tcp_anom_syn_no_options_bytes",
        "xfw_tcp_anom_syn_has_data_packets",
        "xfw_tcp_anom_syn_has_data_bytes",
        "xfw_tcp_anom_zero_port_packets",
        "xfw_tcp_anom_zero_port_bytes",
    ]


@pytest.mark.parametrize(
    "packet, protocol, counters",
    [
        pytest.param(
            get_tcp_packet(flag="SF"),
            "ip4",
            dict(xfw_tcp_anom_bad_flags_packets=10, xfw_tcp_anom_bad_flags_bytes=620),
            id="ip4-bad-flag-u",
        ),
        pytest.param(
            get_tcp_packet(flag="SF"),
            "ip6",
            dict(xfw_tcp_anom_bad_flags_packets=10, xfw_tcp_anom_bad_flags_bytes=820),
            id="ip6-bad-flag-u",
        ),
        pytest.param(
            get_tcp_packet(flag="S", seq=0),
            "ip4",
            dict(xfw_tcp_anom_syn_bad_seq_packets=10, xfw_tcp_anom_syn_bad_seq_bytes=620),
            id="ip4-bad-seq-0",
        ),
        pytest.param(
            get_tcp_packet(flag="S", seq=0),
            "ip6",
            dict(xfw_tcp_anom_syn_bad_seq_packets=10, xfw_tcp_anom_syn_bad_seq_bytes=820),
            id="ip6-bad-seq-0",
        ),
        pytest.param(
            get_tcp_packet(flag="S", options=[]),
            "ip4",
            dict(xfw_tcp_anom_syn_no_options_packets=10, xfw_tcp_anom_syn_no_options_bytes=540),
            id="ip4-syn-no-options",
        ),
        pytest.param(
            get_tcp_packet(flag="S", options=[]),
            "ip6",
            dict(xfw_tcp_anom_syn_no_options_packets=10, xfw_tcp_anom_syn_no_options_bytes=740),
            id="ip6-syn-no-options",
        ),
        pytest.param(
            get_tcp_packet(flag="S", payload=b"1"),
            "ip4",
            dict(xfw_tcp_anom_syn_has_data_packets=10, xfw_tcp_anom_syn_has_data_bytes=630),
            id="ip4-syn-payload",
        ),
        pytest.param(
            get_tcp_packet(flag="S", payload=b"1"),
            "ip6",
            dict(xfw_tcp_anom_syn_has_data_packets=10, xfw_tcp_anom_syn_has_data_bytes=830),
            id="ip6-syn-payload",
        ),
    ],
)
async def test_common(
    packet: TCP,
    protocol: str,
    counters: dict[str, int],
    stats_counters: list[str],
    xfw: XFW,
    tcp_ip4_server: TcpV4Server,
    tcp_ip6_server: TcpV6Server,
    tcp_ip4_raw_client: TcpIpV4RawClient,
    tcp_ip6_raw_client: TcpIpV6RawClient,
    client_cloner,
):
    server = locals().get(f"tcp_{protocol}_server")
    client = locals().get(f"tcp_{protocol}_raw_client")
    client.auto_ack_seq = False
    client_2 = client_cloner(cloner=client, amount=1)[0]
    client_2.auto_ack_seq = False

    await server.start()
    await client.start()
    await client_2.start()

    await xfw.rules_set(
        "xfw { tcp_anomaly_filter syn_without_opt" " syn_with_payload syn_with_seqno=0 bad_flags; }"
    )

    async with xfw.metrics_diff(stats_counters) as diff:
        await asyncio.gather(
            *[client.send(packet) for i in range(5)] + [client_2.send(packet) for i in range(5)]
        )

    invalid_metrics = compare_metrics_diff(
        compare_metrics=stats_counters, all_metrics=diff, diff_metrics=counters
    )

    await client.stop()
    await client_2.stop()
    await server.stop()

    assert invalid_metrics == [], f"Some metrics are different: {invalid_metrics}"


@pytest.mark.parametrize(
    "protocol, counters",
    [
        pytest.param(
            "ip4",
            dict(xfw_tcp_anom_zero_port_packets=10, xfw_tcp_anom_zero_port_bytes=740),
            id="ip4-zero-port",
        ),
        pytest.param(
            "ip6",
            dict(xfw_tcp_anom_zero_port_packets=10, xfw_tcp_anom_zero_port_bytes=940),
            id="ip6-zero-port",
        ),
    ],
)
async def test_zero_port(
    protocol: str,
    counters: dict[str, int],
    stats_counters: list[str],
    xfw: XFW,
    tcp_ip4_server: TcpV4Server,
    tcp_ip6_server: TcpV6Server,
    tcp_ip4_raw_client: TcpIpV4RawClient,
    tcp_ip6_raw_client: TcpIpV6RawClient,
    client_cloner,
):
    server = locals().get(f"tcp_{protocol}_server")
    client: TcpRawClient = locals().get(f"tcp_{protocol}_raw_client")
    client.auto_ack_seq = False
    client_2: TcpRawClient = client_cloner(cloner=client, amount=1)[0]
    client_2.auto_ack_seq = False

    await server.start()
    await client.start()
    await client_2.start()

    client.remote_port = 0
    client_2.remote_port = 0

    await xfw.rules_set(
        "xfw { tcp_anomaly_filter syn_without_opt" " syn_with_payload syn_with_seqno=0 bad_flags; }"
    )

    async with xfw.metrics_diff(stats_counters, wait_softirq=True) as diff:
        await asyncio.gather(
            *[client.send(client.valid_syn_packet) for i in range(5)]
            + [client_2.send(client_2.valid_syn_packet) for i in range(5)]
        )

    invalid_metrics = compare_metrics_diff(
        compare_metrics=stats_counters, all_metrics=diff, diff_metrics=counters
    )

    await client.stop()
    await client_2.stop()
    await server.stop()

    assert invalid_metrics == [], f"Some metrics are different: {invalid_metrics}"
