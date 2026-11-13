# SPDX-FileCopyrightText: (c) 2026 Tempesta Technologies, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later
import asyncio
import random
from typing import AsyncGenerator

import pytest
from scapy.layers.inet import TCP

from framework.metrics import PrometheusMetricsDiff


@pytest.fixture(scope="module", autouse=True)
async def xfw_scrubbing(xfw_global, xfw_use_rule_reset) -> AsyncGenerator[None, None]:
    if xfw_global.deployment_mode == "scrubbing":
        yield
        return

    original_mode = xfw_global.deployment_mode
    xfw_global.deployment_mode = "scrubbing"
    await xfw_global.restart()

    yield

    xfw_global.deployment_mode = original_mode
    await xfw_global.stop_or_reset(xfw_use_rule_reset)


def get_expected_tcp_metrics(packets_n: int, ip_version: str) -> PrometheusMetricsDiff:
    # IPv4: 14 (eth) + 20 (IPv4) + 20 (TCP)
    # IPv6: 14 (eth) + 40 (IPv6) + 20 (TCP)
    packet_size = 54 if ip_version == "ip4" else 74
    return PrometheusMetricsDiff(
        xfw_syn_packets=packets_n,
        xfw_syn_bytes=packets_n * packet_size,
        xfw_ack_packets=packets_n,
        xfw_ack_bytes=packets_n * packet_size,
        xfw_synack_packets=packets_n,
        xfw_synack_bytes=packets_n * packet_size,
        xfw_fin_packets=packets_n,
        xfw_fin_bytes=packets_n * packet_size,
        xfw_rst_packets=packets_n,
        xfw_rst_bytes=packets_n * packet_size,
    )


async def test_tcp_metrics(
    metric_analyzer,
    ip_version,
    xfw,
    tcp_raw_client,
    tcp_raw_server,
    client_cloner,
    flush_arp_cache,
):
    packets_n = 10

    await tcp_raw_server.start()
    await tcp_raw_client.start()

    await xfw.rules_set("xfw {}")

    async with metric_analyzer.expected_metrics_diff(
        xfw, get_expected_tcp_metrics(packets_n, ip_version)
    ):
        await asyncio.gather(
            *[tcp_raw_client.send_packet(TCP(flags="S")) for _ in range(packets_n)]
        )
        await asyncio.gather(
            *[tcp_raw_client.send_packet(TCP(flags="A")) for _ in range(packets_n)]
        )
        await asyncio.gather(
            *[tcp_raw_client.send_packet(TCP(flags="SA")) for _ in range(packets_n)]
        )
        await asyncio.gather(
            *[tcp_raw_client.send_packet(TCP(flags="F")) for _ in range(packets_n)]
        )
        await asyncio.gather(
            *[tcp_raw_client.send_packet(TCP(flags="R")) for _ in range(packets_n)]
        )
        await asyncio.gather(*[tcp_raw_server.receive_packet() for _ in range(packets_n * 5)])


@pytest.mark.skip_on_veth
async def test_tcp_syn_drop_blocked(
    xfw_scrubbing,
    metric_analyzer,
    ip_version,
    xfw,
    tcp_raw_client,
    tcp_raw_server,
    client_cloner,
):
    tcp_raw_client.auto_ack_seq = False
    tcp_raw_client.filter_packets = False

    await tcp_raw_server.start()
    await tcp_raw_client.start()

    min_delay = 1000
    max_delay = 2000
    seq = random.getrandbits(32)

    await xfw.rules_set(
        "xfw { "
        "tcp_syn_drop "
        f"min_delay={min_delay} "
        f"max_delay={max_delay} "
        f"retry_count=3 "
        f"block_timeout=0; "
        "}"
    )

    async with metric_analyzer.expected_metrics_diff(
        xfw,
        expected_metrics=PrometheusMetricsDiff(
            xfw_syn_drop_passed_packets=0,
            xfw_syn_drop_passed_bytes=0,
            xfw_syn_drop_blocked_packets=1,
            xfw_syn_drop_blocked_bytes=58 if tcp_raw_client.is_ip4 else 78,
        ),
    ):
        packet = TCP(
            flags="S",
            seq=seq,
            window=64240,
            options=(("MSS", 1460),),
        )
        await tcp_raw_client.send_packet(packet)
        assert await tcp_raw_server.receive_block()

        # Intentionally miss the initial retransmission window.
        await asyncio.sleep(max_delay / 1000 + 0.2)

        await tcp_raw_client.send_packet(packet)
        assert await tcp_raw_server.receive_block()


@pytest.mark.skip_on_veth
async def test_tcp_syn_drop_passed(
    xfw_scrubbing,
    metric_analyzer,
    ip_version,
    xfw,
    tcp_raw_client,
    tcp_raw_server,
    client_cloner,
):
    tcp_raw_client.auto_ack_seq = False
    tcp_raw_client.filter_packets = False

    await tcp_raw_server.start()
    await tcp_raw_client.start()

    min_delay = 1000
    max_delay = 5000
    seq = random.getrandbits(32)

    await xfw.rules_set(
        "xfw { "
        "tcp_syn_drop "
        f"min_delay={min_delay} "
        f"max_delay={max_delay} "
        f"retry_count=3 "
        f"block_timeout=0; "
        "}"
    )

    async with metric_analyzer.expected_metrics_diff(
        xfw,
        expected_metrics=PrometheusMetricsDiff(
            xfw_syn_drop_passed_packets=1,
            xfw_syn_drop_passed_bytes=58 if tcp_raw_client.is_ip4 else 78,
            xfw_syn_drop_blocked_packets=0,
            xfw_syn_drop_blocked_bytes=0,
        ),
    ):
        packet = TCP(
            flags="S",
            seq=seq,
            window=64240,
            options=(("MSS", 1460),),
        )
        # First SYN starts validation and must always be dropped.
        await tcp_raw_client.send_packet(packet)
        assert await tcp_raw_server.receive_block()

        # Wait until the valid retransmission window.
        await asyncio.sleep(min_delay / 1000 + 0.2)

        # Same 5-tuple + same ISN => lookup in stage 1 map succeeds.
        await tcp_raw_client.send_packet(packet)

        # Valid retransmission is promoted into stage 2 map and passed upstream.
        request = await tcp_raw_server.receive_packet()
        assert request is not None, "Expected SYN, got no reply"
        assert tcp_raw_server.has_flag(
            request, "S"
        ), f"Unexpected reply flags={request.flags}, expected SA"

        await tcp_raw_server.send_packet(TCP(flags="SA"))

        response = await tcp_raw_client.receive_packet()

        assert response is not None, "Expected SYN-ACK from server side, got no reply"
        assert tcp_raw_client.has_flag(
            response, "SA"
        ), f"Unexpected reply flags={response.flags}, expected SA"
