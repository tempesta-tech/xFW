# SPDX-FileCopyrightText: (c) 2026 Tempesta Technologies, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later

import asyncio
import json
import random
from typing import AsyncGenerator

import pytest
from scapy.layers.inet import TCP

from framework.asyn import (
    TcpIpV4RawClient,
    TcpIpV6RawClient,
    TcpRawClient,
    TcpRawServer,
    TcpServer,
)
from framework.fabrics import client_fabric
from framework.metrics import PrometheusMetricsDiff
from framework.xfw import XFW


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


class TcpRawSynDropClient(TcpRawClient):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.stop_receive = False


class TcpRawSynDropIpv4Client(TcpRawSynDropClient, TcpIpV4RawClient):
    def __init__(self, *args, **kwargs):
        TcpRawSynDropClient.__init__(self, *args, **kwargs)
        TcpIpV4RawClient.__init__(self, *args, **kwargs)


class TcpRawSynDropIpv6Client(TcpRawSynDropClient, TcpIpV6RawClient):
    def __init__(self, *args, **kwargs):
        TcpRawSynDropClient.__init__(self, *args, **kwargs)
        TcpIpV6RawClient.__init__(self, *args, **kwargs)


@pytest.fixture
async def tcp_ip4_raw_syn_drop_client(
    xfw_mode, config, logging_level: int
) -> AsyncGenerator[TcpRawSynDropIpv4Client, None]:
    client = client_fabric(
        xfw_mode=xfw_mode,
        logging_level=logging_level,
        config=config,
        local_class=TcpRawSynDropIpv4Client,
    )
    client.auto_ack_seq = False
    client.filter_packets = False

    await client.start()
    yield client
    await client.stop()


@pytest.fixture
async def tcp_ip6_raw_syn_drop_client(
    xfw_mode, config, logging_level
) -> AsyncGenerator[TcpRawSynDropIpv6Client, None]:
    client = client_fabric(
        xfw_mode=xfw_mode,
        logging_level=logging_level,
        config=config,
        local_class=TcpRawSynDropIpv6Client,
    )
    client.auto_ack_seq = False
    client.filter_packets = False

    await client.start()
    yield client
    await client.stop()


@pytest.fixture
def tcp_syn_drop_client(request, ip_version) -> TcpRawSynDropClient:
    return request.getfixturevalue(f"tcp_{ip_version}_raw_syn_drop_client")


async def expect_synack(client: TcpRawClient):
    response = await client.receive_packet()

    assert response is not None, "Expected SYN-ACK, got no reply"
    assert client.has_flag(response, "SA"), f"Unexpected reply flags={response.flags}, expected SA"

    return response


def syn_packet(seq: int) -> TCP:
    return TCP(
        flags="S",
        seq=seq,
        window=64240,
        options=(("MSS", 1460),),
    )


async def complete_initial_syn_validation(
    client: TcpRawClient,
    server: TcpRawServer,
    packet: TCP,
    min_delay: int,
):
    # First SYN starts validation and must be dropped.
    await client.send_packet(packet)
    assert await server.receive_block()

    # Valid retransmission promotes stage 1 -> stage 2 and is passed.
    await asyncio.sleep(min_delay / 1000 + 0.2)

    await client.send_packet(packet)
    received = await server.receive_packet()

    assert received is not None
    assert server.has_flag(received, "S")


@pytest.mark.skip_on_veth
async def test_first_syn_dropped_second_syn_passed(
    xfw: XFW,
    tcp_server: TcpServer,
    tcp_syn_drop_client: TcpRawClient,
    start_tcp_server_and_raw_clients,
):
    min_delay = 1000
    max_delay = 5000
    seq = random.randrange(1, 2**31)

    await xfw.rules_set(
        "xfw { "
        "tcp_syn_drop "
        f"min_delay={min_delay} "
        f"max_delay={max_delay} "
        f"retry_count=3 "
        f"block_timeout=0; "
        "}"
    )

    packet = syn_packet(seq)

    # First SYN starts validation and must always be dropped.
    await tcp_syn_drop_client.send_packet(packet)
    assert packet.seq == seq
    assert await tcp_syn_drop_client.receive_block()

    # Wait until the valid retransmission window.
    await asyncio.sleep(min_delay / 1000 + 0.2)

    # Same 5-tuple + same ISN => lookup in stage 1 map succeeds.
    await tcp_syn_drop_client.send_packet(packet)
    assert packet.seq == seq

    # Valid retransmission is promoted into stage 2 map and passed upstream.
    await expect_synack(tcp_syn_drop_client)


@pytest.mark.skip_on_veth
async def test_syn_drop_deleted_by_patch(
    xfw: XFW,
    tcp_server: TcpServer,
    tcp_syn_drop_client: TcpRawClient,
    start_tcp_server_and_raw_clients,
):
    # await xfw.restart()
    await xfw.rules_set("xfw { tcp_syn_drop retry_count=3; }")

    seq = random.randrange(1, 2**31)
    await tcp_syn_drop_client.send_packet(syn_packet(seq))
    await expect_no_reply(tcp_syn_drop_client)

    await xfw.rules_patch("xfw { tcp_syn_drop/del; }")

    # A new sequence number must pass without retransmission validation.
    await tcp_syn_drop_client.send_packet(syn_packet(seq + 1))
    await expect_synack(tcp_syn_drop_client)


@pytest.mark.skip_on_veth
async def test_second_syn_before_min_delay_blocks_tuple(
    xfw: XFW,
    tcp_server: TcpServer,
    tcp_syn_drop_client: TcpRawClient,
    start_tcp_server_and_raw_clients,
):
    min_delay = 1000
    max_delay = 5000
    seq = random.randrange(1, 2**31)

    await xfw.rules_set(
        "xfw { "
        "tcp_syn_drop "
        f"min_delay={min_delay} "
        f"max_delay={max_delay} "
        f"retry_count=3 "
        f"block_timeout=0; "
        "}"
    )

    packet = syn_packet(seq)

    # First SYN: stage 1 + DROP.
    await tcp_syn_drop_client.send_packet(packet)
    assert await tcp_syn_drop_client.receive_block()

    # Too early.
    await asyncio.sleep(min_delay / 1000 - 0.2)

    await tcp_syn_drop_client.send_packet(packet)
    assert await tcp_syn_drop_client.receive_block()

    #
    # The early retransmission permanently poisons the stage 1 entry.
    # Even after entering the otherwise valid window it must stay blocked.
    #
    await asyncio.sleep(min_delay / 1000 + 0.2)

    await tcp_syn_drop_client.send_packet(packet)
    assert await tcp_syn_drop_client.receive_block()


@pytest.mark.skip_on_veth
async def test_second_syn_after_max_delay_blocks_tuple(
    xfw: XFW,
    tcp_server: TcpServer,
    tcp_syn_drop_client: TcpRawClient,
    start_tcp_server_and_raw_clients,
):
    min_delay = 1000
    max_delay = 2000
    seq = random.randrange(1, 2**31)

    await xfw.rules_set(
        "xfw { "
        "tcp_syn_drop "
        f"min_delay={min_delay} "
        f"max_delay={max_delay} "
        f"retry_count=3 "
        f"block_timeout=0; "
        "}"
    )

    packet = syn_packet(seq)

    await tcp_syn_drop_client.send_packet(packet)
    assert await tcp_syn_drop_client.receive_block()

    # Intentionally miss the initial retransmission window.
    await asyncio.sleep(max_delay / 1000 + 0.2)

    await tcp_syn_drop_client.send_packet(packet)
    assert await tcp_syn_drop_client.receive_block()

    #
    # The later retransmission permanently poisons the stage 1 entry.
    # Even after entering the otherwise valid window it must stay blocked.
    #
    await asyncio.sleep(min_delay / 1000 + 0.2)

    await tcp_syn_drop_client.send_packet(packet)
    assert await tcp_syn_drop_client.receive_block()


@pytest.mark.skip_on_veth
async def test_retry_count_blocks_following_syns(
    xfw: XFW,
    tcp_syn_drop_client: TcpRawClient,
    tcp_raw_server: TcpRawServer,
    start_tcp_raw_server_and_raw_clients,
):
    min_delay = 1000
    max_delay = 3000
    retry_count = 3
    seq = random.randrange(1, 2**31)

    await xfw.rules_set(
        "xfw { "
        "tcp_syn_drop "
        f"min_delay={min_delay} "
        f"max_delay={max_delay} "
        f"retry_count={retry_count} "
        f"block_timeout=0; "
        "}"
    )

    packet = syn_packet(seq)
    await complete_initial_syn_validation(tcp_syn_drop_client, tcp_raw_server, packet, min_delay)

    #
    # retry_count valid retransmissions must be passed upstream.
    #
    # The first retransmission promotes the tuple from the stage 1
    # map to the stage 2 map. The SYN which reaches retry_count is
    # still passed upstream.
    #
    for _ in range(retry_count - 1):
        await asyncio.sleep(min_delay / 1000 + 0.2)

        await tcp_syn_drop_client.send_packet(packet)

        received = await tcp_raw_server.receive_packet()
        assert received is not None
        assert tcp_raw_server.has_flag(received, "S")
        assert not tcp_raw_server.has_flag(received, "A")

    #
    # retry_count has been reached. The next timing-valid SYN is dropped
    # and blocks the tuple indefinitely because block_timeout=0.
    #
    await asyncio.sleep(min_delay / 1000 + 0.2)

    await tcp_syn_drop_client.send_packet(packet)
    assert await tcp_raw_server.receive_block()


@pytest.mark.skip_on_veth
async def test_finite_block_timeout_restarts_validation(
    xfw: XFW,
    tcp_syn_drop_client: TcpRawClient,
    tcp_raw_server: TcpRawServer,
    start_tcp_raw_server_and_raw_clients,
):
    min_delay = 1000
    max_delay = 5000
    retry_count = 2
    block_timeout = 1000
    seq = random.randrange(1, 2**31)

    await xfw.rules_set(
        "xfw { "
        "tcp_syn_drop "
        f"min_delay={min_delay} "
        f"max_delay={max_delay} "
        f"retry_count={retry_count} "
        f"block_timeout={block_timeout}; "
        "}"
    )

    packet = syn_packet(seq)
    await complete_initial_syn_validation(tcp_syn_drop_client, tcp_raw_server, packet, min_delay)

    #
    # The second valid retransmission reaches retry_count=2 and still
    # passes upstream. The block starts on the next timing-valid SYN.
    #
    await asyncio.sleep(min_delay / 1000 + 0.2)
    await tcp_syn_drop_client.send_packet(packet)
    received = await tcp_raw_server.receive_packet()
    assert received is not None
    assert tcp_raw_server.has_flag(received, "S")

    #
    # The next timing-valid SYN starts the finite block. Sending it before
    # min_delay would permanently block the tuple instead.
    #
    await asyncio.sleep(min_delay / 1000 + 0.2)

    await tcp_syn_drop_client.send_packet(packet)
    assert await tcp_raw_server.receive_block()

    # While the finite block is active, following SYNs must be dropped.
    await asyncio.sleep(0.2)
    await tcp_syn_drop_client.send_packet(packet)
    assert await tcp_raw_server.receive_packet() is None

    #
    # Wait until the finite block expires.
    #
    await asyncio.sleep(block_timeout / 1000 + 0.2)

    #
    # Expiration does not immediately make the tuple trusted again.
    # This SYN starts a new validation cycle:
    #
    #     stage 2 entry -> delete
    #     stage 1 entry -> create
    #     current SYN -> DROP
    #
    await tcp_syn_drop_client.send_packet(packet)
    assert await tcp_raw_server.receive_block()

    #
    # A retransmission inside the new validation window must now be
    # promoted from stage 1 to stage 2 and passed upstream.
    #
    await asyncio.sleep(min_delay / 1000 + 0.2)

    await tcp_syn_drop_client.send_packet(packet)

    received = await tcp_raw_server.receive_packet()
    assert received is not None
    assert tcp_raw_server.has_flag(received, "S")


@pytest.mark.skip_on_veth
async def test_retry_max_delay_exponential_backoff(
    xfw: XFW,
    tcp_syn_drop_client: TcpRawClient,
    tcp_raw_server: TcpRawServer,
    start_tcp_raw_server_and_raw_clients,
):
    min_delay = 500
    max_delay = 1000
    seq = random.randrange(1, 2**31)

    await xfw.rules_set(
        "xfw { "
        "tcp_syn_drop "
        f"min_delay={min_delay} "
        f"max_delay={max_delay} "
        f"retry_count=5 "
        f"block_timeout=0; "
        "}"
    )

    packet = syn_packet(seq)
    await complete_initial_syn_validation(tcp_syn_drop_client, tcp_raw_server, packet, min_delay)

    #
    # The first SYN already promoted the tuple and doubles max_delay.
    #
    await asyncio.sleep(min_delay / 1000 + 0.1)

    #
    # max_delay is now 2000 ms.
    #
    # Wait 1200 ms: this would be outside the original 1000 ms window,
    # but must still be accepted after exponential backoff.
    #
    await asyncio.sleep(1.2)

    await tcp_syn_drop_client.send_packet(packet)

    received = await tcp_raw_server.receive_packet()
    assert received is not None
    assert tcp_raw_server.has_flag(received, "S")


@pytest.mark.skip_on_veth
async def test_dst_rules_with_tcp_syn_drop_enabled(
    xfw: XFW,
    ip_version: str,
    tcp_syn_drop_client: TcpRawClient,
    tcp_raw_server: TcpRawServer,
    start_tcp_raw_server_and_raw_clients,
):
    min_delay = 1000
    max_delay = 5000
    seq = random.randrange(1, 2**31)

    await xfw.rules_set(f"""
        xfw {{
            defaults {{ dst: allow; }}

            tcp_syn_drop
                min_delay={min_delay}
                max_delay={max_delay}
                retry_count=3
                block_timeout=0;

            dst {ip_version}.tcp : block {{
                {tcp_raw_server.ip_testing}:{tcp_raw_server.port}
            }}
        }}
        """)

    packet = syn_packet(seq)

    # First SYN is dropped by tcp_syn_drop.
    await tcp_syn_drop_client.send_packet(packet)
    assert await tcp_raw_server.receive_block()

    await asyncio.sleep(min_delay / 1000 + 0.2)

    # tcp_syn_drop accepts the retransmission, but dst_filter must
    # still process and block it.
    await tcp_syn_drop_client.send_packet(packet)
    assert await tcp_raw_server.receive_block()


@pytest.mark.skip_on_veth
async def test_syn_ratelimit_with_syn_drop(
    xfw: XFW,
    tcp_syn_drop_client: TcpRawClient,
    tcp_raw_server: TcpRawServer,
    start_tcp_raw_server_and_raw_clients,
):
    min_delay = 1
    max_delay = 5000
    seq = random.randrange(1, 2**31)

    await xfw.rules_set(f"""
        xfw {{
            ratelimit=test pps=2 bps=1000000;

            tcp_flags syn : ratelimit=test;

            tcp_syn_drop
                min_delay={min_delay}
                max_delay={max_delay}
                retry_count=3
                block_timeout=0;
        }}
    """)

    packet = TCP(
        flags="S",
        seq=seq,
        window=64240,
        options=(("MSS", 1460),),
    )

    #
    # First SYN passes the SYN rate limiter and reaches tcp_syn_drop.
    # tcp_syn_drop records the tuple and deliberately drops this SYN.
    #
    await tcp_syn_drop_client.send_packet(packet)
    assert await tcp_raw_server.receive_block()

    #
    # Consume the second SYN allowed by the rate limit using a different
    # TCP tuple. This must not affect the stage 1 tcp_syn_drop entry above.
    # (ratelimit is not accuracy, so we need to send several SYNs to be sure
    #  that it will be exhausted).
    #
    fillers = [
        TCP(
            flags="S",
            seq=seq + i + 1,
            window=64240,
            options=(("MSS", 1460),),
        )
        for i in range(3)
    ]

    await asyncio.gather(*(tcp_syn_drop_client.send_packet(packet) for packet in fillers))

    #
    # Send the retransmission while the SYN rate limit is still exhausted.
    # It must be dropped by tcp_flags before tcp_syn_drop sees it.
    #
    await asyncio.sleep(0.005)

    await tcp_syn_drop_client.send_packet(packet)
    assert await tcp_raw_server.receive_block()

    #
    # Wait for the rate limiter to fully recover. The rate limiter uses two
    # adjacent fixed windows to approximate a sliding window, so an event may
    # contribute through the previous-window bucket for up to two window
    # lengths, depending on where it occurred relative to a window boundary.
    # Waiting for two full windows guarantees that the first SYN no longer
    # contributes to the rate estimate.
    #
    # Since the previous SYN was dropped before tcp_syn_drop, the original
    # stage 1 entry must still be present. The same retransmission can now pass
    # the rate limiter and be validated by tcp_syn_drop.
    #
    await asyncio.sleep(2.0)

    await tcp_syn_drop_client.send_packet(packet)
    received = await tcp_raw_server.receive_packet()
    assert received is not None
    assert tcp_raw_server.has_flag(received, "S")


@pytest.mark.skip_on_veth
async def test_syn_drop_flood_concurrency(
    xfw: XFW,
    tcp_syn_drop_client: TcpRawClient,
    tcp_raw_server: TcpRawServer,
    start_tcp_raw_server_and_raw_clients,
    metric_analyzer,
):
    """
    The test checks the stability of the tcp_syn_drop under SYN flood
    """
    await xfw.rules_set(f"""
        xfw {{
            tcp_syn_drop
                min_delay=1
                max_delay=1000
                retry_count=3
                block_timeout=10;
        }}
    """)

    async def send_single_spoofed_syn():
        await tcp_syn_drop_client.send_packet(syn_packet(random.getrandbits(32)))

    legit_packets_n = 3
    flood_pps = 100
    flood_duration = 5
    legit_packets = [syn_packet(seq=random.getrandbits(32)) for _ in range(legit_packets_n)]
    legit_tasks = []

    async with metric_analyzer.expected_metrics_diff(
        xfw=xfw,
        expected_metrics=PrometheusMetricsDiff(
            xfw_syn_packets=[flood_pps, flood_duration * flood_pps],
            xfw_passed_downstream_ingress_packets=[legit_packets_n, legit_packets_n * 2],
        ),
    ):
        flood_task = tcp_syn_drop_client.generate_traffic(
            messages_pps=flood_pps,
            duration=flood_duration,
            function=send_single_spoofed_syn,
        )

        await asyncio.sleep(0.1)

        for packet in legit_packets:
            legit_tasks.append(
                complete_initial_syn_validation(
                    tcp_syn_drop_client, tcp_raw_server, packet, min_delay=100
                )
            )

        result = await asyncio.gather(*legit_tasks, return_exceptions=True)
        await flood_task

    assert all(res is None for res in result), f"Errors for legitim clients: {result}."
