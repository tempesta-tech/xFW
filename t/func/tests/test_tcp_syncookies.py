# SPDX-FileCopyrightText: (c) 2026 Tempesta Technologies, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later

import asyncio
import logging
import random
import time
from typing import AsyncGenerator, Union

import pytest
from scapy.layers.inet import TCP

from config import ConfigSettings
from framework.asyn import (
    TcpIpV4RawClient,
    TcpIpV6RawClient,
    TcpRawClient,
    TcpServer,
)
from framework.fabrics import client_fabric
from framework.utils import compare_metrics_diff, get_tcp_packet, run_in_background
from framework.xfw import XFW

SynStats = tuple[int, int, int]
StatExpectation = Union[int, tuple[int, int]]
StatsExpectation = tuple[StatExpectation, StatExpectation, StatExpectation]
bad_packet = TCP(flags="S")
ok_packet = TCP(
    flags="S",
    window=6420,
    seq=32513451,
    options=[
        ("MSS", 1460),
    ],
)


def cmp_stats(value: int, expected: StatExpectation) -> bool:
    if isinstance(expected, int):
        return value == expected

    return expected[0] <= value <= expected[1]


def check_kern_rcv(
    logger: logging.Logger,
    stats_before: SynStats,
    stats_after: SynStats,
) -> None:
    """
    Check the only kernel syncookie counter relevant to xFW cookies.
    """
    syn_cookies_recv = stats_after[1] - stats_before[1]
    logger.info(f"recv={syn_cookies_recv}")
    assert syn_cookies_recv >= 1, "SynCookieRcv did not increase"


stats_counters = [
    "xfw_syncookie_generated_packets",
    "xfw_syncookie_failed_packets",
    "xfw_syncookie_received_packets",
]


def check_xfw_stats(
    diff: dict[str, int],
    expectation: tuple[int, int, int],
) -> None:
    invalid_metrics = compare_metrics_diff(
        compare_metrics=stats_counters,
        all_metrics=diff,
        diff_metrics={
            "xfw_syncookie_generated_packets": expectation[0],
            "xfw_syncookie_received_packets": expectation[1],
            "xfw_syncookie_failed_packets": expectation[2],
        },
    )
    assert invalid_metrics == [], f"Some metrics are different: {invalid_metrics}"


class TcpRawSynCookieClient(TcpRawClient):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.stop_receive = False

    async def _read_replies(self):
        total_replies = 0

        while not self.stop_receive:
            response = await super().receive_packet()

            if not response:
                continue

            assert self.has_flag(
                response, "SA"
            ), f"Unexpected reply packet with flags = {response.flags}. Expected SA"

            total_replies += 1

        return total_replies

    async def _send_requests(self, packet: TCP, amount: int, duration: float):
        counter = 0
        sleep_time = duration / amount

        self.logger.debug(
            f"sleep_time={sleep_time}, total_requests={amount}, duration={duration} sec"
        )

        while counter < amount:
            await self.send_packet(packet)
            await asyncio.sleep(sleep_time)
            counter += 1

        self.stop_receive = True
        return counter

    async def flood(self, packet: TCP, amount: int, duration: float) -> tuple[int, int]:
        """
        Sends from client special packet 100 times each second during the
        next 5 seconds
        """
        sent, replies = await asyncio.gather(
            self._send_requests(packet=packet, amount=amount, duration=duration),
            self._read_replies(),
        )
        return sent, replies

    async def flood_handshake(self, amount: int, duration: int) -> tuple[int, int]:
        """
        Send SYNs from unique source ports with deliberately invalid ACKs.
        The function makes sure that all handshakes will not pass SYN cookies
        challenge. This guarantee is important to have stable test results.
        """

        sent = 0
        acknowledged = 0
        sleep_time = duration / amount

        while sent < amount:
            await asyncio.sleep(sleep_time)
            sent += 1
            # A distinct 4-tuple makes every iteration an independent cookie
            # attempt against the listening socket.
            self.port = 1024 if self.port == 65535 else self.port + 1
            packet = TCP(
                flags="S",
                seq=random.randrange(1, 9999999),
                window=64240,
                options=(("MSS", 1460),),
            )
            await self.send_packet(packet)

            response = await super().receive_packet()

            # Probably, the server can answer with rst or something else,
            # we skip such situations and register them as complete.
            if not response:
                continue

            if not self.has_flag(response, "SA"):
                continue

            # Deliberately corrupt the cookie carried in the SYN-ACK sequence.
            # Keep the wrong value explicit: cloned flood clients disable
            # automatic seq/ack substitution.
            await self.send_packet(
                TCP(
                    flags="A",
                    seq=response.ack,
                    ack=response.seq ^ 0x80000000,
                )
            )
            acknowledged += 1

        return sent, acknowledged


class TcpRawSynCookieIpv4Client(TcpRawSynCookieClient, TcpIpV4RawClient):
    def __init__(self, *args, **kwargs):
        TcpRawSynCookieClient.__init__(self, *args, **kwargs)
        TcpIpV4RawClient.__init__(self, *args, **kwargs)


class TcpRawSynCookieIpv6Client(TcpRawSynCookieClient, TcpIpV6RawClient):
    def __init__(self, *args, **kwargs):
        TcpRawSynCookieClient.__init__(self, *args, **kwargs)
        TcpIpV6RawClient.__init__(self, *args, **kwargs)


@pytest.fixture
async def tcp_ip4_raw_syncookie_client(
    config: ConfigSettings, logging_level: int
) -> AsyncGenerator[TcpServer, None]:
    client = client_fabric(
        logging_level=logging_level,
        config=config,
        local_class=TcpRawSynCookieIpv4Client,
    )
    yield client
    await client.stop()


@pytest.fixture
async def tcp_ip6_raw_syncookie_client(
    config: ConfigSettings, logging_level
) -> AsyncGenerator[TcpServer, None]:
    client = client_fabric(
        logging_level=logging_level,
        config=config,
        local_class=TcpRawSynCookieIpv6Client,
    )
    yield client
    await client.stop()


@pytest.fixture
def tcp_syncookie_client(request, ip_version):
    return request.getfixturevalue(f"tcp_{ip_version}_raw_syncookie_client")


@pytest.fixture
async def xfw_with_forced_syncookie(xfw: XFW) -> AsyncGenerator[XFW, None]:
    """
    While `sysctl-tcp-syncookies: 2` is not practical, it's required for the
    test to get a deterministic kernel behavior always requireing a syncookie
    generation.
    """
    original_mode = await xfw.syncookies_value_get()
    await xfw.set_config(f"""{{
        "devices": "{xfw.network_interface}",
        "devices-mode": "skb",
        "verbose": true,
        "mgr-args": "--listen {xfw.ipv4} --port {xfw.port}",
        "sysctl-tcp-max-syn-backlog": 1,
        "sysctl-tcp-syncookies": 2
        }}""")
    await xfw.restart()

    yield xfw

    await xfw.stop()
    await xfw.syncookies_value_set(original_mode)


@pytest.fixture
async def group_of_clients(
    tcp_syncookie_client: TcpRawSynCookieClient, client_cloner
) -> AsyncGenerator[list[TcpRawSynCookieClient], None]:
    clients: list[TcpRawClient] = client_cloner(
        cloner=tcp_syncookie_client,
        amount=2,
    )

    for client in clients:
        client.auto_ack_seq = False
        client.filter_packets = False
        client.log_msg = False
        await client.start()

    yield clients

    for client in clients:
        await client.stop()


@pytest.mark.parametrize(
    "tcp_syncookies_parameter",
    [
        pytest.param("flood_timer=2 passive_timer=3", id="custom"),
        pytest.param("flood_timer=2", id="flood"),
        pytest.param("passive_timer=2", id="passive"),
        pytest.param("flood_timer=1 passive_timer=0", id="always-passive"),
    ],
)
async def test_normal_connection(
    tcp_syncookies_parameter: str,
    xfw_with_forced_syncookie: XFW,
    tcp_server: TcpServer,
    tcp_raw_client: TcpRawClient,
    start_tcp_server_and_raw_clients,
):
    await xfw_with_forced_syncookie.rules_set(
        f"xfw {{ tcp_syncookies {tcp_syncookies_parameter}; }}"
    )

    # It's required to have a unique client because syncookie is issued at 4-tuple.
    tcp_raw_client.port = random.randrange(1, 65000)

    # STAGE 1: Connection
    async with xfw_with_forced_syncookie.metrics_diff(stats_counters, wait_softirq=True) as diff:
        stats_before = await xfw_with_forced_syncookie.syncookies_read_kern_stats()
        assert await tcp_raw_client.handshake() is True
        stats_after = await xfw_with_forced_syncookie.syncookies_read_kern_stats()

    # Full TCP handshake: xFW handles client SYN and sends SYN+ACK,
    # the received client ACK goes to the TCP/IP stack, so:
    # SyncookieSent are the same, SyncookieRecv is +1 and
    # xfw_syncookie_generated_packets is +1.
    assert stats_after[0] == stats_before[0]
    assert stats_after[1] == stats_before[1] + 1
    assert stats_after[2] == stats_before[2]
    invalid_metrics = compare_metrics_diff(
        compare_metrics=stats_counters,
        all_metrics=diff,
        diff_metrics={
            "xfw_syncookie_generated_packets": 1,
            "xfw_syncookie_failed_packets": 0,
            "xfw_syncookie_received_packets": 1,
        },
    )
    assert invalid_metrics == [], f"Some metrics are different: {invalid_metrics}"

    # STAGE 2: Send data
    async with xfw_with_forced_syncookie.metrics_diff(stats_counters, wait_softirq=True) as diff:
        stats_before = await xfw_with_forced_syncookie.syncookies_read_kern_stats()
        await tcp_raw_client.send_packet(TCP(flags="PA") / b"hello")

        answer = await tcp_raw_client.receive_packet()
        assert answer is not None
        assert tcp_raw_client.has_flag(answer, "A")

        stats_after = await xfw_with_forced_syncookie.syncookies_read_kern_stats()

    # nothing changes
    assert stats_after[0] == stats_before[0]
    assert stats_after[1] == stats_before[1]
    assert stats_after[2] == stats_before[2]
    invalid_metrics = compare_metrics_diff(
        compare_metrics=stats_counters,
        all_metrics=diff,
        diff_metrics={
            "xfw_syncookie_generated_packets": 0,
            "xfw_syncookie_failed_packets": 0,
            "xfw_syncookie_received_packets": 0,
        },
    )
    assert invalid_metrics == [], f"Some metrics are different: {invalid_metrics}"

    # STAGE 3: Disconnecting
    async with xfw_with_forced_syncookie.metrics_diff(stats_counters, wait_softirq=True) as diff:
        stats_before = await xfw_with_forced_syncookie.syncookies_read_kern_stats()
        assert await tcp_raw_client.close_connection() is True
        stats_after = await xfw_with_forced_syncookie.syncookies_read_kern_stats()

    # nothing changes
    assert stats_after[0] == stats_before[0]
    assert stats_after[1] == stats_before[1]
    assert stats_after[2] == stats_before[2]
    invalid_metrics = compare_metrics_diff(
        compare_metrics=stats_counters,
        all_metrics=diff,
        diff_metrics={
            "xfw_syncookie_generated_packets": 0,
            "xfw_syncookie_failed_packets": 0,
            "xfw_syncookie_received_packets": 0,
        },
    )
    assert invalid_metrics == [], f"Some metrics are different: {invalid_metrics}"


@pytest.mark.parametrize(
    "tcp_options,expected_synack_option_names,expected_timestamp_bits",
    [
        pytest.param(
            [
                ("MSS", 1460),
                ("SAckOK", b""),
                ("Timestamp", (4294693388, 0)),
                ("NOP", None),
                ("WScale", 6),
            ],
            ("MSS", "NOP", "WScale", "SAckOK", "Timestamp"),
            0x16,
            id="full-house",
        ),
        pytest.param(
            [("MSS", 1460), ("SAckOK", b""), ("Timestamp", (4294693388, 0)), ("NOP", None)],
            ("MSS", "NOP", "WScale", "SAckOK", "Timestamp"),
            0x1F,
            id="mss+sackok+ts+nop",
        ),
        pytest.param(
            [("MSS", 1460), ("SAckOK", b""), ("Timestamp", (4294693388, 0))],
            ("MSS", "NOP", "WScale", "SAckOK", "NOP", "EOL"),
            None,
            id="mss+sackok+ts",
        ),
        pytest.param(
            [("MSS", 1460), ("SAckOK", b"")],
            ("MSS", "NOP", "WScale"),
            None,
            id="mss+sackok",
        ),
        pytest.param(
            [("MSS", 1460)],
            ("MSS",),
            None,
            id="mss",
        ),
        pytest.param(
            [],
            (),
            None,
            id="empty",
        ),
    ],
)
async def test_syncookie_with_options(
    tcp_options: list[tuple],
    expected_synack_option_names: tuple[str, ...],
    expected_timestamp_bits: int | None,
    ip_version: str,
    xfw_with_forced_syncookie: XFW,
    tcp_server: TcpServer,
    tcp_raw_client: TcpRawClient,
    start_tcp_server_and_raw_clients,
):
    tcp_packet = get_tcp_packet(flag="S", options=tcp_options)

    # Use zero passive timer to try to generate a cookie for each SYN.
    await xfw_with_forced_syncookie.rules_set(
        "xfw { tcp_syncookies flood_timer=1 passive_timer=0; }"
    )

    # It's required to have a unique client because syncookie is issued at 4-tuple.
    tcp_raw_client.port = random.randrange(1, 65000)

    async with xfw_with_forced_syncookie.metrics_diff(stats_counters, wait_softirq=True) as diff:
        stats_before = await xfw_with_forced_syncookie.syncookies_read_kern_stats()
        # Do not use handshake() method to analyze SYN-ACK options instead
        # of dropping just silent drop of the packet.
        await tcp_raw_client.send_packet(tcp_packet)
        syn_ack = await tcp_raw_client.receive_packet()
        assert syn_ack is not None, "Server did not reply"
        assert tcp_raw_client.has_flag(
            syn_ack, "SA"
        ), f"Unexpected reply flags {syn_ack.flags}; expected SA"

        assert tuple(name for name, _ in syn_ack.options) == expected_synack_option_names

        syn_ack_options = dict(syn_ack.options)
        if "MSS" in syn_ack_options:
            # xFW hides the SYN options from bpf_tcp_gen_syncookie(), so the
            # helper returns the RFC default MSS for the address family.
            # tcp_get_syncookie_mss() defines the MSS as:
            #   IPv4: TCP_MSS_DEFAULT = 536
            #   IPv6: IPV6_MIN_MTU - 40-byte IPv6 header - 20-byte TCP header
            #         = 1280 - 40 - 20 = 1220
            expected_mss = 536 if ip_version == "ip4" else 1220
            assert syn_ack_options["MSS"] == expected_mss
        if "WScale" in syn_ack_options:
            assert syn_ack_options["WScale"] == 7
        if "SAckOK" in syn_ack_options:
            assert syn_ack_options["SAckOK"] == b""
        if "Timestamp" in syn_ack_options:
            sent_timestamp = dict(tcp_packet.options)["Timestamp"][0]
            timestamp, echoed_timestamp = syn_ack_options["Timestamp"]
            assert echoed_timestamp == sent_timestamp
            assert timestamp & 0x3F == expected_timestamp_bits

        await tcp_raw_client.send_packet(TCP(flags="A"))
        assert await tcp_raw_client.close_connection() is True
        stats_after = await xfw_with_forced_syncookie.syncookies_read_kern_stats()

    # xFW generates the cookie, while the kernel accepts the final ACK.
    assert stats_after[0] == stats_before[0]
    assert stats_after[1] == stats_before[1] + 1
    assert stats_after[2] == stats_before[2]
    check_xfw_stats(diff, (1, 1, 0))


async def test_flood_mode(
    xfw_with_forced_syncookie: XFW,
    tcp_server: TcpServer,
    tcp_raw_client: TcpRawClient,
    start_tcp_server_and_raw_clients,
):
    """
    In the flood_mode we expect that upstream is under the
    syn-flood attack and each connection triggers the Syncookie
    generating. But after the timeout and only if attack is finished
    the XFW stop the syncookie generating
    """

    flood_timer = 3
    tcp_raw_client.port = random.randrange(1, 65000)

    # XFW requests the kernel whether syncookie should be issued, so we make the
    # kernel always consider to generate a cyncookie with net.ipv4.tcp_syncookies=2.
    # Besides the kernel consideration, xFW also has flood and passive timers,
    # so to generate syncookie both the kernel and xFW must be in flood mode.
    # Set passive timer to 0 to immediately move to flood mode.
    await xfw_with_forced_syncookie.syncookies_always()
    await xfw_with_forced_syncookie.rules_set(
        f"xfw {{ tcp_syncookies flood_timer={flood_timer} passive_timer=0; }}"
    )

    # xFW generates the cookie; the kernel only accounts for accepting it.
    async with xfw_with_forced_syncookie.metrics_diff(stats_counters, wait_softirq=True) as diff:
        stats_before = await xfw_with_forced_syncookie.syncookies_read_kern_stats()
        assert await tcp_raw_client.handshake() is True
        assert await tcp_raw_client.close_connection() is True
        stats_after = await xfw_with_forced_syncookie.syncookies_read_kern_stats()
    assert stats_after[0] == stats_before[0]
    assert stats_after[1] == stats_before[1] + 1
    assert stats_after[2] == stats_before[2]
    check_xfw_stats(diff, (1, 1, 0))

    # wait until flood_timer first loop expires.
    # We don't change the sysctl syncookie value, so
    # the flood attack is continue going
    middle_of_flood_timer_loop = flood_timer / 2
    await asyncio.sleep(flood_timer + middle_of_flood_timer_loop)

    async with xfw_with_forced_syncookie.metrics_diff(stats_counters, wait_softirq=True) as diff:
        stats_before = await xfw_with_forced_syncookie.syncookies_read_kern_stats()
        assert await tcp_raw_client.handshake() is True
        assert await tcp_raw_client.close_connection() is True
        stats_after = await xfw_with_forced_syncookie.syncookies_read_kern_stats()
    assert stats_after[0] == stats_before[0]
    assert stats_after[1] == stats_before[1] + 1
    assert stats_after[2] == stats_before[2]
    check_xfw_stats(diff, (1, 1, 0))

    # turn off the kernel syncookie and wait
    # until second loop finishes. Now, we assume that syn-flood
    # attack is started and non syn-cookies should be issued
    await xfw_with_forced_syncookie.syncookies_never()
    await asyncio.sleep(flood_timer)

    async with xfw_with_forced_syncookie.metrics_diff(stats_counters, wait_softirq=True) as diff:
        stats_before = await xfw_with_forced_syncookie.syncookies_read_kern_stats()
        assert await tcp_raw_client.handshake() is True
        assert await tcp_raw_client.close_connection() is True
        stats_after = await xfw_with_forced_syncookie.syncookies_read_kern_stats()
    assert stats_after[0] == stats_before[0]
    assert stats_after[1] == stats_before[1]
    assert stats_after[2] == stats_before[2]
    check_xfw_stats(diff, (0, 0, 0))

    # let's turn on the kernel syncookie again
    # and check that syncookie works again
    await xfw_with_forced_syncookie.syncookies_always()
    await asyncio.sleep(flood_timer)

    async with xfw_with_forced_syncookie.metrics_diff(stats_counters, wait_softirq=True) as diff:
        stats_before = await xfw_with_forced_syncookie.syncookies_read_kern_stats()
        assert await tcp_raw_client.handshake() is True
        assert await tcp_raw_client.close_connection() is True
        stats_after = await xfw_with_forced_syncookie.syncookies_read_kern_stats()
    assert stats_after[0] == stats_before[0]
    assert stats_after[1] == stats_before[1] + 1
    assert stats_after[2] == stats_before[2]
    check_xfw_stats(diff, (1, 1, 0))


async def test_passive_mode(
    xfw_with_forced_syncookie: XFW,
    tcp_server: TcpServer,
    tcp_raw_client: TcpRawClient,
    start_tcp_server_and_raw_clients,
):
    """
    In the passive_mode we expect that there is no syn-attack and
    check it with interval. If after some check the XFW see some
    abnormal traffic, the syncookie should be issued on the each
    new connection
    """

    passive_timer = 3
    tcp_raw_client.port = random.randrange(1, 65000)

    # As XFW requests the kernel whether syncookie should be
    # issued, we "patch" the kernel response with forced
    # set sysctl flag. Now, kernel always replies on !!! XFW REQUEST NEGATIVE !!!
    # That is immitation of regular traffic without anomalies
    await xfw_with_forced_syncookie.syncookies_never()
    await xfw_with_forced_syncookie.rules_set(
        f"xfw {{ tcp_syncookies passive_timer={passive_timer} flood_timer=1; }}"
    )

    # As we in the passive_mode, no syncookies should be issued
    async with xfw_with_forced_syncookie.metrics_diff(stats_counters, wait_softirq=True) as diff:
        stats_before = await xfw_with_forced_syncookie.syncookies_read_kern_stats()
        assert await tcp_raw_client.handshake() is True
        assert await tcp_raw_client.close_connection() is True
        stats_after = await xfw_with_forced_syncookie.syncookies_read_kern_stats()
    assert stats_after[0] == stats_before[0]
    assert stats_after[1] == stats_before[1]
    assert stats_after[2] == stats_before[2]
    check_xfw_stats(diff, (0, 0, 0))

    # wait until passive_timer first loop expires.
    # We don't change the sysctl syncookie value, so
    # we still don't have any anomalies
    middle_of_passive_timer_loop = passive_timer / 2
    await asyncio.sleep(passive_timer + middle_of_passive_timer_loop)

    async with xfw_with_forced_syncookie.metrics_diff(stats_counters, wait_softirq=True) as diff:
        stats_before = await xfw_with_forced_syncookie.syncookies_read_kern_stats()
        assert await tcp_raw_client.handshake() is True
        assert await tcp_raw_client.close_connection() is True
        stats_after = await xfw_with_forced_syncookie.syncookies_read_kern_stats()
    assert stats_after[0] == stats_before[0]
    assert stats_after[1] == stats_before[1]
    assert stats_after[2] == stats_before[2]
    check_xfw_stats(diff, (0, 0, 0))

    # turn on the kernel syncookie and wait until
    # second loop finishes. Now, we assume that syn-flood
    # attack is started and syn-cookies should be issued

    await xfw_with_forced_syncookie.syncookies_always()
    await asyncio.sleep(passive_timer)

    async with xfw_with_forced_syncookie.metrics_diff(stats_counters, wait_softirq=True) as diff:
        stats_before = await xfw_with_forced_syncookie.syncookies_read_kern_stats()
        assert await tcp_raw_client.handshake() is True
        assert await tcp_raw_client.close_connection() is True
        stats_after = await xfw_with_forced_syncookie.syncookies_read_kern_stats()
    assert stats_after[0] == stats_before[0]
    assert stats_after[1] == stats_before[1] + 1
    assert stats_after[2] == stats_before[2]
    check_xfw_stats(diff, (1, 1, 0))

    # let's turn off the kernel syncookie again
    # and check that syncookie disabled again
    await xfw_with_forced_syncookie.syncookies_never()
    await asyncio.sleep(passive_timer)

    async with xfw_with_forced_syncookie.metrics_diff(stats_counters, wait_softirq=True) as diff:
        stats_before = await xfw_with_forced_syncookie.syncookies_read_kern_stats()
        assert await tcp_raw_client.handshake() is True
        assert await tcp_raw_client.close_connection() is True
        stats_after = await xfw_with_forced_syncookie.syncookies_read_kern_stats()
    assert stats_after[0] == stats_before[0]
    assert stats_after[1] == stats_before[1]
    assert stats_after[2] == stats_before[2]
    check_xfw_stats(diff, (0, 0, 0))


@pytest.mark.parametrize(
    "option,packets_amount,duration,packet",
    [
        pytest.param("flood_timer=1 passive_timer=0", 2000, 20, bad_packet, id="flood-bad"),
        pytest.param("flood_timer=1 passive_timer=0", 2000, 20, ok_packet, id="flood-ok-1"),
        pytest.param("flood_timer=15 passive_timer=0", 2000, 20, ok_packet, id="flood-ok-15"),
        pytest.param("flood_timer=1000 passive_timer=0", 2000, 20, ok_packet, id="flood-ok-1000"),
        # Options not starting with "flood_timer" test non-zero passive timer.
        # These tests are not deterministic and we assert their results with rough ranges.
        pytest.param("passive_timer=1 flood_timer=0", 2000, 20, bad_packet, id="passive-bad"),
        pytest.param("passive_timer=1 flood_timer=0", 2000, 20, ok_packet, id="passive-ok-1"),
        pytest.param("passive_timer=15 flood_timer=0", 2000, 20, ok_packet, id="passive-ok-15"),
        pytest.param("passive_timer=1000 flood_timer=0", 2000, 20, ok_packet, id="passive-ok-1000"),
    ],
)
async def test_normal_connection_under_flood(
    option: str,
    packets_amount: int,
    duration: float,
    packet: TCP,
    xfw_with_forced_syncookie: XFW,
    tcp_server: TcpServer,
    tcp_raw_client: TcpRawClient,
    start_tcp_server_and_raw_clients,
    group_of_clients: list[TcpRawSynCookieClient],
    conf_logger,
):
    await xfw_with_forced_syncookie.rules_set(f"xfw {{ tcp_syncookies {option}; }}")

    async with xfw_with_forced_syncookie.metrics_diff(stats_counters) as diff:
        stats_before = await xfw_with_forced_syncookie.syncookies_read_kern_stats()
        coroutines = [
            client.flood(packet=packet, amount=packets_amount, duration=duration)
            for client in group_of_clients
        ]

        async with run_in_background(coroutines) as tasks:
            # wait the middle of attack
            await asyncio.sleep(duration / 2)

            # At this moment, tcp_raw_client trigger XFW to
            # generate the syncookie
            assert (
                await tcp_raw_client.handshake() is True
            ), "Normal client can not establish tcp connection"
            assert (
                await tcp_raw_client.close_connection() is True
            ), "Normal client can not close tcp connection"

        flood_results = [task.result() for task in tasks]
        assert all(sent == packets_amount for sent, _ in flood_results)
        await xfw_with_forced_syncookie.wait_softirq()
        stats_after = await xfw_with_forced_syncookie.syncookies_read_kern_stats()

    expected_total = packets_amount * len(group_of_clients) + 1
    check_kern_rcv(conf_logger, stats_before, stats_after)
    if option.startswith("flood_timer"):
        check_xfw_stats(diff, (expected_total, 1, 0))
    else:
        # The kernel Sent/Failed counters are namespace-global and cannot be
        # combined with xFW metrics. Check xFW's share of passive-mode traffic.
        assert 0 < diff["xfw_syncookie_generated_packets"] < expected_total
        assert diff["xfw_syncookie_received_packets"] in (0, 1)
        assert diff["xfw_syncookie_failed_packets"] == 0


@pytest.mark.parametrize(
    "option,handshakes,duration",
    [
        pytest.param("flood_timer=2 passive_timer=0", 1000, 40, id="flood"),
        pytest.param("passive_timer=5 flood_timer=0", 1000, 40, id="passive"),
    ],
)
async def test_normal_connection_under_handshake_flood(
    option: str,
    handshakes: int,
    duration: int,
    xfw_with_forced_syncookie: XFW,
    tcp_server: TcpServer,
    tcp_raw_client: TcpRawClient,
    start_tcp_server_and_raw_clients,
    group_of_clients: list[TcpRawSynCookieClient],
    conf_logger,
):
    await xfw_with_forced_syncookie.rules_set(f"xfw {{ tcp_syncookies {option}; }}")

    async with xfw_with_forced_syncookie.metrics_diff(stats_counters) as diff:
        stats_before = await xfw_with_forced_syncookie.syncookies_read_kern_stats()

        coroutines = [
            client.flood_handshake(amount=handshakes, duration=duration)
            for client in group_of_clients
        ]
        async with run_in_background(coroutines) as tasks:
            # wait the middle of attack
            await asyncio.sleep(duration / 2)

            # At this moment, tcp_raw_client trigger XFW to
            # generate the syncookie
            assert (
                await tcp_raw_client.handshake() is True
            ), "Normal client can not establish tcp connection"
            assert (
                await tcp_raw_client.close_connection() is True
            ), "Normal client can not close tcp connection"

        flood_results = [task.result() for task in tasks]
        await xfw_with_forced_syncookie.wait_softirq()
        stats_after = await xfw_with_forced_syncookie.syncookies_read_kern_stats()

    expected_total = handshakes * len(group_of_clients)
    invalid_acks = sum(acknowledged for _, acknowledged in flood_results)
    check_kern_rcv(conf_logger, stats_before, stats_after)
    if option.startswith("flood_timer"):
        check_xfw_stats(diff, (expected_total + 1, 1, invalid_acks))
    else:
        assert 0 < diff["xfw_syncookie_generated_packets"] < expected_total + 1
        assert 0 <= diff["xfw_syncookie_failed_packets"] <= invalid_acks
        assert diff["xfw_syncookie_received_packets"] in (0, 1)


async def test_artificial_flood_timer(
    xfw_with_forced_syncookie: XFW,
    tcp_server: TcpServer,
    tcp_raw_client: TcpRawClient,
    start_tcp_server_and_raw_clients,
    group_of_clients: list[TcpRawSynCookieClient],
    conf_logger,
):
    handshakes_amount = 1000
    duration_sec = 40
    flood_timer = 10
    passive_timer = 1000

    # ENTERING FLOOD MODE
    await xfw_with_forced_syncookie.syncookies_value_set(2)
    await xfw_with_forced_syncookie.rules_set(
        f"xfw {{ tcp_syncookies passive_timer={passive_timer} flood_timer={flood_timer}; }}"
    )
    expected_total = handshakes_amount * len(group_of_clients)

    async with xfw_with_forced_syncookie.metrics_diff(stats_counters) as flood_diff:
        stats_before = await xfw_with_forced_syncookie.syncookies_read_kern_stats()

        start_time = time.monotonic()
        coroutines = [
            client.flood_handshake(amount=handshakes_amount, duration=duration_sec)
            for client in group_of_clients
        ]
        tasks = [asyncio.create_task(coro) for coro in coroutines]

        await asyncio.sleep(duration_sec / 2)

        # We must check that cookies, xfw issued, are correct (i.e. accepted by kernel)
        await tcp_raw_client.handshake()
        await tcp_raw_client.close_connection()

        await asyncio.gather(*tasks)
        assert time.monotonic() - start_time < 50, "Haven't finished all syns in time"

        await xfw_with_forced_syncookie.wait_softirq()
        stats_after = await xfw_with_forced_syncookie.syncookies_read_kern_stats()

    invalid_acks = sum(task.result()[1] for task in tasks)
    check_kern_rcv(conf_logger, stats_before, stats_after)
    assert 0 < flood_diff["xfw_syncookie_generated_packets"] <= expected_total + 1
    assert 0 <= flood_diff["xfw_syncookie_failed_packets"] <= invalid_acks
    assert flood_diff["xfw_syncookie_received_packets"] in (0, 1)

    await xfw_with_forced_syncookie.syncookies_value_set(0)
    async with xfw_with_forced_syncookie.metrics_diff(stats_counters) as passive_diff:
        stats_before = await xfw_with_forced_syncookie.syncookies_read_kern_stats()

        # Wait until xFW leaves flood mode.
        await asyncio.sleep(flood_timer + 1)

        # ENTERING PASSIVE MODE
        # With kernel syncookies disabled, this connection changes no counters.
        await tcp_raw_client.handshake()
        await tcp_raw_client.close_connection()

        # On CPUs primed in phase one, the passive timer has not expired, so
        # xFW passes SYNs to the kernel. An unprimed CPU can still generate an
        # xFW cookie and enter flood mode.
        await xfw_with_forced_syncookie.syncookies_value_set(2)

        start_time = time.monotonic()
        coroutines = [
            client.flood_handshake(amount=handshakes_amount, duration=duration_sec)
            for client in group_of_clients
        ]
        tasks = [asyncio.create_task(coro) for coro in coroutines]

        await asyncio.sleep(duration_sec / 2)

        await tcp_raw_client.handshake()
        await tcp_raw_client.close_connection()

        await asyncio.gather(*tasks)
        assert time.monotonic() - start_time < 100, "Haven't finished all syns in time"

        await xfw_with_forced_syncookie.wait_softirq()
        stats_after = await xfw_with_forced_syncookie.syncookies_read_kern_stats()

    invalid_acks = sum(task.result()[1] for task in tasks)
    check_kern_rcv(conf_logger, stats_before, stats_after)
    assert 0 <= passive_diff["xfw_syncookie_generated_packets"] <= expected_total + 1
    assert 0 <= passive_diff["xfw_syncookie_failed_packets"] <= invalid_acks
    assert passive_diff["xfw_syncookie_received_packets"] in (0, 1)
    assert (
        flood_diff["xfw_syncookie_generated_packets"]
        > passive_diff["xfw_syncookie_generated_packets"]
    )


async def test_flood_allowed_by_del_rule(
    xfw_with_forced_syncookie: XFW,
    tcp_server: TcpServer,
    tcp_raw_client: TcpRawClient,
    start_tcp_server_and_raw_clients,
):
    await xfw_with_forced_syncookie.rules_set(
        "xfw { tcp_syncookies passive_timer=0 flood_timer=0; }"
    )
    await xfw_with_forced_syncookie.rules_set("xfw { tcp_syncookies/del; }")

    await tcp_raw_client.send_packet(TCP(flags="S"))

    response = await tcp_raw_client.receive_packet()
    assert tcp_raw_client.has_flag(
        response, "SA"
    ), f"Unexpected reply packet with flags = {response.flags}. Expected SA"
