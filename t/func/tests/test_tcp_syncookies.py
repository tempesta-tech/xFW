# SPDX-FileCopyrightText: (c) 2026 Tempesta Technologies, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later
import abc
import asyncio
import random
import time
from typing import AsyncGenerator

import pytest
from freezegun import freeze_time
from scapy.layers.inet import TCP

from config import ConfigSettings
from framework.asyn import (
    TcpIpV4RawClient,
    TcpIpV6RawClient,
    TcpRawClient,
    TcpServer,
)
from framework.fabrics import client_fabric
from framework.metrics import KernelMetrics, KernelMetricsDiff, PrometheusMetricsDiff
from framework.utils import get_tcp_packet, run_in_background
from framework.xfw import XFW

bad_packet = TCP(flags="S")
ok_packet = TCP(
    flags="S",
    window=6420,
    seq=32513451,
    options=[
        ("MSS", 1460),
    ],
)


class TcpRawSynCookieClient(TcpRawClient, abc.ABC):
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
) -> AsyncGenerator[TcpRawSynCookieIpv4Client, None]:
    client = client_fabric(
        logging_level=logging_level,
        config=config,
        local_class=TcpRawSynCookieIpv4Client,
    )
    yield client


@pytest.fixture
async def tcp_ip6_raw_syncookie_client(
    config: ConfigSettings, logging_level
) -> AsyncGenerator[TcpRawSynCookieIpv6Client, None]:
    client = client_fabric(
        logging_level=logging_level,
        config=config,
        local_class=TcpRawSynCookieIpv6Client,
    )
    yield client


@pytest.fixture
def tcp_syncookie_client(request, ip_version) -> TcpRawSynCookieClient:
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
    clients: list[TcpRawSynCookieClient] = client_cloner(
        cloner=tcp_syncookie_client,
        amount=2,
    )

    for client in clients:
        client.auto_ack_seq = False
        client.filter_packets = False
        client.log_msg = False
        await client.start()

    yield clients


@pytest.mark.parametrize(
    "tcp_syncookies_parameter",
    [
        pytest.param("flood_timer=2 passive_timer=3", id="custom"),
        pytest.param("flood_timer=2", id="flood"),
        pytest.param("passive_timer=2", id="passive"),
        pytest.param("flood_timer=1 passive_timer=0", id="always-passive"),
        pytest.param(
            # This configuration is not recommeded by our wiki.
            # The problem with it that it's very non-deterministic: zero passive
            # mode makes xFW to try to send SYN cookie every CPU scheduler tick
            # and zero flood mode moves to the passive mode also every scheduler
            # tick. With these timing the tests results may differ.
            "flood_timer=0 passive_timer=0",
            id="no-received-syncookies",
            marks=pytest.mark.xfail(
                strict=False,
                reason="Expected failre as `flood_timer=0 passive_timer=0` configuration is not recommended",
            ),
        ),
    ],
)
async def test_normal_connection(
    tcp_syncookies_parameter: str,
    xfw_with_forced_syncookie: XFW,
    tcp_server: TcpServer,
    tcp_raw_client: TcpRawClient,
    start_tcp_server_and_raw_clients,
    metric_analyzer,
):
    await xfw_with_forced_syncookie.rules_set(
        f"xfw {{ tcp_syncookies {tcp_syncookies_parameter}; }}"
    )

    # It's required to have a unique client because syncookie is issued at 4-tuple.
    tcp_raw_client.port = random.randrange(1, 65000)

    # STAGE 1: Connection
    async with (
        metric_analyzer.expected_metrics_diff(
            xfw=xfw_with_forced_syncookie,
            expected_metrics=PrometheusMetricsDiff(
                xfw_syncookie_generated_packets=1,
                xfw_syncookie_received_packets=1,
                xfw_syncookie_failed_packets=0,
            ),
            wait_softirq=True,
        ),
        metric_analyzer.expected_metrics_diff(
            xfw=xfw_with_forced_syncookie,
            expected_metrics=KernelMetricsDiff(
                syncookie_sent=0,
                syncookie_recv=1,
                syncookie_failed=0,
            ),
        ),
    ):
        # Full TCP handshake: xFW handles client SYN and sends SYN+ACK,
        # the received client ACK goes to the TCP/IP stack, so:
        # SyncookieSent are the same, SyncookieRecv is +1 and
        # xfw_syncookie_generated_packets is +1.
        assert await tcp_raw_client.handshake() is True

    # STAGE 2: Send data
    async with (
        metric_analyzer.expected_metrics_diff(
            xfw=xfw_with_forced_syncookie,
            expected_metrics=PrometheusMetricsDiff(
                xfw_syncookie_generated_packets=0,
                xfw_syncookie_received_packets=0,
                xfw_syncookie_failed_packets=0,
            ),
            wait_softirq=True,
        ),
        metric_analyzer.expected_metrics_diff(
            xfw=xfw_with_forced_syncookie,
            expected_metrics=KernelMetricsDiff(
                syncookie_sent=0,
                syncookie_recv=0,
                syncookie_failed=0,
            ),
        ),
    ):

        # nothing changes
        await tcp_raw_client.send_packet(TCP(flags="PA") / b"hello")
        answer = await tcp_raw_client.receive_packet()

    assert answer is not None
    assert tcp_raw_client.has_flag(answer, "A")

    # STAGE 3: Disconnecting
    async with (
        metric_analyzer.expected_metrics_diff(
            xfw=xfw_with_forced_syncookie,
            expected_metrics=PrometheusMetricsDiff(
                xfw_syncookie_generated_packets=0,
                xfw_syncookie_received_packets=0,
                xfw_syncookie_failed_packets=0,
            ),
            wait_softirq=True,
        ),
        metric_analyzer.expected_metrics_diff(
            xfw=xfw_with_forced_syncookie,
            expected_metrics=KernelMetricsDiff(
                syncookie_sent=0,
                syncookie_recv=0,
                syncookie_failed=0,
            ),
        ),
    ):
        # nothing changes
        assert await tcp_raw_client.close_connection() is True


@pytest.mark.parametrize(
    "ip_version,send_options,expected_options",
    [
        pytest.param(
            "ip4",
            [
                ("MSS", 1460),
                ("NOP", None),
                ("WScale", 6),
                ("SAckOK", b""),
                ("Timestamp", (1767225600, 0)),
            ],
            [
                ("MSS", 536),
                ("NOP", None),
                ("WScale", 7),
                ("SAckOK", b""),
                ("Timestamp", (0x16, 1767225600)),
            ],
            id="full-house-ip4",
        ),
        pytest.param(
            "ip6",
            [
                ("MSS", 1460),
                ("NOP", None),
                ("WScale", 6),
                ("SAckOK", b""),
                ("Timestamp", (1767225600, 0)),
            ],
            [
                ("MSS", 1220),
                ("NOP", None),
                ("WScale", 7),
                ("SAckOK", b""),
                ("Timestamp", (0x16, 1767225600)),
            ],
            id="full-house-ip6",
        ),
        pytest.param(
            "ip4",
            [
                ("MSS", 1460),
                ("NOP", None),
                ("SAckOK", b""),
                ("Timestamp", (1767225600, 0)),
            ],
            [
                ("MSS", 536),
                ("NOP", None),
                ("WScale", 7),
                ("SAckOK", b""),
                ("Timestamp", (0x1F, 1767225600)),
            ],
            id="mss+sackok+ts+nop-ip4",
        ),
        pytest.param(
            "ip6",
            [
                ("MSS", 1460),
                ("NOP", None),
                ("SAckOK", b""),
                ("Timestamp", (1767225600, 0)),
            ],
            [
                ("MSS", 1220),
                ("NOP", None),
                ("WScale", 7),
                ("SAckOK", b""),
                ("Timestamp", (0x1F, 1767225600)),
            ],
            id="mss+sackok+ts+nop-ip6",
        ),
        pytest.param(
            "ip4",
            [
                ("MSS", 1460),
                ("SAckOK", b""),
                ("Timestamp", (1767225600, 0)),
            ],
            [
                ("MSS", 536),
                ("NOP", None),
                ("WScale", 7),
                ("SAckOK", b""),
                ("NOP", None),
                ("EOL", None),
            ],
            id="mss+sackok+ts-ip4",
        ),
        pytest.param(
            "ip6",
            [
                ("MSS", 1460),
                ("SAckOK", b""),
                ("Timestamp", (1767225600, 0)),
            ],
            [
                ("MSS", 1220),
                ("NOP", None),
                ("WScale", 7),
                ("SAckOK", b""),
                ("NOP", None),
                ("EOL", None),
            ],
            id="mss+sackok+ts-ip6",
        ),
        pytest.param(
            "ip4",
            [
                ("MSS", 1460),
                ("SAckOK", b""),
            ],
            [
                ("MSS", 536),
                ("NOP", None),
                ("WScale", 7),
            ],
            id="mss+sackok-ip4",
        ),
        pytest.param(
            "ip6",
            [
                ("MSS", 1460),
                ("SAckOK", b""),
            ],
            [
                ("MSS", 1220),
                ("NOP", None),
                ("WScale", 7),
            ],
            id="mss+sackok-ip6",
        ),
        pytest.param(
            "ip4",
            [
                ("MSS", 1460),
            ],
            [
                ("MSS", 536),
            ],
            id="mss-ip4",
        ),
        pytest.param(
            "ip6",
            [
                ("MSS", 1460),
            ],
            [
                ("MSS", 1220),
            ],
            id="mss-ip6",
        ),
        pytest.param("ip4", [], [], id="empty-ip4"),
        pytest.param("ip6", [], [], id="empty-ip6"),
    ],
)
@freeze_time("2026-01-01 00:00:00", real_asyncio=True)
async def test_syncookie_with_options(
    ip_version: str,
    send_options: list[tuple],
    expected_options: list[tuple],
    xfw_with_forced_syncookie: XFW,
    tcp_ip4_server: TcpServer,
    tcp_ip6_server: TcpServer,
    tcp_ip4_raw_client: TcpRawClient,
    tcp_ip6_raw_client: TcpRawClient,
    metric_analyzer,
):
    tcp_server = locals()[f"tcp_{ip_version}_server"]
    tcp_raw_client = locals()[f"tcp_{ip_version}_raw_client"]

    await tcp_server.start()
    await tcp_raw_client.start()

    tcp_packet = get_tcp_packet(flag="S", options=send_options)

    # Use zero passive timer to try to generate a cookie for each SYN.
    await xfw_with_forced_syncookie.rules_set(
        "xfw { tcp_syncookies flood_timer=1 passive_timer=0; }"
    )

    # It's required to have a unique client because syncookie is issued at 4-tuple.
    tcp_raw_client.port = random.randrange(1, 65000)

    async with (
        metric_analyzer.expected_metrics_diff(
            xfw=xfw_with_forced_syncookie,
            expected_metrics=PrometheusMetricsDiff(
                xfw_syncookie_generated_packets=1,
                xfw_syncookie_received_packets=1,
                xfw_syncookie_failed_packets=0,
            ),
            wait_softirq=True,
        ),
        metric_analyzer.expected_metrics_diff(
            xfw=xfw_with_forced_syncookie,
            # xFW generates the cookie, while the kernel accepts the final ACK.
            expected_metrics=KernelMetricsDiff(
                syncookie_sent=0,
                syncookie_recv=1,
                syncookie_failed=0,
            ),
        ),
    ):
        # Do not use handshake() method to analyze SYN-ACK options instead
        # of dropping just silent drop of the packet.
        await tcp_raw_client.send_packet(tcp_packet)
        syn_ack = await tcp_raw_client.receive_packet()
        assert syn_ack is not None, "Server did not reply"
        assert tcp_raw_client.has_flag(
            syn_ack, "SA"
        ), f"Unexpected reply flags {syn_ack.flags}; expected SA"

        await tcp_raw_client.send_packet(TCP(flags="A"))
        assert await tcp_raw_client.close_connection() is True

    # TSval high bits are the TCP clock; expected lists only cookie flags in the low 6 bits.
    received_options = [
        (name, (value[0] & 0x3F, value[1]) if name == "Timestamp" else value)
        for name, value in syn_ack.options
    ]
    assert expected_options == received_options


async def test_flood_mode(
    xfw_with_forced_syncookie: XFW,
    tcp_server: TcpServer,
    tcp_raw_client: TcpRawClient,
    start_tcp_server_and_raw_clients,
    metric_analyzer,
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
    async with (
        metric_analyzer.expected_metrics_diff(
            xfw=xfw_with_forced_syncookie,
            expected_metrics=PrometheusMetricsDiff(
                xfw_syncookie_generated_packets=1,
                xfw_syncookie_received_packets=1,
                xfw_syncookie_failed_packets=0,
            ),
            wait_softirq=True,
        ),
        metric_analyzer.expected_metrics_diff(
            xfw=xfw_with_forced_syncookie,
            # xFW generates the cookie, while the kernel accepts the final ACK.
            expected_metrics=KernelMetricsDiff(
                syncookie_sent=0,
                syncookie_recv=1,
                syncookie_failed=0,
            ),
        ),
    ):
        assert await tcp_raw_client.handshake() is True
        assert await tcp_raw_client.close_connection() is True

    # wait until flood_timer first loop expires.
    # We don't change the sysctl syncookie value, so
    # the flood attack is continue going
    middle_of_flood_timer_loop = flood_timer / 2
    await asyncio.sleep(flood_timer + middle_of_flood_timer_loop)

    async with (
        metric_analyzer.expected_metrics_diff(
            xfw=xfw_with_forced_syncookie,
            expected_metrics=PrometheusMetricsDiff(
                xfw_syncookie_generated_packets=1,
                xfw_syncookie_received_packets=1,
                xfw_syncookie_failed_packets=0,
            ),
            wait_softirq=True,
        ),
        metric_analyzer.expected_metrics_diff(
            xfw=xfw_with_forced_syncookie,
            expected_metrics=KernelMetricsDiff(
                syncookie_sent=0,
                syncookie_recv=1,
                syncookie_failed=0,
            ),
        ),
    ):
        assert await tcp_raw_client.handshake() is True
        assert await tcp_raw_client.close_connection() is True

    # turn off the kernel syncookie and wait
    # until second loop finishes. Now, we assume that syn-flood
    # attack is started and non syn-cookies should be issued
    await xfw_with_forced_syncookie.syncookies_never()
    await asyncio.sleep(flood_timer)

    async with (
        metric_analyzer.expected_metrics_diff(
            xfw=xfw_with_forced_syncookie,
            expected_metrics=PrometheusMetricsDiff(
                xfw_syncookie_generated_packets=0,
                xfw_syncookie_received_packets=0,
                xfw_syncookie_failed_packets=0,
            ),
            wait_softirq=True,
        ),
        metric_analyzer.expected_metrics_diff(
            xfw=xfw_with_forced_syncookie,
            expected_metrics=KernelMetricsDiff(
                syncookie_sent=0,
                syncookie_recv=0,
                syncookie_failed=0,
            ),
        ),
    ):
        assert await tcp_raw_client.handshake() is True
        assert await tcp_raw_client.close_connection() is True

    # let's turn on the kernel syncookie again
    # and check that syncookie works again
    await xfw_with_forced_syncookie.syncookies_always()
    await asyncio.sleep(flood_timer)

    async with (
        metric_analyzer.expected_metrics_diff(
            xfw=xfw_with_forced_syncookie,
            expected_metrics=PrometheusMetricsDiff(
                xfw_syncookie_generated_packets=1,
                xfw_syncookie_received_packets=1,
                xfw_syncookie_failed_packets=0,
            ),
            wait_softirq=True,
        ),
        metric_analyzer.expected_metrics_diff(
            xfw=xfw_with_forced_syncookie,
            expected_metrics=KernelMetricsDiff(
                syncookie_sent=0,
                syncookie_recv=1,
                syncookie_failed=0,
            ),
        ),
    ):
        assert await tcp_raw_client.handshake() is True
        assert await tcp_raw_client.close_connection() is True


async def test_passive_mode(
    xfw_with_forced_syncookie: XFW,
    tcp_server: TcpServer,
    tcp_raw_client: TcpRawClient,
    start_tcp_server_and_raw_clients,
    metric_analyzer,
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
    async with (
        metric_analyzer.expected_metrics_diff(
            xfw=xfw_with_forced_syncookie,
            expected_metrics=PrometheusMetricsDiff(
                xfw_syncookie_generated_packets=0,
                xfw_syncookie_received_packets=0,
                xfw_syncookie_failed_packets=0,
            ),
            wait_softirq=True,
        ),
        metric_analyzer.expected_metrics_diff(
            xfw=xfw_with_forced_syncookie,
            expected_metrics=KernelMetricsDiff(
                syncookie_sent=0,
                syncookie_recv=0,
                syncookie_failed=0,
            ),
        ),
    ):
        assert await tcp_raw_client.handshake() is True
        assert await tcp_raw_client.close_connection() is True

    # wait until passive_timer first loop expires.
    # We don't change the sysctl syncookie value, so
    # we still don't have any anomalies
    middle_of_passive_timer_loop = passive_timer / 2
    await asyncio.sleep(passive_timer + middle_of_passive_timer_loop)

    async with (
        metric_analyzer.expected_metrics_diff(
            xfw=xfw_with_forced_syncookie,
            expected_metrics=PrometheusMetricsDiff(
                xfw_syncookie_generated_packets=0,
                xfw_syncookie_received_packets=0,
                xfw_syncookie_failed_packets=0,
            ),
            wait_softirq=True,
        ),
        metric_analyzer.expected_metrics_diff(
            xfw=xfw_with_forced_syncookie,
            expected_metrics=KernelMetricsDiff(
                syncookie_sent=0,
                syncookie_recv=0,
                syncookie_failed=0,
            ),
        ),
    ):
        assert await tcp_raw_client.handshake() is True
        assert await tcp_raw_client.close_connection() is True

    # turn on the kernel syncookie and wait until
    # second loop finishes. Now, we assume that syn-flood
    # attack is started and syn-cookies should be issued

    await xfw_with_forced_syncookie.syncookies_always()
    await asyncio.sleep(passive_timer)

    async with (
        metric_analyzer.expected_metrics_diff(
            xfw=xfw_with_forced_syncookie,
            expected_metrics=PrometheusMetricsDiff(
                xfw_syncookie_generated_packets=1,
                xfw_syncookie_received_packets=1,
                xfw_syncookie_failed_packets=0,
            ),
            wait_softirq=True,
        ),
        metric_analyzer.expected_metrics_diff(
            xfw=xfw_with_forced_syncookie,
            expected_metrics=KernelMetricsDiff(
                syncookie_sent=0,
                syncookie_recv=1,
                syncookie_failed=0,
            ),
        ),
    ):
        assert await tcp_raw_client.handshake() is True
        assert await tcp_raw_client.close_connection() is True

    # let's turn off the kernel syncookie again
    # and check that syncookie disabled again
    await xfw_with_forced_syncookie.syncookies_never()
    await asyncio.sleep(passive_timer)

    async with (
        metric_analyzer.expected_metrics_diff(
            xfw=xfw_with_forced_syncookie,
            expected_metrics=PrometheusMetricsDiff(
                xfw_syncookie_generated_packets=0,
                xfw_syncookie_received_packets=0,
                xfw_syncookie_failed_packets=0,
            ),
            wait_softirq=True,
        ),
        metric_analyzer.expected_metrics_diff(
            xfw=xfw_with_forced_syncookie,
            expected_metrics=KernelMetricsDiff(
                syncookie_sent=0,
                syncookie_recv=0,
                syncookie_failed=0,
            ),
        ),
    ):
        assert await tcp_raw_client.handshake() is True
        assert await tcp_raw_client.close_connection() is True


_HANDSHAKE_NUM = 2000

# 2 flood client and 1 handshake
_FLOOD_GENERATED = _HANDSHAKE_NUM * 2 + 1
_FLOOD_GENERATED_DELTA = 500
_FLOOD_GENERATED_MAX_VALUE = [
    _FLOOD_GENERATED - _FLOOD_GENERATED_DELTA,
    _FLOOD_GENERATED + _FLOOD_GENERATED_DELTA,
]
_FLOOD_GENERATED_MIN_VALUE = [0, _FLOOD_GENERATED_DELTA]


@pytest.mark.parametrize(
    "option,packets_amount,duration,packet,expected_xfw,expected_kernel",
    [
        pytest.param(
            "flood_timer=1 passive_timer=0",
            _HANDSHAKE_NUM,
            20,
            bad_packet,
            PrometheusMetricsDiff(
                xfw_syncookie_generated_packets=_FLOOD_GENERATED_MAX_VALUE,
                xfw_syncookie_received_packets=_FLOOD_GENERATED_MIN_VALUE,
                xfw_syncookie_failed_packets=_FLOOD_GENERATED_MIN_VALUE,
            ),
            KernelMetricsDiff(
                syncookie_sent=_FLOOD_GENERATED_MIN_VALUE,
                syncookie_recv=_FLOOD_GENERATED_MIN_VALUE,
                syncookie_failed=_FLOOD_GENERATED_MIN_VALUE,
            ),
            id="flood-bad",
        ),
        pytest.param(
            "flood_timer=1 passive_timer=0",
            _HANDSHAKE_NUM,
            20,
            ok_packet,
            PrometheusMetricsDiff(
                xfw_syncookie_generated_packets=_FLOOD_GENERATED_MAX_VALUE,
                xfw_syncookie_received_packets=_FLOOD_GENERATED_MIN_VALUE,
                xfw_syncookie_failed_packets=_FLOOD_GENERATED_MIN_VALUE,
            ),
            KernelMetricsDiff(
                syncookie_sent=_FLOOD_GENERATED_MIN_VALUE,
                syncookie_recv=_FLOOD_GENERATED_MIN_VALUE,
                syncookie_failed=_FLOOD_GENERATED_MIN_VALUE,
            ),
            id="flood-ok-1",
        ),
        pytest.param(
            "flood_timer=15 passive_timer=0",
            _HANDSHAKE_NUM,
            20,
            ok_packet,
            PrometheusMetricsDiff(
                xfw_syncookie_generated_packets=_FLOOD_GENERATED_MAX_VALUE,
                xfw_syncookie_received_packets=_FLOOD_GENERATED_MIN_VALUE,
                xfw_syncookie_failed_packets=_FLOOD_GENERATED_MIN_VALUE,
            ),
            KernelMetricsDiff(
                syncookie_sent=_FLOOD_GENERATED_MIN_VALUE,
                syncookie_recv=_FLOOD_GENERATED_MIN_VALUE,
                syncookie_failed=_FLOOD_GENERATED_MIN_VALUE,
            ),
            id="flood-ok-15",
        ),
        pytest.param(
            "flood_timer=1000 passive_timer=0",
            _HANDSHAKE_NUM,
            20,
            ok_packet,
            PrometheusMetricsDiff(
                xfw_syncookie_generated_packets=_FLOOD_GENERATED_MAX_VALUE,
                xfw_syncookie_received_packets=_FLOOD_GENERATED_MIN_VALUE,
                xfw_syncookie_failed_packets=_FLOOD_GENERATED_MIN_VALUE,
            ),
            KernelMetricsDiff(
                syncookie_sent=_FLOOD_GENERATED_MIN_VALUE,
                syncookie_recv=_FLOOD_GENERATED_MIN_VALUE,
                syncookie_failed=_FLOOD_GENERATED_MIN_VALUE,
            ),
            id="flood-ok-1000",
        ),
        pytest.param(
            "passive_timer=1 flood_timer=0",
            _HANDSHAKE_NUM,
            20,
            bad_packet,
            PrometheusMetricsDiff(
                xfw_syncookie_generated_packets=_FLOOD_GENERATED_MIN_VALUE,
                xfw_syncookie_received_packets=_FLOOD_GENERATED_MIN_VALUE,
                xfw_syncookie_failed_packets=_FLOOD_GENERATED_MIN_VALUE,
            ),
            KernelMetricsDiff(
                syncookie_sent=_FLOOD_GENERATED_MAX_VALUE,
                syncookie_recv=_FLOOD_GENERATED_MIN_VALUE,
                syncookie_failed=_FLOOD_GENERATED_MIN_VALUE,
            ),
            id="passive-bad",
        ),
        pytest.param(
            "passive_timer=1 flood_timer=0",
            _HANDSHAKE_NUM,
            20,
            ok_packet,
            PrometheusMetricsDiff(
                xfw_syncookie_generated_packets=_FLOOD_GENERATED_MIN_VALUE,
                xfw_syncookie_received_packets=_FLOOD_GENERATED_MIN_VALUE,
                xfw_syncookie_failed_packets=_FLOOD_GENERATED_MIN_VALUE,
            ),
            KernelMetricsDiff(
                syncookie_sent=_FLOOD_GENERATED_MAX_VALUE,
                syncookie_recv=_FLOOD_GENERATED_MIN_VALUE,
                syncookie_failed=_FLOOD_GENERATED_MIN_VALUE,
            ),
            id="passive-ok-1",
        ),
        pytest.param(
            "passive_timer=15 flood_timer=0",
            _HANDSHAKE_NUM,
            20,
            ok_packet,
            PrometheusMetricsDiff(
                xfw_syncookie_generated_packets=_FLOOD_GENERATED_MIN_VALUE,
                xfw_syncookie_received_packets=_FLOOD_GENERATED_MIN_VALUE,
                xfw_syncookie_failed_packets=_FLOOD_GENERATED_MIN_VALUE,
            ),
            KernelMetricsDiff(
                syncookie_sent=_FLOOD_GENERATED_MAX_VALUE,
                syncookie_recv=_FLOOD_GENERATED_MIN_VALUE,
                syncookie_failed=_FLOOD_GENERATED_MIN_VALUE,
            ),
            id="passive-ok-15",
        ),
        pytest.param(
            "passive_timer=1000 flood_timer=0",
            _HANDSHAKE_NUM,
            20,
            ok_packet,
            PrometheusMetricsDiff(
                xfw_syncookie_generated_packets=_FLOOD_GENERATED_MIN_VALUE,
                xfw_syncookie_received_packets=_FLOOD_GENERATED_MIN_VALUE,
                xfw_syncookie_failed_packets=_FLOOD_GENERATED_MIN_VALUE,
            ),
            KernelMetricsDiff(
                syncookie_sent=_FLOOD_GENERATED_MAX_VALUE,
                syncookie_recv=_FLOOD_GENERATED_MIN_VALUE,
                syncookie_failed=_FLOOD_GENERATED_MIN_VALUE,
            ),
            id="passive-ok-1000",
        ),
    ],
)
async def test_normal_connection_under_flood(
    option: str,
    packets_amount: int,
    duration: float,
    packet: TCP,
    expected_xfw: PrometheusMetricsDiff,
    expected_kernel: KernelMetricsDiff,
    xfw_with_forced_syncookie: XFW,
    tcp_server: TcpServer,
    tcp_raw_client: TcpRawClient,
    start_tcp_server_and_raw_clients,
    group_of_clients: list[TcpRawSynCookieClient],
    metric_analyzer,
):
    await xfw_with_forced_syncookie.rules_set(f"xfw {{ tcp_syncookies {option}; }}")

    coroutines = [
        client.flood(packet=packet, amount=packets_amount, duration=duration)
        for client in group_of_clients
    ]

    async with (
        metric_analyzer.expected_metrics_diff(
            xfw=xfw_with_forced_syncookie, expected_metrics=expected_xfw
        ),
        metric_analyzer.expected_metrics_diff(
            xfw=xfw_with_forced_syncookie,
            expected_metrics=expected_kernel,
        ),
    ):
        async with run_in_background(coroutines):
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


_HANDSHAKE_NUM = 1000

# 2 flood clients and 1 legitimate handshake.
_HANDSHAKE_FLOOD_GENERATED = _HANDSHAKE_NUM * 2 + 1

# SYN packets can be dropped or generated by other background activities.
# Moreover there is limited time to make _HANDSHAKE_NUM, so depending on
# the machine speed and concurrent workload we may see smaller amount of
# handshakes. Make the limits permissive to avoid flaky tests.
_SYNCOOKIE_GENERATED_VAL_RANGE = [
    _HANDSHAKE_FLOOD_GENERATED * 0.5,
    _HANDSHAKE_FLOOD_GENERATED * 1.5,
]
# These TCP handshakes finish with invalid ACK, so we should 'receive' only
# one syncookie. However, the test uses `net.ipv4.tcp_syncookies=2`, meaning
# that any TCP process in the system (local or extarnal) triggers syncookie
# generation and we might see almost any number here.
#
# xFW syncookies are non-deterministic: at the moment of passive/flood modes
# transition or during the passive mode xFW may not generte syncookies at all,
# so all the counters can be zero.
_SYNCOOKIE_RECEIVED_VAL_RANGE = [0, _HANDSHAKE_FLOOD_GENERATED * 0.1]

# It's almost impossible to predict the number of failed syn cookies,
# but we know that all hanshakes have malformed cookies in ACKs.
_SYNCOOKIE_FAILED_VAL_RANGE = _SYNCOOKIE_GENERATED_VAL_RANGE

# Just a small fraction of generated SYNs
_SYNCOOKIE_SMALL_FRACTION_VAL_RANGE = [0, _HANDSHAKE_FLOOD_GENERATED * 0.1]

# The whole range for the values, which are fully undeterministic
_SYNCOOKIE_WHOLE_VAL_RANGE = [0, _HANDSHAKE_FLOOD_GENERATED]


@pytest.mark.parametrize(
    "option,handshakes,duration,expected_xfw,expected_kernel",
    [
        # The most of the time xFW is in flood mode, but still not always.
        # The kernel must not see the most of the SYNs and invalid ACKs.
        pytest.param(
            "flood_timer=2 passive_timer=0",
            _HANDSHAKE_NUM,
            40,
            PrometheusMetricsDiff(
                xfw_syncookie_generated_packets=_SYNCOOKIE_GENERATED_VAL_RANGE,
                xfw_syncookie_received_packets=_SYNCOOKIE_RECEIVED_VAL_RANGE,
                xfw_syncookie_failed_packets=_SYNCOOKIE_FAILED_VAL_RANGE,
            ),
            KernelMetricsDiff(
                syncookie_sent=_SYNCOOKIE_SMALL_FRACTION_VAL_RANGE,
                syncookie_recv=_SYNCOOKIE_RECEIVED_VAL_RANGE,
                syncookie_failed=_SYNCOOKIE_SMALL_FRACTION_VAL_RANGE,
            ),
            id="flood",
        ),
        pytest.param(
            "passive_timer=5 flood_timer=0",
            _HANDSHAKE_NUM,
            40,
            PrometheusMetricsDiff(
                xfw_syncookie_generated_packets=_SYNCOOKIE_WHOLE_VAL_RANGE,
                xfw_syncookie_received_packets=_SYNCOOKIE_RECEIVED_VAL_RANGE,
                xfw_syncookie_failed_packets=_SYNCOOKIE_WHOLE_VAL_RANGE,
            ),
            KernelMetricsDiff(
                syncookie_sent=_SYNCOOKIE_WHOLE_VAL_RANGE,
                syncookie_recv=_SYNCOOKIE_RECEIVED_VAL_RANGE,
                syncookie_failed=_SYNCOOKIE_WHOLE_VAL_RANGE,
            ),
            id="passive",
        ),
        pytest.param(
            "passive_timer=1 flood_timer=1",
            _HANDSHAKE_NUM,
            40,
            PrometheusMetricsDiff(
                xfw_syncookie_generated_packets=_SYNCOOKIE_GENERATED_VAL_RANGE,
                xfw_syncookie_received_packets=_SYNCOOKIE_RECEIVED_VAL_RANGE,
                xfw_syncookie_failed_packets=_SYNCOOKIE_FAILED_VAL_RANGE,
            ),
            KernelMetricsDiff(
                syncookie_sent=_SYNCOOKIE_SMALL_FRACTION_VAL_RANGE,
                syncookie_recv=_SYNCOOKIE_RECEIVED_VAL_RANGE,
                syncookie_failed=_SYNCOOKIE_SMALL_FRACTION_VAL_RANGE,
            ),
            id="normal",
        ),
    ],
)
async def test_normal_connection_under_handshake_flood(
    option: str,
    handshakes: int,
    duration: int,
    expected_xfw: PrometheusMetricsDiff,
    expected_kernel: KernelMetricsDiff,
    xfw_with_forced_syncookie: XFW,
    tcp_server: TcpServer,
    tcp_raw_client: TcpRawClient,
    start_tcp_server_and_raw_clients,
    group_of_clients: list[TcpRawSynCookieClient],
    metric_analyzer,
):
    await xfw_with_forced_syncookie.rules_set(f"xfw {{ tcp_syncookies {option}; }}")

    coroutines = [
        client.flood_handshake(amount=handshakes, duration=duration) for client in group_of_clients
    ]

    async with (
        metric_analyzer.expected_metrics_diff(
            xfw=xfw_with_forced_syncookie,
            expected_metrics=expected_xfw,
            wait_softirq=True,
        ),
        metric_analyzer.expected_metrics_diff(
            xfw=xfw_with_forced_syncookie,
            expected_metrics=expected_kernel,
        ),
    ):
        async with run_in_background(coroutines):
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


async def test_artificial_flood_timer(
    xfw_with_forced_syncookie: XFW,
    tcp_server: TcpServer,
    tcp_raw_client: TcpRawClient,
    start_tcp_server_and_raw_clients,
    group_of_clients: list[TcpRawSynCookieClient],
    metric_analyzer,
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
    coroutines = [
        client.flood_handshake(amount=handshakes_amount, duration=duration_sec)
        for client in group_of_clients
    ]
    tasks = [asyncio.create_task(coro) for coro in coroutines]

    async with (
        metric_analyzer.expected_metrics_diff(
            xfw=xfw_with_forced_syncookie,
            expected_metrics=PrometheusMetricsDiff(
                xfw_syncookie_generated_packets=[1, expected_total + 2],
                xfw_syncookie_received_packets=[0, 2],
                xfw_syncookie_failed_packets=0,
            ),
            strict=False,
        ) as flood_diff,
        metric_analyzer.expected_metrics_diff(
            xfw=xfw_with_forced_syncookie,
            expected_metrics=KernelMetricsDiff(syncookie_recv=[1, expected_total + 2]),
        ),
    ):
        start_time = time.monotonic()
        await asyncio.sleep(duration_sec / 2)

        # We must check that cookies, xfw issued, are correct (i.e. accepted by kernel)
        await tcp_raw_client.handshake()
        await tcp_raw_client.close_connection()

        await asyncio.gather(*tasks)
        assert time.monotonic() - start_time < 50, "Haven't finished all syns in time"

    invalid_acks = sum(task.result()[1] for task in tasks)
    assert len(flood_diff.invalid_metrics) == 1
    assert 0 <= flood_diff.diff_metrics.xfw_syncookie_failed_packets.value <= invalid_acks + 1

    await xfw_with_forced_syncookie.syncookies_value_set(0)
    async with (
        metric_analyzer.expected_metrics_diff(
            xfw=xfw_with_forced_syncookie,
            expected_metrics=PrometheusMetricsDiff(
                xfw_syncookie_generated_packets=[1, expected_total + 2],
                xfw_syncookie_received_packets=[0, 2],
                xfw_syncookie_failed_packets=0,
            ),
            strict=False,
        ) as passive_diff,
        metric_analyzer.expected_metrics_diff(
            xfw=xfw_with_forced_syncookie,
            expected_metrics=KernelMetricsDiff(syncookie_recv=[1, expected_total + 2]),
        ),
    ):
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

    invalid_acks = sum(task.result()[1] for task in tasks)
    assert len(passive_diff.invalid_metrics) == 1
    assert 0 <= passive_diff.diff_metrics.xfw_syncookie_failed_packets.value <= invalid_acks + 1

    assert (
        flood_diff.diff_metrics.xfw_syncookie_generated_packets.value
        > passive_diff.diff_metrics.xfw_syncookie_generated_packets.value
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
