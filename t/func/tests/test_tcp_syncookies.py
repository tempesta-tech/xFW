# SPDX-FileCopyrightText: (c) 2026 Tempesta Technologies, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later

import asyncio
import logging
import random
import time
from typing import Union

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
from framework.utils import get_tcp_packet, run_in_background
from framework.xfw import XFW

SynStats = tuple[int, int, int]
StatsExpectation = tuple[
    Union[int, tuple[int, int]], Union[int, tuple[int, int]], Union[int, tuple[int, int]]
]
bad_packet = TCP(flags="S")
ok_packet = TCP(
    flags="S",
    window=6420,
    seq=32513451,
    options=[
        ("MSS", 1460),
    ],
)


def cmp_stats(value: int, expected: Union[int, tuple[int, int]]) -> bool:
    if isinstance(expected, int):
        return value == expected

    return expected[0] <= value <= expected[1]


def check_stats(
    logger: logging.Logger,
    stats_before: SynStats,
    stats_after: SynStats,
    expectation: StatsExpectation,
):
    syn_cookies_sent = stats_after[0] - stats_before[0]
    logger.info(f"sent={syn_cookies_sent}")
    assert cmp_stats(syn_cookies_sent, expectation[0]), "SynCookieSent is different"

    syn_cookies_recv = stats_after[1] - stats_before[1]
    logger.info(f"recv={syn_cookies_recv}")
    assert cmp_stats(syn_cookies_recv, expectation[1]), "SynCookieRcv is different"

    # for fails we check for <=, because (as I understand) kernel do not increase
    # this counter without tcp syn overflow even if net.ipv4.tcp_syncookies=2
    # so beginning of flood would not be counted
    syn_cookies_fail = stats_after[2] - stats_before[2]
    logger.info(f"fail={syn_cookies_fail}")
    assert cmp_stats(syn_cookies_fail, expectation[2]), "SynCookieFail is different"


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
        return await asyncio.gather(
            self._send_requests(packet=packet, amount=amount, duration=duration),
            self._read_replies(),
        )

    async def flood_handshake(self, amount: int, duration: int):
        """
        Try to make unique 3-step handshake 1000 times from the same
        client
        """

        counter = 0
        sleep_time = duration / amount

        while counter < amount:
            await asyncio.sleep(sleep_time)
            counter += 1
            packet = TCP(
                flags="S",
                seq=random.randrange(1, 9999999),
                window=64240,
                options=(("MSS", 1460),),
            )
            await self.send_packet(packet)

            response = await super().receive_packet()

            # probably, the server can answer with rst or something else,
            # we skip such situations and register them as complete
            if not response:
                continue

            if not self.has_flag(response, "SA"):
                continue

            self.ack -= 1
            await self.send_packet(TCP(flags="A"))


class TcpRawSynCookieIpv4Client(TcpRawSynCookieClient, TcpIpV4RawClient):
    def __init__(self, *args, **kwargs):
        TcpRawSynCookieClient.__init__(self, *args, **kwargs)
        TcpIpV4RawClient.__init__(self, *args, **kwargs)


class TcpRawSynCookieIpv6Client(TcpRawSynCookieClient, TcpIpV6RawClient):
    def __init__(self, *args, **kwargs):
        TcpRawSynCookieClient.__init__(self, *args, **kwargs)
        TcpIpV6RawClient.__init__(self, *args, **kwargs)


@pytest.fixture
async def tcp_ip4_raw_syncookie_client(config: ConfigSettings, logging_level: int) -> TcpServer:
    client = client_fabric(
        logging_level=logging_level,
        config=config,
        local_class=TcpRawSynCookieIpv4Client,
    )
    yield client
    await client.stop()


@pytest.fixture
async def tcp_ip6_raw_syncookie_client(config: ConfigSettings, logging_level) -> TcpServer:
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
async def xfw_with_forced_syncookie(xfw: XFW) -> XFW:
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
) -> list[TcpRawSynCookieClient]:
    clients: list[TcpRawClient] = client_cloner(
        cloner=tcp_syncookie_client,
        amount=2,
    )

    for client in clients:
        client.auto_ack_seq = False
        client.filter_packets = False
        client.log_requests = False
        await client.start()

    yield clients

    for client in clients:
        await client.stop()


@pytest.mark.skip("ISSUE: 470")
@pytest.mark.parametrize(
    "tcp_syncookies_parameter",
    [
        pytest.param("flood_timer=0 passive_timer=0", id="default"),
        pytest.param("flood_timer=1", id="flood"),
        pytest.param("passive_timer=1", id="passive"),
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

    # it's required to have a unique client
    # because syncookie is issues on 4-tuple
    tcp_raw_client.port = random.randrange(1, 65000)

    # STAGE 1: Connection
    stats_before = await xfw_with_forced_syncookie.syncookies_read_stats()
    assert await tcp_raw_client.handshake() is True
    stats_after = await xfw_with_forced_syncookie.syncookies_read_stats()

    # 1 cookie issued by the server and 1 OK receive from client
    assert stats_after[0] == stats_before[0] + 1
    assert stats_after[1] == stats_before[1] + 1
    assert stats_after[2] == stats_before[2]

    # STAGE 2: Send data
    stats_before = await xfw_with_forced_syncookie.syncookies_read_stats()
    await tcp_raw_client.send_packet(TCP(flags="PA") / b"hello")

    answer = await tcp_raw_client.receive_packet()
    assert answer is not None
    assert tcp_raw_client.has_flag(answer, "A")

    stats_after = await xfw_with_forced_syncookie.syncookies_read_stats()

    # nothing changes
    assert stats_after[0] == stats_before[0]
    assert stats_after[1] == stats_before[1]
    assert stats_after[2] == stats_before[2]

    # STAGE 3: Disconnecting
    stats_before = await xfw_with_forced_syncookie.syncookies_read_stats()

    assert await tcp_raw_client.close_connection() is True
    stats_after = await xfw_with_forced_syncookie.syncookies_read_stats()

    # nothing changes
    assert stats_after[0] == stats_before[0]
    assert stats_after[1] == stats_before[1]
    assert stats_after[2] == stats_before[2]


@pytest.mark.skip("ISSUE: 470")
@pytest.mark.parametrize(
    "tcp_options",
    [
        pytest.param(
            [
                ("MSS", 1460),
                ("SAckOK", b""),
                ("Timestamp", (4294693388, 0)),
                ("NOP", None),
                ("WScale", 6),
            ],
            id="full-house",
        ),
        pytest.param(
            [("MSS", 1460), ("SAckOK", b""), ("Timestamp", (4294693388, 0)), ("NOP", None)],
            id="mss+sackok+ts+nop",
        ),
        pytest.param(
            [("MSS", 1460), ("SAckOK", b""), ("Timestamp", (4294693388, 0))], id="mss+sackok+ts"
        ),
        pytest.param([("MSS", 1460), ("SAckOK", b"")], id="mss+sackok"),
        pytest.param([("MSS", 1460)], id="mss"),
        pytest.param(
            [], id="empty", marks=pytest.mark.xfail(reason="no options is not allowed at all")
        ),
    ],
)
async def test_syncookie_with_options(
    tcp_options: list[tuple],
    xfw_with_forced_syncookie: XFW,
    tcp_server: TcpServer,
    tcp_raw_client: TcpRawClient,
    start_tcp_server_and_raw_clients,
):
    tcp_packet = get_tcp_packet(flag="S", options=tcp_options)

    await xfw_with_forced_syncookie.syncookies_value_set(2)
    await xfw_with_forced_syncookie.rules_set(
        f"xfw {{ tcp_syncookies flood_timer=0 passive_timer=0; }}"
    )

    # it's required to have a unique client
    # because syncookie is issues on 4-tuple
    tcp_raw_client.port = random.randrange(1, 65000)

    stats_before = await xfw_with_forced_syncookie.syncookies_read_stats()

    assert await tcp_raw_client.handshake(tcp_packet) is True
    assert await tcp_raw_client.close_connection() is True
    stats_after = await xfw_with_forced_syncookie.syncookies_read_stats()

    # 1 cookie issued by the server and 1 OK receive from client
    assert stats_after[0] == stats_before[0] + 1
    assert stats_after[1] == stats_before[1] + 1
    assert stats_after[2] == stats_before[2]


@pytest.mark.skip("ISSUE: 470")
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

    # As XFW requests the kernel whether syncookie should be
    # issued, we "patch" the kernel response with forced
    # set sysctl flag. Now, kernel always replies on !!! XFW REQUEST POSITIVE !!!
    # That is immitation of syn-flood attack
    await xfw_with_forced_syncookie.syncookies_always()
    await xfw_with_forced_syncookie.rules_set(
        f"xfw {{ tcp_syncookies flood_timer={flood_timer}; }}"
    )

    # On the handshake the Send and Recv cookie should be increased
    stats_before = await xfw_with_forced_syncookie.syncookies_read_stats()
    assert await tcp_raw_client.handshake() is True
    assert await tcp_raw_client.close_connection() is True
    stats_after = await xfw_with_forced_syncookie.syncookies_read_stats()
    assert stats_after[0] == stats_before[0] + 1
    assert stats_after[1] == stats_before[1] + 1
    assert stats_after[2] == stats_before[2]

    # wait until flood_timer first loop expires.
    # We don't change the sysctl syncookie value, so
    # the flood attack is continue going
    middle_of_flood_timer_loop = flood_timer / 2
    await asyncio.sleep(flood_timer + middle_of_flood_timer_loop)

    stats_before = await xfw_with_forced_syncookie.syncookies_read_stats()
    assert await tcp_raw_client.handshake() is True
    assert await tcp_raw_client.close_connection() is True
    stats_after = await xfw_with_forced_syncookie.syncookies_read_stats()
    assert stats_after[0] == stats_before[0] + 1
    assert stats_after[1] == stats_before[1] + 1
    assert stats_after[2] == stats_before[2]

    # turn off the kernel syncookie and wait
    # until second loop finishes. Now, we assume that syn-flood
    # attack is started and non syn-cookies should be issued
    await xfw_with_forced_syncookie.syncookies_never()
    await asyncio.sleep(flood_timer)

    stats_before = await xfw_with_forced_syncookie.syncookies_read_stats()
    assert await tcp_raw_client.handshake() is True
    assert await tcp_raw_client.close_connection() is True
    stats_after = await xfw_with_forced_syncookie.syncookies_read_stats()
    assert stats_after[0] == stats_before[0]
    assert stats_after[1] == stats_before[1]
    assert stats_after[2] == stats_before[2]

    # let's turn on the kernel syncookie again
    # and check that syncookie works again
    await xfw_with_forced_syncookie.syncookies_always()
    await asyncio.sleep(flood_timer)

    stats_before = await xfw_with_forced_syncookie.syncookies_read_stats()
    assert await tcp_raw_client.handshake() is True
    assert await tcp_raw_client.close_connection() is True
    stats_after = await xfw_with_forced_syncookie.syncookies_read_stats()
    assert stats_after[0] == stats_before[0] + 1
    assert stats_after[1] == stats_before[1] + 1
    assert stats_after[2] == stats_before[2]


@pytest.mark.skip("ISSUE: 470")
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
        f"xfw {{ tcp_syncookies passive_timer={passive_timer}; }}"
    )

    # As we in the passive_mode, no syncookies should be issued
    stats_before = await xfw_with_forced_syncookie.syncookies_read_stats()
    assert await tcp_raw_client.handshake() is True
    assert await tcp_raw_client.close_connection() is True
    stats_after = await xfw_with_forced_syncookie.syncookies_read_stats()
    assert stats_after[0] == stats_before[0]
    assert stats_after[1] == stats_before[1]
    assert stats_after[2] == stats_before[2]

    # wait until passive_timer first loop expires.
    # We don't change the sysctl syncookie value, so
    # we still don't have any anomalies
    middle_of_passive_timer_loop = passive_timer / 2
    await asyncio.sleep(passive_timer + middle_of_passive_timer_loop)

    stats_before = await xfw_with_forced_syncookie.syncookies_read_stats()
    assert await tcp_raw_client.handshake() is True
    assert await tcp_raw_client.close_connection() is True
    stats_after = await xfw_with_forced_syncookie.syncookies_read_stats()
    assert stats_after[0] == stats_before[0]
    assert stats_after[1] == stats_before[1]
    assert stats_after[2] == stats_before[2]

    # turn on the kernel syncookie and wait until
    # second loop finishes. Now, we assume that syn-flood
    # attack is started and syn-cookies should be issued

    await xfw_with_forced_syncookie.syncookies_always()
    await asyncio.sleep(passive_timer)

    stats_before = await xfw_with_forced_syncookie.syncookies_read_stats()
    assert await tcp_raw_client.handshake() is True
    assert await tcp_raw_client.close_connection() is True
    stats_after = await xfw_with_forced_syncookie.syncookies_read_stats()
    assert stats_after[0] == stats_before[0] + 1
    assert stats_after[1] == stats_before[1] + 1
    assert stats_after[2] == stats_before[2]

    # let's turn off the kernel syncookie again
    # and check that syncookie disabled again
    await xfw_with_forced_syncookie.syncookies_never()
    await asyncio.sleep(passive_timer)

    stats_before = await xfw_with_forced_syncookie.syncookies_read_stats()
    assert await tcp_raw_client.handshake() is True
    assert await tcp_raw_client.close_connection() is True
    stats_after = await xfw_with_forced_syncookie.syncookies_read_stats()
    assert stats_after[0] == stats_before[0]
    assert stats_after[1] == stats_before[1]
    assert stats_after[2] == stats_before[2]


@pytest.mark.skip("ISSUE: 470")
@pytest.mark.parametrize(
    "option,packets_amount,duration,packet,sent,recv,fail",
    [
        # recv=1 - ack on handshake from normal client
        # in flood mode, xfw handles acks with broken cookies and counters don't increase
        pytest.param("flood_timer=1", 2000, 20, bad_packet, 0, 1, 0, id="flood-bad"),
        pytest.param("flood_timer=1", 2000, 20, ok_packet, 0, 1, 0, id="flood-ok-1"),
        pytest.param("flood_timer=15", 2000, 20, ok_packet, 0, 1, 0, id="flood-ok-15"),
        pytest.param("flood_timer=1000", 2000, 20, ok_packet, 0, 1, 0, id="flood-ok-1000"),
        # sent=2 client * 2000 SYN packets
        # recv=1 - ack on handshake from normal client
        pytest.param("passive_timer=1", 2000, 20, bad_packet, [3900, 4000], 1, 0, id="passive-bad"),
        pytest.param("passive_timer=1", 2000, 20, ok_packet, [3900, 4000], 1, 0, id="passive-ok-1"),
        pytest.param(
            "passive_timer=15", 2000, 20, ok_packet, [3900, 4000], 1, 0, id="passive-ok-15"
        ),
        pytest.param(
            "passive_timer=1000", 2000, 20, ok_packet, [3900, 4000], 1, 0, id="passive-ok-1000"
        ),
    ],
)
async def test_normal_connection_under_flood(
    option: str,
    packets_amount: int,
    duration: float,
    packet: TCP,
    sent: int,
    recv: int,
    fail: int,
    xfw_with_forced_syncookie: XFW,
    tcp_server: TcpServer,
    tcp_raw_client: TcpRawClient,
    start_tcp_server_and_raw_clients,
    group_of_clients: list[TcpRawSynCookieClient],
    conf_logger,
):
    await xfw_with_forced_syncookie.rules_set(f"xfw {{ tcp_syncookies {option}; }}")

    stats_before = await xfw_with_forced_syncookie.syncookies_read_stats()
    coroutines = [
        client.flood(packet=packet, amount=packets_amount, duration=duration)
        for client in group_of_clients
    ]

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

    stats_after = await xfw_with_forced_syncookie.syncookies_read_stats()
    check_stats(conf_logger, stats_before, stats_after, (sent, recv, fail))


@pytest.mark.skip("ISSUE: 470")
@pytest.mark.parametrize(
    "option,handshakes,duration,sent,recv,fail",
    [
        # recv=1 - ack on handshake from normal client
        # in flood mode, xfw handles acks with broken cookies and counters don't increase
        pytest.param("flood_timer=2", 1000, 40, 0, 1, 0, id="flood"),
        # sent=2 clients * 1000 SYN packets
        # recv=1 - ack on handshake from normal client
        # failed ~ 1000 - broken attempts to finished handshake.
        #      Depends on machine speed (locally about 1200, on server about 1600)
        pytest.param("passive_timer=5", 1000, 40, [1900, 2000], 1, [1000, 2000], id="passive"),
    ],
)
async def test_normal_connection_under_handshake_flood(
    option: str,
    handshakes: int,
    duration: int,
    sent: int,
    recv: int,
    fail: int,
    xfw_with_forced_syncookie: XFW,
    tcp_server: TcpServer,
    tcp_raw_client: TcpRawClient,
    start_tcp_server_and_raw_clients,
    group_of_clients: list[TcpRawSynCookieClient],
    conf_logger,
):
    await xfw_with_forced_syncookie.rules_set(f"xfw {{ tcp_syncookies {option}; }}")

    stats_before = await xfw_with_forced_syncookie.syncookies_read_stats()

    coroutines = [
        client.flood_handshake(amount=handshakes, duration=duration) for client in group_of_clients
    ]
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

    stats_after = await xfw_with_forced_syncookie.syncookies_read_stats()
    check_stats(conf_logger, stats_before, stats_after, (sent, recv, fail))


@pytest.mark.skip("ISSUE: 470")
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
    stats_before = await xfw_with_forced_syncookie.syncookies_read_stats()

    start_time = time.time()
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

    assert time.time() - start_time < 50, "Haven't finished all syns in time"

    stats_after = await xfw_with_forced_syncookie.syncookies_read_stats()

    # 0 sent (because kernel generated nothing),
    # 1 recved from normal client,
    # 0 failed (because xfw in flood mode handles acks)
    check_stats(conf_logger, stats_before, stats_after, (0, 1, 0))

    await xfw_with_forced_syncookie.syncookies_value_set(0)
    stats_before = await xfw_with_forced_syncookie.syncookies_read_stats()

    # wait till xfw leave flood mode (passive timer expires)
    await asyncio.sleep(time.time() - start_time + flood_timer)

    # ENTERING PASSIVE MODE
    # no syncookies should be issued now (stats are not affected)
    # according to kernel answer, xfw should turn to passive mode
    await tcp_raw_client.handshake()
    await tcp_raw_client.close_connection()

    # make kernel answer that cookies are necessary,
    # however, in passive mode xfw should not ask kernel for new cookies
    await xfw_with_forced_syncookie.syncookies_value_set(2)

    # passive timer hasn't expired yet, so we should not issue any syncookies
    start_time = time.time()
    coroutines = [
        client.flood_handshake(amount=handshakes_amount, duration=duration_sec)
        for client in group_of_clients
    ]

    tasks = [asyncio.create_task(coro) for coro in coroutines]

    await asyncio.sleep(duration_sec / 2)

    await tcp_raw_client.handshake()
    await tcp_raw_client.close_connection()

    await asyncio.gather(*tasks)
    assert time.time() - start_time < 100, "Haven't finished all syns in time"

    expected_total = handshakes_amount * len(group_of_clients)

    stats_after = await xfw_with_forced_syncookie.syncookies_read_stats()

    # ~1200 sent
    # 1 recved from normal client,
    # ~1200 failed
    # because we entered passive mode for 1000 seconds, kernel issues all cookies
    # it does not equal 2000, because kernel need some time to be activated
    check_stats(
        logger=conf_logger,
        stats_before=stats_before,
        stats_after=stats_after,
        expectation=(
            (expected_total / 2, expected_total + 1),
            1,
            (expected_total / 2, expected_total + 1),
        ),
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
