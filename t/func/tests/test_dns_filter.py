# SPDX-FileCopyrightText: (c) 2026 Tempesta Technologies, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later

import pytest
from dnslib import NS, OPCODE, QTYPE, RCODE, RR, A, DNSRecord

from framework.asyn import DnsUdpClient, DnsUdpServer
from framework.cmp import check_connection
from framework.xfw import XFW


@pytest.fixture
async def xfw_mtu(xfw: XFW):
    """
    XFW interface with increased MTU.

    4096 is the maximum MTU that can be set on the virtual rtl8139 NIC.
    Since this NIC is used together with other interfaces, the same MTU
    must be applied to all of them.
    """
    await xfw.set_mtu(4096)
    yield xfw
    await xfw.set_mtu()


async def test_normal_connection(
    xfw: XFW,
    dns_udp_server: DnsUdpServer,
    dns_udp_client: DnsUdpClient,
    start_dns_udp_server_and_clients,
):
    await xfw.rules_set("xfw { dns_filter; }")
    assert await check_connection(dns_udp_client, dns_udp_server), "The DNS server is not allowed"


@pytest.mark.parametrize(
    "opcode",
    [
        -1,
        OPCODE.IQUERY,
        OPCODE.STATUS,
        OPCODE.NOTIFY,
        OPCODE.UPDATE,
        15,
        300,
    ],
)
async def test_skip_query_requests(
    opcode: int,
    xfw: XFW,
    dns_udp_server: DnsUdpServer,
    dns_udp_client: DnsUdpClient,
    start_dns_udp_server_and_clients,
):
    await xfw.rules_set("xfw { dns_filter; }")

    query = DNSRecord.question("google.com", qtype="A")
    query.header.rcode = RCODE.FORMERR
    query.header.opcode = opcode

    await dns_udp_client.send_query(query)
    assert (
        await dns_udp_server.receive_dns_record()
    ), "Any OPCODE != QUERY should be skipped by the XFW"


@pytest.mark.parametrize(
    "rcode",
    [
        -1,
        RCODE.FORMERR,
        RCODE.SERVFAIL,
        RCODE.NXDOMAIN,
        RCODE.NOTIMP,
        RCODE.REFUSED,
        RCODE.YXDOMAIN,
        RCODE.YXRRSET,
        RCODE.NXRRSET,
        RCODE.NOTAUTH,
        RCODE.NOTZONE,
        13,
        23,
        3500,
        # The greater codes are not blocked because of:
        # https://github.com/tempesta-tech/escudo/issues/346
        # 4000,
        65535,
    ],
)
async def test_block_invalid_rcodes(
    rcode: int,
    xfw: XFW,
    dns_udp_server: DnsUdpServer,
    dns_udp_client: DnsUdpClient,
    start_dns_udp_server_and_clients,
):
    await xfw.rules_set("xfw { dns_filter; }")

    query = DNSRecord.question("google.com", qtype="A")
    query.header.rcode = rcode

    await dns_udp_client.send_query(query)
    assert (
        not await dns_udp_server.receive_dns_record()
    ), "Any queries with RCODES except OK should be dropped by the XFW"


async def test_drop_query_with_answer(
    xfw: XFW,
    dns_udp_server: DnsUdpServer,
    dns_udp_client: DnsUdpClient,
    start_dns_udp_server_and_clients,
):
    await xfw.rules_set("xfw { dns_filter; }")

    query = DNSRecord.question("google.com", qtype="A")
    query.add_answer(RR("google.com.", ttl=300, rdata=A("1.2.3.4")))

    await dns_udp_client.send_query(query)
    assert not await dns_udp_server.receive_dns_record(), "Query with answers is not blocked"


async def test_drop_query_with_authority(
    xfw: XFW,
    dns_udp_server: DnsUdpServer,
    dns_udp_client: DnsUdpClient,
    start_dns_udp_server_and_clients,
):
    await xfw.rules_set("xfw { dns_filter; }")

    query = DNSRecord.question("google.com", qtype="A")
    query.add_auth(RR("google.com.", ttl=300, rdata=NS("ns.google.com.")))

    await dns_udp_client.send_query(query)
    assert not await dns_udp_server.receive_dns_record(), "Query with authority is not blocked"


async def test_pass_ixfr_request_without_answer_and_auth(
    xfw: XFW,
    dns_udp_server: DnsUdpServer,
    dns_udp_client: DnsUdpClient,
    start_dns_udp_server_and_clients,
):
    await xfw.rules_set("xfw { dns_filter; }")

    query = DNSRecord.question("google.com", qtype="IXFR")

    await dns_udp_client.send_query(query)
    assert (
        await dns_udp_server.receive_dns_record()
    ), "IXFR Query without authority and answer is blocked"


async def test_dont_block_ixfr_request_with_answer(
    xfw: XFW,
    dns_udp_server: DnsUdpServer,
    dns_udp_client: DnsUdpClient,
    start_dns_udp_server_and_clients,
):
    await xfw.rules_set("xfw { dns_filter; }")

    query = DNSRecord.question("google.com", qtype="IXFR")
    query.add_answer(RR("google.com.", ttl=300, rdata=A("1.2.3.4")))

    await dns_udp_client.send_query(query)
    assert await dns_udp_server.receive_dns_record(), "IXFR Query with answer is not blocked"


async def test_block_ixfr_request_with_authority(
    xfw: XFW,
    dns_udp_server: DnsUdpServer,
    dns_udp_client: DnsUdpClient,
    start_dns_udp_server_and_clients,
):
    await xfw.rules_set("xfw { dns_filter; }")

    query = DNSRecord.question("google.com", qtype="IXFR")
    query.add_auth(RR("google.com.", ttl=300, rdata=NS("ns.google.com.")))

    await dns_udp_client.send_query(query)
    assert not await dns_udp_server.receive_dns_record(), "IXFR Query with authority is not blocked"


async def test_block_ixfr_request_with_authority_and_answers(
    xfw: XFW,
    dns_udp_server: DnsUdpServer,
    dns_udp_client: DnsUdpClient,
    start_dns_udp_server_and_clients,
):
    await xfw.rules_set("xfw { dns_filter; }")

    query = DNSRecord.question("google.com", qtype="IXFR")
    query.add_auth(RR("google.com.", ttl=300, rdata=NS("ns.google.com.")))
    query.add_answer(RR("google.com.", ttl=300, rdata=A("1.2.3.4")))
    query.add_answer(RR("google.com.", ttl=300, rdata=A("1.2.3.5")))

    await dns_udp_client.send_query(query)
    assert not await dns_udp_server.receive_dns_record(), "IXFR Query with authority is not blocked"


async def test_skip_query_with_2_additional_sections(
    xfw: XFW,
    dns_udp_server: DnsUdpServer,
    dns_udp_client: DnsUdpClient,
    start_dns_udp_server_and_clients,
):
    await xfw.rules_set("xfw { dns_filter; }")

    query = DNSRecord.question("google.com", qtype="A")
    query.add_ar(RR(f"foo.bar.", rtype=QTYPE.A, rdata=A("192.0.2.1")))
    query.add_ar(RR(f"boo.bar.", rtype=QTYPE.A, rdata=A("192.0.2.2")))

    await dns_udp_client.send_query(query)
    assert await dns_udp_server.receive_dns_record(), "Query with 2 additional sections is blocked"


async def test_block_query_with_more_than_2_additional_sections(
    xfw: XFW,
    dns_udp_server: DnsUdpServer,
    dns_udp_client: DnsUdpClient,
    start_dns_udp_server_and_clients,
):
    await xfw.rules_set("xfw { dns_filter; }")

    query = DNSRecord.question("google.com", qtype="A")
    query.add_ar(RR(f"foo.bar.", rtype=QTYPE.A, rdata=A("192.0.2.1")))
    query.add_ar(RR(f"boo.bar.", rtype=QTYPE.A, rdata=A("192.0.2.2")))
    query.add_ar(RR(f"zoo.bar.", rtype=QTYPE.A, rdata=A("192.0.2.3")))

    await dns_udp_client.send_query(query)
    assert (
        not await dns_udp_server.receive_dns_record()
    ), "Query with more then 2 additional sections is not blocked"


async def test_dont_block_ixfr_query_with_more_than_2_additional_sections(
    xfw: XFW,
    dns_udp_server: DnsUdpServer,
    dns_udp_client: DnsUdpClient,
    start_dns_udp_server_and_clients,
):
    await xfw.rules_set("xfw { dns_filter; }")

    query = DNSRecord.question("google.com", qtype="IXFR")
    query.add_ar(RR(f"foo.bar.", rtype=QTYPE.A, rdata=A("192.0.2.1")))
    query.add_ar(RR(f"boo.bar.", rtype=QTYPE.A, rdata=A("192.0.2.2")))
    query.add_ar(RR(f"zoo.bar.", rtype=QTYPE.A, rdata=A("192.0.2.3")))

    await dns_udp_client.send_query(query)
    assert (
        await dns_udp_server.receive_dns_record()
    ), "IXFR Query with more than 2 additional sections is blocked"


@pytest.fixture
async def new_dns_server(
    dns_udp_client: DnsUdpClient,
) -> DnsUdpClient:
    """
    The swapping of client and server roles is required
    by XFW protection mode. In the tests, the application
    protected by XFW is the **Client**.

    In the DNS scenario, the client sends requests to the
    DNS server, while XFW protects the client from anomalous
    traffic, including attacks with spoofed IP addresses.

    In our test setup, `UdpDnsClient` therefore becomes the
    simulated DNS server (it replies to requests), and
    `UdpDnsServer` becomes the client (it initiates requests).
    This role reversal is intentional.

    The same logic applies to `new_dns_server_mtu` and
    `new_dns_client`.
    """
    dns_udp_client.port = 53
    dns_udp_client.remote_port = 50_000
    await dns_udp_client.start()
    yield dns_udp_client


@pytest.fixture
async def new_dns_server_mtu(new_dns_server: DnsUdpClient) -> DnsUdpClient:
    await new_dns_server.set_mtu(4096)
    yield new_dns_server
    await new_dns_server.set_mtu()


@pytest.fixture
async def new_dns_client(
    dns_udp_server: DnsUdpServer, new_dns_server: DnsUdpServer
) -> DnsUdpServer:
    await dns_udp_server.update_config(
        client_ip=new_dns_server.ip, client_port=new_dns_server.port, my_port=50_000
    )
    await dns_udp_server.set_mtu(4096)
    await dns_udp_server.start()
    yield dns_udp_server


async def test_normal_request_response(
    xfw: XFW,
    new_dns_client: DnsUdpServer,
    new_dns_server: DnsUdpClient,
):
    await xfw.rules_set("xfw { dns_filter; }")

    await new_dns_client.request_dns_server()
    assert await new_dns_server.receive_dns_record(), "DNS client did not receive request"


async def test_reply_on_unexisting_queries_with_dns_filter_off_is_allowed(
    new_dns_client: DnsUdpServer, new_dns_server: DnsUdpClient
):
    await new_dns_client.request_dns_server()
    assert (
        await new_dns_server.reply_for_non_existing_query() is True
    ), "DNS client did not receive request"

    assert (
        await new_dns_client.receive_dns_record()
    ), "Server did not receive answer on unexisting query"


async def test_reply_on_unexisting_query_is_blocked(
    xfw: XFW,
    new_dns_client: DnsUdpServer,
    new_dns_server: DnsUdpClient,
):
    await xfw.rules_set("xfw { dns_filter; }")

    await new_dns_client.request_dns_server()
    assert (
        await new_dns_server.reply_for_non_existing_query() is True
    ), "DNS client did not receive request"

    assert (
        not await new_dns_client.receive_dns_record()
    ), "Server receive answer on unexisting query"


@pytest.mark.parametrize(
    "size,reply_blocked",
    [
        (100, False),
        (1024, False),
        (2048, False),
        (4096, True),
        (8192, True),
    ],
)
@pytest.mark.skip_on_e1000
async def test_block_reply_with_size(
    size: int,
    reply_blocked: bool,
    xfw_mtu: XFW,
    new_dns_client: DnsUdpServer,
    new_dns_server_mtu: DnsUdpClient,
):
    """
    This test requires non-standard MTU both for
    XFW and Client interfaces
    """
    await xfw_mtu.rules_set("xfw { dns_filter; }")

    await new_dns_client.request_dns_server()
    assert (
        await new_dns_server_mtu.reply_with_size_bytes(size) is True
    ), "DNS client did not receive request"

    if reply_blocked:
        assert not await new_dns_client.receive_dns_record(), "Server answer is not blocked"
    else:
        assert await new_dns_client.receive_dns_record(), "Server answer is blocked"


@pytest.mark.parametrize(
    "answers,reply_blocked",
    [
        (10, False),
        (65, False),
        (99, False),
        (100, False),
        (101, True),
    ],
)
@pytest.mark.skip_on_e1000
async def test_block_or_skip_reply_with_multiple_answers(
    answers: int,
    reply_blocked: bool,
    xfw_mtu: XFW,
    new_dns_client: DnsUdpServer,
    new_dns_server_mtu: DnsUdpClient,
):
    """
    This test requires non-standard MTU both for
    XFW and Client interfaces
    """
    await xfw_mtu.rules_set("xfw { dns_filter; }")

    await new_dns_client.request_dns_server()
    assert (
        await new_dns_server_mtu.reply_with_multiple_answers(answers) is True
    ), "DNS client did not receive request"

    if reply_blocked:
        assert not await new_dns_client.receive_dns_record(), "Server answer is not blocked"
    else:
        assert await new_dns_client.receive_dns_record(), "Server answer is blocked"


@pytest.mark.parametrize(
    "ttl,reply_blocked", [(1, False), (1000, False), (604800, False), (0, True), (604801, True)]
)
@pytest.mark.skip_on_e1000
async def test_block_or_skip_by_ttl(
    ttl: int,
    reply_blocked: bool,
    xfw: XFW,
    new_dns_client: DnsUdpServer,
    new_dns_server: DnsUdpClient,
):
    await xfw.rules_set("xfw { dns_filter; }")

    await new_dns_client.request_dns_server()
    assert await new_dns_server.reply_with_ttl(ttl) is True, "DNS client did not receive request"

    if reply_blocked:
        assert not await new_dns_client.receive_dns_record(), "Server answer is not blocked"
    else:
        assert await new_dns_client.receive_dns_record(), "Server answer is blocked"
