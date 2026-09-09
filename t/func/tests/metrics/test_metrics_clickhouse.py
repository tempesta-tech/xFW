# SPDX-FileCopyrightText: (c) 2026 Tempesta Technologies, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later
import asyncio
import struct
from typing import Callable

import pytest
from dnslib import DNSRecord
from scapy.layers.inet import TCP, UDP

from framework.metrics import ClickhouseSingleMetric
from framework.utils import get_tcp_packet
from tests.metrics.utils import DnsRequests


@pytest.mark.parametrize(
    "xfw_setup, expected_metric, blocking_packet",
    [
        pytest.param(
            "xfw_blocked_by_tcp_flags_syn",
            ClickhouseSingleMetric.blocked_by_tcp_flags_syn_ratelimit,
            TCP(flags="S"),
            id="blocked-by-tcp-flags-syn-1-bit",
        ),
        pytest.param(
            "xfw_blocked_by_tcp_flags_rst",
            ClickhouseSingleMetric.blocked_by_tcp_flags_rst_ratelimit,
            TCP(flags="R"),
            id="blocked-by-tcp-flags-rst-2-bit",
        ),
    ],
    indirect=["xfw_setup"],
)
async def test_tcp_flags(
    xfw_setup,
    expected_metric: Callable,
    blocking_packet: TCP,
    xfw,
    tcp_raw_client,
    tcp_raw_server,
    clickhouse_client,
    metric_analyzer,
):
    await clickhouse_client.connect()
    await tcp_raw_server.start()
    await tcp_raw_client.start()

    async with metric_analyzer.track_clickhouse_metric(
        clickhouse_client, ip_to_search=tcp_raw_client.ip_clickhouse
    ) as metric:
        await tcp_raw_client.send_packet(blocking_packet)
        assert await tcp_raw_server.receive_block()

    assert expected_metric(metric)


@pytest.mark.parametrize(
    "xfw_setup, expected_metric",
    [
        pytest.param(
            "xfw_blocked_by_icmp",
            ClickhouseSingleMetric.blocked_by_icmp_block,
            id="blocked-by-icmp-0-bit",
        ),
        pytest.param(
            "xfw_blocked_by_icmp_ratelimit",
            ClickhouseSingleMetric.blocked_by_icmp_ratelimit,
            id="blocked-by-icmp-ratelimit-3-bit",
        ),
        pytest.param(
            "xfw_blocked_by_icmp_defaults",
            ClickhouseSingleMetric.blocked_by_defaults_icmp_block,
            id="blocked-by-icmp-defaults-4-bit",
        ),
        pytest.param(
            "xfw_blocked_by_icmp_defaults_ratelimit",
            ClickhouseSingleMetric.blocked_by_defaults_icmp_ratelimit,
            id="blocked-by-icmp-defaults-ratelimit-5-bit",
        ),
    ],
    indirect=["xfw_setup"],
)
async def test_icmp(
    xfw_setup,
    expected_metric: Callable,
    xfw,
    icmp_raw_client,
    udp_server,
    clickhouse_client,
    metric_analyzer,
):
    await udp_server.start()
    await icmp_raw_client.start()
    await clickhouse_client.connect()

    async with metric_analyzer.track_clickhouse_metric(
        clickhouse_client, ip_to_search=icmp_raw_client.ip_clickhouse
    ) as metric:
        await icmp_raw_client.ping()
        assert await icmp_raw_client.pong() is False

    assert expected_metric(metric)


@pytest.mark.parametrize(
    "xfw_setup, expected_metric",
    [
        pytest.param(
            "xfw_blocked_by_dst",
            ClickhouseSingleMetric.blocked_by_dst_block,
            id="blocked-by-dst-6-bit",
        ),
        pytest.param(
            "xfw_blocked_by_dst_ratelimit",
            ClickhouseSingleMetric.rate_limited_by_dst_ratelimit,
            id="blocked-by-dst-ratelimit-7-bit",
        ),
    ],
    indirect=["xfw_setup"],
)
async def test_dst(
    xfw_setup, expected_metric: Callable, xfw, client, server, clickhouse_client, metric_analyzer
):
    await clickhouse_client.connect()

    async with metric_analyzer.track_clickhouse_metric(
        clickhouse_client, ip_to_search=client.ip_clickhouse
    ) as metric:
        await client.ping()
        assert await server.receive_block()

    assert expected_metric(metric)


@pytest.mark.parametrize(
    "xfw_setup, expected_metric",
    [
        pytest.param(
            "xfw_blocked_by_src_port",
            ClickhouseSingleMetric.blocked_by_src_port_block,
            id="blocked-by-src-port-8-bit",
        ),
        pytest.param(
            "xfw_ratelimit_by_src_port",
            ClickhouseSingleMetric.rate_limited_by_src_port_ratelimit,
            id="ratelimit-by-src-port-9-bit",
        ),
        pytest.param(
            "xfw_blocked_by_src_port_defaults",
            ClickhouseSingleMetric.blocked_by_defaults_src_port_block,
            id="blocked-by-src-port-defaults-10-bit",
        ),
        pytest.param(
            "xfw_ratelimit_by_src_port_defaults",
            ClickhouseSingleMetric.rate_limited_by_defaults_src_port_ratelimit,
            id="ratelimit-by-src-port-defaults-11-bit",
        ),
        pytest.param(
            "xfw_blocked_by_src_ip",
            ClickhouseSingleMetric.blocked_by_src_ip_block,
            id="blocked-by-src-ip-12-bit",
        ),
        pytest.param(
            "xfw_ratelimit_by_src_ip",
            ClickhouseSingleMetric.rate_limited_by_src_ip_ratelimit,
            id="ratelimit-by-src-ip-13-bit",
        ),
        pytest.param(
            "xfw_blocked_by_src_ip_defaults",
            ClickhouseSingleMetric.blocked_by_defaults_src_ip_block,
            id="blocked-by-src-ip-defaults-14-bit",
        ),
        pytest.param(
            "xfw_ratelimit_by_src_ip_defaults",
            ClickhouseSingleMetric.rate_limited_by_defaults_src_ip_ratelimit,
            id="ratelimit-by-src-ip-defaults-15-bit",
        ),
    ],
    indirect=["xfw_setup"],
)
async def test_src(
    xfw_setup, expected_metric: Callable, xfw, client, server, clickhouse_client, metric_analyzer
):
    await clickhouse_client.connect()

    async with metric_analyzer.track_clickhouse_metric(
        clickhouse_client, ip_to_search=client.ip_clickhouse
    ) as metric:
        await client.ping()
        assert await server.receive_block()

    assert expected_metric(metric)


@pytest.mark.parametrize(
    "xfw_setup, expected_metric, blocking_packet",
    [
        pytest.param(
            "xfw_blocked_by_tcp_anomaly_invalid_flags",
            ClickhouseSingleMetric.blocked_by_tcp_anomaly_invalid_flags,
            get_tcp_packet(flag="SF"),
            id="blocked-by-tcp-anomaly-invalid-flags-16-bit",
        ),
        pytest.param(
            "xfw_blocked_by_tcp_anomaly_invalid_syn_seq",
            ClickhouseSingleMetric.blocked_by_tcp_anomaly_invalid_syn_sequence_number,
            get_tcp_packet(flag="S", seq=0),
            id="blocked-by-tcp-anomaly-invalid-syn-seq-17-bit",
        ),
        pytest.param(
            "xfw_blocked_by_tcp_anomaly_syn_without_options",
            ClickhouseSingleMetric.blocked_by_tcp_anomaly_syn_without_tcp_options,
            get_tcp_packet(flag="S", options=[]),
            id="blocked-by-tcp-anomaly-syn-without-options-18-bit",
        ),
        pytest.param(
            "xfw_blocked_by_tcp_anomaly_syn_with_payload",
            ClickhouseSingleMetric.blocked_by_tcp_anomaly_syn_packet_with_payload,
            get_tcp_packet(flag="S", payload=b"1"),
            id="blocked-by-tcp-anomaly-syn-with-payload-19-bit",
        ),
    ],
    indirect=["xfw_setup"],
)
async def test_tcp_anomaly(
    xfw_setup,
    expected_metric: Callable,
    blocking_packet: TCP,
    xfw,
    tcp_raw_client,
    tcp_raw_server,
    clickhouse_client,
    metric_analyzer,
):
    await clickhouse_client.connect()
    await tcp_raw_server.start()
    await tcp_raw_client.start()

    async with metric_analyzer.track_clickhouse_metric(
        clickhouse_client, ip_to_search=tcp_raw_client.ip_clickhouse
    ) as metric:
        await tcp_raw_client.send_packet(blocking_packet)
        assert await tcp_raw_server.receive_block()

    assert expected_metric(metric)


@pytest.mark.parametrize("port_type", ["sport", "dport"], ids=["src", "dst"])
async def test_blocked_by_tcp_anomaly_zero_port_20_bit(
    port_type: str,
    xfw,
    tcp_raw_client,
    tcp_raw_server,
    clickhouse_client,
    metric_analyzer,
):
    await clickhouse_client.connect()
    await tcp_raw_server.start()
    await tcp_raw_client.start()

    tcp_raw_client.auto_add_host = False
    packet = get_tcp_packet(flag="S")
    packet.sport = tcp_raw_client.port
    packet.dport = tcp_raw_server.port
    setattr(packet, port_type, 0)

    await xfw.rules_set("xfw { tcp_anomaly_filter; }")

    async with metric_analyzer.track_clickhouse_metric(
        clickhouse_client, ip_to_search=tcp_raw_client.ip_clickhouse
    ) as metric:
        await tcp_raw_client.send_packet(packet)
        assert await tcp_raw_server.receive_block()

    assert metric.blocked_by_tcp_anomaly_zero_source_or_destination_port()


@pytest.mark.parametrize("port_type", ["sport", "dport"], ids=["src", "dst"])
async def test_blocked_by_udp_anomaly_zero_port_21_bit(
    port_type: str,
    xfw,
    udp_raw_client,
    udp_server,
    clickhouse_client,
    metric_analyzer,
):
    await clickhouse_client.connect()
    await udp_server.start()
    await udp_raw_client.start()

    udp_raw_client.auto_add_host = False
    packet = UDP()
    packet.sport = udp_raw_client.port
    packet.dport = udp_server.port
    setattr(packet, port_type, 0)

    await xfw.rules_set("xfw { }")

    async with metric_analyzer.track_clickhouse_metric(
        clickhouse_client, ip_to_search=udp_raw_client.ip_clickhouse
    ) as metric:
        await udp_raw_client.send_packet(packet / "Hello :)")
        assert await udp_server.receive_block()

    assert metric.blocked_by_udp_anomaly_zero_source_or_destination_port()


@pytest.mark.parametrize(
    "send_method, expected_metric",
    [
        pytest.param(
            "send_bad_tcp_headers",
            ClickhouseSingleMetric.blocked_during_parsing_malformed_tcp_header,
            id="blocked-during-parsing-malformed-tcp-header-28-bit",
        ),
        pytest.param(
            "send_bad_udp_headers",
            ClickhouseSingleMetric.blocked_during_parsing_malformed_udp_header,
            id="blocked-during-parsing-malformed-udp-header-29-bit",
        ),
        pytest.param(
            "send_bad_icmp_headers",
            ClickhouseSingleMetric.blocked_during_parsing_malformed_icmp_header,
            id="blocked-during-parsing-malformed-icmp-header-30-bit",
        ),
        pytest.param(
            "send_l4_unsupported_ip_proto",
            ClickhouseSingleMetric.blocked_during_parsing_unsupported_l4_protocol,
            id="blocked-during-parsing-unsupported-l4-protocol-31-bit",
        ),
    ],
)
async def test_l4_parsing(
    send_method: str,
    expected_metric: Callable,
    xfw,
    invalid_l4_raw_client,
    ether_raw_server,
    clickhouse_client,
    metric_analyzer,
):
    await clickhouse_client.connect()
    await ether_raw_server.start()
    await invalid_l4_raw_client.start()

    src_mac, dst_mac = await asyncio.gather(
        invalid_l4_raw_client.get_mac_address(), ether_raw_server.get_mac_address()
    )

    await xfw.rules_set("xfw { }")

    async with metric_analyzer.track_clickhouse_metric(
        clickhouse_client, ip_to_search=invalid_l4_raw_client.ip_clickhouse
    ) as metric:
        await getattr(invalid_l4_raw_client, send_method)(src_mac, dst_mac)

    assert expected_metric(metric)


async def test_blocked_by_tcp_auth_filter_unknown_connection_32_bit(
    xfw,
    tcp_raw_client,
    tcp_raw_server,
    clickhouse_client,
    metric_analyzer,
):
    await xfw.rules_set("xfw { tcp_auth_filter; }")

    await clickhouse_client.connect()
    await tcp_raw_server.start()
    await tcp_raw_client.start()

    async with metric_analyzer.track_clickhouse_metric(
        clickhouse_client, ip_to_search=tcp_raw_client.ip_clickhouse
    ) as metric:
        await tcp_raw_client.send_packet(TCP(flags="A"))
        assert await tcp_raw_server.receive_block()

    assert metric.blocked_by_tcp_auth_filter_unknown_connection()


@pytest.mark.long
async def test_blocked_by_tcp_auth_filter_expired_connection_33_bit(
    xfw,
    tcp_raw_client,
    tcp_raw_server,
    clickhouse_client,
    metric_analyzer,
):
    await xfw.rules_set("xfw { tcp_auth_filter; }")

    await clickhouse_client.connect()
    await tcp_raw_server.start()
    await tcp_raw_client.start()

    assert await asyncio.gather(
        tcp_raw_client.handshake(),
        tcp_raw_server.handshake(),
    ) == [True, True]

    assert await asyncio.gather(
        tcp_raw_client.close_connection(),
        tcp_raw_server.close_connection(),
    ) == [True, True]

    await asyncio.sleep(65)

    async with metric_analyzer.track_clickhouse_metric(
        clickhouse_client, ip_to_search=tcp_raw_client.ip_clickhouse
    ) as metric:
        await tcp_raw_client.send_packet(TCP(flags="P") / b"111")
        assert await tcp_raw_server.receive_packet()

    assert metric.blocked_by_tcp_auth_filter_expired_connection()


@pytest.mark.parametrize(
    "data_to_send, expected_metric",
    [
        pytest.param(
            b"\x00\x01",
            ClickhouseSingleMetric.blocked_during_parsing_malformed_dns_header,
            id="header-35-bit",
        ),
        pytest.param(
            # Valid header with QDCOUNT=1, but the question name has no terminating zero.
            struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + b"\x05" + b"a" * 5,
            ClickhouseSingleMetric.blocked_during_parsing_malformed_dns_question,
            id="question-37-bit",
        ),
    ],
)
async def test_blocked_during_parsing_malformed_dns(
    data_to_send,
    expected_metric: Callable,
    xfw,
    dns_udp_client,
    dns_udp_server,
    clickhouse_client,
    metric_analyzer,
):
    await xfw.rules_set("xfw { dns_filter; }")

    await clickhouse_client.connect()
    await dns_udp_server.start()
    await dns_udp_client.start()

    async with metric_analyzer.track_clickhouse_metric(
        clickhouse_client, ip_to_search=dns_udp_client.ip_clickhouse
    ) as metric:
        await dns_udp_client._send(data_to_send)
        assert not await dns_udp_server.receive_dns_record()

    assert expected_metric(metric)


@pytest.mark.parametrize(
    "data_to_send, expected_metric",
    [
        pytest.param(
            DnsRequests.non_zero_rcode(),
            ClickhouseSingleMetric.blocked_by_dns_anomaly_non_zero_rcode_in_dns_query,
            id="non-zero-rcode-36-bit",
        ),
        pytest.param(
            DnsRequests.more_than_one_question(),
            ClickhouseSingleMetric.blocked_by_dns_anomaly_more_than_one_question_in_dns_packet,
            id="more-than-one-question-38-bit",
        ),
        pytest.param(
            DnsRequests.answers_or_authority_sections_in_dns_query(),
            ClickhouseSingleMetric.blocked_by_dns_anomaly_answers_or_authority_sections_present_in_dns_query,
            id="answers-or-authority-in-query-39-bit",
        ),
        pytest.param(
            DnsRequests.invalid_ixfr_query(),
            ClickhouseSingleMetric.blocked_by_dns_anomaly_invalid_ixfr_query,
            id="invalid-ixfr-query-40-bit",
            marks=pytest.mark.skip("A NEW ISSUE"),
        ),
        pytest.param(
            DnsRequests.more_than_two_additional_sections(),
            ClickhouseSingleMetric.blocked_by_dns_anomaly_more_than_two_additional_sections_in_dns_query,
            id="more-than-two-additional-sections-41-bit",
        ),
    ],
)
async def test_blocked_by_dns_anomaly(
    data_to_send: DNSRecord,
    expected_metric: Callable,
    xfw,
    dns_udp_client,
    dns_udp_server,
    clickhouse_client,
    metric_analyzer,
):
    await xfw.rules_set("xfw { dns_filter; }")

    await dns_udp_server.start()
    await dns_udp_client.start()
    await clickhouse_client.connect()

    async with metric_analyzer.track_clickhouse_metric(
        clickhouse_client, ip_to_search=dns_udp_client.ip_clickhouse
    ) as metric:
        await dns_udp_client.send_query(data_to_send)
        assert not await dns_udp_server.receive_dns_record()

    assert expected_metric(metric)


@pytest.mark.skip_on_e1000
@pytest.mark.parametrize(
    "xfw_setup, server_reply_method, expected_metric",
    [
        pytest.param(
            "xfw",
            DnsRequests.reply_for_non_existing_query,
            ClickhouseSingleMetric.blocked_by_dns_anomaly_response_received_without_prior_query,
            id="response-received-without-prior-query-42-bit",
        ),
        pytest.param(
            "xfw_with_mtu_4096",
            DnsRequests.reply_with_size_bytes_4096,
            ClickhouseSingleMetric.blocked_by_dns_anomaly_dns_udp_response_packet_is_too_large,
            id="udp-response-packet-is-too-large-43-bit",
        ),
        pytest.param(
            "xfw_with_mtu_4096",
            DnsRequests.reply_with_multiple_answers_101,
            ClickhouseSingleMetric.blocked_by_dns_anomaly_dns_response_contains_too_many_answers,
            id="response-contains-too-many-answers-44-bit",
        ),
        pytest.param(
            "xfw",
            DnsRequests.reply_with_malformed_rr,
            ClickhouseSingleMetric.blocked_during_parsing_malformed_dns_resource_record,
            id="resource-record-45-bit",
        ),
        pytest.param(
            "xfw",
            DnsRequests.reply_with_ttl_0,
            ClickhouseSingleMetric.blocked_by_dns_anomaly_invalid_ttl_in_dns_answer,
            id="invalid-ttl-46-bit",
        ),
    ],
    indirect=["xfw_setup"],
)
async def test_blocked_by_dns_anomaly_server(
    xfw_setup,
    server_reply_method: Callable,
    expected_metric: Callable,
    inverted_dns_client,
    inverted_dns_server_mtu,
    clickhouse_client,
    metric_analyzer,
):
    await clickhouse_client.connect()
    await xfw_setup.rules_set("xfw { dns_filter; }")

    async with metric_analyzer.track_clickhouse_metric(
        clickhouse_client, ip_to_search=inverted_dns_server_mtu.ip_clickhouse
    ) as metric:
        await inverted_dns_client.request_dns_server()
        assert await server_reply_method(inverted_dns_server_mtu) is True
        assert not await inverted_dns_client.receive_dns_record()

    assert expected_metric(metric)
