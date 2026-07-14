# SPDX-FileCopyrightText: (c) 2026 Tempesta Technologies, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later

import asyncio

import pytest
from scapy.layers.inet import TCP, UDP

from framework.asyn import (
    IcmpRawClient,
    TcpIpV4RawClient,
    TcpIpV4RawServer,
    TcpRawClient,
    TcpRawServer,
    UdpClient,
    UdpRawClient,
    UdpServer,
)
from framework.clickhouse import ClickhouseClient
from framework.cmp import check_connection
from framework.stateful import RegularKernelSocketNetworkStateful
from framework.utils import metrics_increased
from framework.xfw import XFW


@pytest.mark.skip("ISSUE: 40(xFW)")
async def test_dst_block(
    xfw: XFW,
    protocol: str,
    ip_version: str,
    server: RegularKernelSocketNetworkStateful,
    client: RegularKernelSocketNetworkStateful,
    dst_defaults: str,
    establish_connection,
):
    new_ip = server.generate_new_address()

    await xfw.rules_set(f"""
        xfw {{
            evaluation_mode;
            defaults {{ dst: {dst_defaults}; }}
            dst {ip_version}.{protocol} : block {{
                {server.ip_testing}:{server.port}
                {server.ip_format(new_ip)}:{server.port}
            }}
        }}
        """)

    metrics = ["xfw_dst_blocked_packets", "xfw_dst_blocked_bytes"]

    async with xfw.metrics_diff(metrics) as diff_metrics:
        assert (
            await check_connection(client, server) is True
        ), f"Server ({server.ip_testing}:{server.port}) is blocked"

    assert metrics_increased(metrics, diff_metrics) is True


@pytest.mark.skip("ISSUE: 40(xFW)")
async def test_dst_add(
    xfw: XFW,
    protocol: str,
    ip_version: str,
    server: RegularKernelSocketNetworkStateful,
    client: RegularKernelSocketNetworkStateful,
    dst_defaults: str,
    establish_connection,
):
    new_ip = server.generate_new_address()

    await xfw.rules_set(f"""
        xfw {{
            evaluation_mode;
            defaults {{ dst: {dst_defaults}; }}
            dst=extended_group {ip_version}.{protocol} : block {{
                {server.ip_format(new_ip)}:{server.port}
            }}
        }}
        """)
    await xfw.rules_patch(f"""
        xfw {{
            dst=extended_group/add {ip_version}.{protocol} {{
                {server.ip_testing}:{server.port}
            }}
        }}
        """)
    metrics = ["xfw_dst_blocked_packets", "xfw_dst_blocked_bytes"]

    async with xfw.metrics_diff(metrics) as diff_metrics:
        assert (
            await check_connection(client, server) is True
        ), f"Server ({server.ip_testing}:{server.port}) is blocked"

    assert metrics_increased(metrics, diff_metrics) is True


@pytest.mark.skip("ISSUE: 40(xFW)")
async def test_dst_del_block_by_ip(
    xfw: XFW,
    protocol: str,
    ip_version: str,
    server: RegularKernelSocketNetworkStateful,
    client: RegularKernelSocketNetworkStateful,
    establish_connection,
):
    new_ip = server.generate_new_address()

    await xfw.rules_set(f"""
        xfw {{
            evaluation_mode;
            defaults {{ dst: block; }}
            dst=extended_group {ip_version}.{protocol} : block {{
                {server.ip_format(new_ip)}:{server.port},
                {server.ip_testing}:{server.port},
            }}
        }}
        """)
    await xfw.rules_patch(f"""
        xfw {{
            dst=extended_group/del {ip_version}.{protocol} {{
                {server.ip_format(new_ip)}:{server.port},
            }}
        }}
        """)

    metrics = ["xfw_dst_blocked_packets", "xfw_dst_blocked_bytes"]

    async with xfw.metrics_diff(metrics) as diff_metrics:
        assert (
            await check_connection(client, server) is True
        ), f"Server ({server.ip_testing}:{server.port}) is blocked"

    assert metrics_increased(metrics, diff_metrics) is True


@pytest.mark.skip("ISSUE: 40(xFW)")
async def test_src_block_by_ip(
    xfw: XFW,
    protocol: str,
    ip_version: str,
    server: RegularKernelSocketNetworkStateful,
    client: RegularKernelSocketNetworkStateful,
    establish_connection: str,
):
    await xfw.rules_set(f"""
        xfw {{
            evaluation_mode;
            defaults {{ src_ip {ip_version}: block; }}
            src=extended_group {ip_version}.{protocol} : block {{
                {client.ip_testing}
            }}
        }}
        """)
    metrics = ["xfw_src_ip_blocked_packets", "xfw_src_ip_blocked_bytes"]

    async with xfw.metrics_diff(metrics) as diff_metrics:
        assert (
            await check_connection(client, server) is True
        ), f"Server ({server.ip_testing}:{server.port}) is blocked"

    assert metrics_increased(metrics, diff_metrics) is True


@pytest.mark.skip("ISSUE: 40(xFW)")
async def test_src_del_block_by_ip(
    xfw: XFW,
    protocol: str,
    ip_version: str,
    server: RegularKernelSocketNetworkStateful,
    client: RegularKernelSocketNetworkStateful,
    establish_connection,
):
    new_ip = server.generate_new_address()

    await xfw.rules_set(f"""
        xfw {{
            evaluation_mode;
            src=extended_group {ip_version}.{protocol} : block {{
                {client.ip_format(new_ip)}, 
                {client.ip_testing}
            }}
        }}
        """)
    await xfw.rules_patch(f"""
        xfw {{
            src=extended_group/del {ip_version}.{protocol} {{
                {client.ip_format(new_ip)}, 
            }}
        }}
        """)
    metrics = ["xfw_src_ip_blocked_packets", "xfw_src_ip_blocked_bytes"]

    async with xfw.metrics_diff(metrics) as diff_metrics:
        assert (
            await check_connection(client, server) is True
        ), f"Server ({server.ip_testing}:{server.port}) is blocked"

    assert metrics_increased(metrics, diff_metrics) is True


@pytest.mark.skip("ISSUE: 40(xFW)")
async def test_src_replace_block_by_ip_to_allow_by_ip(
    xfw: XFW,
    protocol: str,
    ip_version: str,
    server: RegularKernelSocketNetworkStateful,
    client: RegularKernelSocketNetworkStateful,
    establish_connection,
):
    await xfw.rules_set(f"""
        xfw {{
            evaluation_mode;
            defaults {{ src_ip {ip_version}: block; }}
            src=extended_group {ip_version}.{protocol} : allow {{
                {client.ip_testing}
            }}
        }}
        """)
    await xfw.rules_patch(f"""
        xfw {{
            src=extended_group/replace {ip_version}.{protocol} : block {{
                {client.ip_testing}
            }}
        }}
        """)
    metrics = ["xfw_src_ip_blocked_packets", "xfw_src_ip_blocked_bytes"]

    async with xfw.metrics_diff(metrics) as diff_metrics:
        assert (
            await check_connection(client, server) is True
        ), f"Server ({server.ip_testing}:{server.port}) is blocked"

    assert metrics_increased(metrics, diff_metrics) is True


@pytest.mark.skip("ISSUE: 40(xFW)")
async def test_icmp_block_by_type(
    xfw: XFW,
    ip_version: str,
    udp_server: UdpServer,
    icmp_raw_client: IcmpRawClient,
    start_udp_server_and_icmp_clients,
):
    await xfw.rules_set(f"""
        xfw {{ 
            evaluation_mode;
            defaults {{ icmp: allow; }}
            icmp {ip_version}: block {{ 0, 8, 128, 129, 135, 136 }}
        }}
        """)

    metrics = ["xfw_icmp_blocked_packets", "xfw_icmp_blocked_bytes"]
    async with xfw.metrics_diff(metrics) as diff_metrics:
        await asyncio.gather(*[icmp_raw_client.ping() for _ in range(5)])

    assert await icmp_raw_client.pong() is True, "Client is blocked"
    assert metrics_increased(metrics, diff_metrics) is True


@pytest.mark.skip("ISSUE: 40(xFW)")
async def test_tcp_anomaly_filter(
    xfw: XFW,
    tcp_ip4_raw_server: TcpIpV4RawServer,
    tcp_ip4_raw_client: TcpIpV4RawClient,
):
    packet = TCP(
        flags="SR",
        seq=32513451,
        window=64240,
        options=(("MSS", 1460), ("WScale", 7)),
    )
    tcp_ip4_raw_client.auto_ack_seq = False

    await tcp_ip4_raw_server.start()
    await tcp_ip4_raw_client.start()

    await xfw.rules_set(
        "xfw { evaluation_mode; tcp_anomaly_filter syn_without_opt"
        " syn_with_payload syn_with_seqno=0 bad_flags; }"
    )

    metrics = ["xfw_tcp_anom_bad_flags_packets", "xfw_tcp_anom_bad_flags_bytes"]
    async with xfw.metrics_diff(metrics) as diff_metrics:
        await asyncio.gather(*[tcp_ip4_raw_client.send_packet(packet) for _ in range(5)])

    assert await tcp_ip4_raw_server.receive_tcp_flags() == "SR", "Client is blocked"
    assert metrics_increased(metrics, diff_metrics) is True


@pytest.mark.skip("ISSUE: 40 (xFW)")
async def test_tcp_auth_filter_tcp_flood_from_non_existing_session(
    xfw: XFW,
    tcp_raw_server: TcpRawServer,
    tcp_raw_client: TcpRawClient,
    start_tcp_raw_server_and_raw_clients,
):
    await xfw.rules_set("xfw { evaluation_mode; tcp_auth_filter; }")

    metrics = ["xfw_tcp_auth_failed_packets", "xfw_tcp_auth_failed_bytes"]
    async with xfw.metrics_diff(metrics) as diff_metrics:
        await tcp_raw_client.send_packet(TCP(flags="A"))

    assert (
        await tcp_raw_server.receive_tcp_flags() == "A"
    ), f"TCP packet with A without session is skipped"
    assert metrics_increased(metrics, diff_metrics) is True


@pytest.mark.skip("ISSUE: 40 (xFW)")
async def test_tcp_flags_filter(
    xfw: XFW,
    tcp_raw_server: TcpRawServer,
    tcp_raw_client: TcpRawClient,
    start_tcp_raw_server_and_raw_clients,
):
    await xfw.rules_set(f"""
        xfw {{
            evaluation_mode; 
            ratelimit=test pps=5 bps=1000;
            tcp_flags syn : ratelimit=test;
        }}
        """)
    metrics = ["xfw_syn_rate_limited_packets", "xfw_syn_rate_limited_bytes"]
    async with xfw.metrics_diff(metrics) as diff_metrics:
        await asyncio.gather(
            *[tcp_raw_client.send_packet(tcp_raw_client.valid_syn_packet) for _ in range(10)]
        )

    assert await tcp_raw_server.receive_many_packets(10) == 10
    assert metrics_increased(metrics, diff_metrics) is True


@pytest.mark.skip("ISSUE: 40 (xFW)")
async def test_udp_anomaly_filter_zero_port_is_blocked(
    xfw: XFW,
    udp_server: RegularKernelSocketNetworkStateful,
    udp_raw_client: UdpRawClient,
    start_udp_server_and_raw_clients,
):
    udp_raw_client.auto_add_host = False

    packet = UDP()
    packet.sport = 0
    packet.dport = udp_server.port

    await xfw.rules_set("xfw { evaluation_mode; }")

    metrics = ["xfw_udp_anom_zero_port_packets", "xfw_udp_anom_zero_port_bytes"]
    async with xfw.metrics_diff(metrics) as diff_metrics:
        await udp_raw_client.send_packet(packet / "Hello :)")

    assert await udp_server.receive_message() == "Hello :)", f"Zero source port port is blocked"
    assert metrics_increased(metrics, diff_metrics) is True


@pytest.mark.clickhouse
async def test_multiple_requests_logs_without_blocking(
    xfw: XFW,
    clickhouse_client: ClickhouseClient,
    udp_ip4_client: UdpClient,
    udp_ip4_server: UdpServer,
    client_cloner,
):
    await clickhouse_client.connect()
    await udp_ip4_server.start()

    clients = client_cloner(cloner=udp_ip4_client, amount=10)
    for client in clients:
        await client.start()

    await xfw.rules_set(f"""
        xfw {{
            evaluation_mode; 
            defaults {{ dst: allow; }} 
            dst ip4.udp : block {{
                {udp_ip4_server.ip_testing}:{udp_ip4_server.port}
            }}
        }}
        """)

    results = await asyncio.gather(
        *[check_connection(client, udp_ip4_server) for client in clients]
    )

    assert results, "Empty results"
    assert all(results)

    await clickhouse_client.wait_for_number_of_records(expected_records_n=10)
    records = await clickhouse_client.records_all()
    clients_ips = {client.ipv4 for client in clients}
    blocked_ips = {str(record.address.ipv4_mapped) for record in records}
    diff = clients_ips - blocked_ips
    assert diff == set(), f"Not all blocked clients where appeared in the db: {diff}"
