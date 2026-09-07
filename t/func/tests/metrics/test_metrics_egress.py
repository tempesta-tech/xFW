# SPDX-FileCopyrightText: (c) 2026 Tempesta Technologies, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later

import asyncio
import socket

import pytest
from scapy.all import ETH_P_IP, ETH_P_IPV6
from scapy.data import ETH_P_ALL

from config import ConfigSettings
from framework.cmp import check_connection
from framework.fabrics import client_fabric, server_fabric
from framework.metrics import PrometheusMetrics, PrometheusMetricsDiff
from framework.xfw import XFW
from tests.metrics.utils import (
    InvalidEthTypeRawClient,
    InvalidEthTypeRawServer,
    InvalidEthTypeRawServerRemote,
)


@pytest.mark.parametrize(
    "counters, method, sock_proto",
    [
        # xfw_l2_unknown_egress_packets is diapason because
        # some kernel messages could be caught
        # sizeof(ethhdr) = 14
        # sizeof(payload) = 9
        # (14 + 9) * 10
        pytest.param(
            PrometheusMetricsDiff(
                xfw_l2_unknown_egress_packets=[10, 15], xfw_l2_unknown_egress_bytes=[230, 345]
            ),
            "send_eth_eapol_packet",
            ETH_P_IP,
            id="eth-l2-bad-protocol-eapol",
        ),
        # sizeof(ethhdr) = 14
        # sizeof(payload) = 9
        # (14 + 9) * 10
        pytest.param(
            PrometheusMetricsDiff(
                xfw_l2_unknown_egress_packets=[10, 12], xfw_l2_unknown_egress_bytes=[230, 276]
            ),
            "send_eth_custom_packet",
            ETH_P_IP,
            id="eth-l2-bad-protocol-custom",
        ),
        pytest.param(
            PrometheusMetricsDiff(
                xfw_eth_badhdr_egress_packets=10, xfw_eth_badhdr_egress_bytes=540
            ),
            "send_bad_eth_header",
            ETH_P_IP,
            id="eth-send-bad-header",
            marks=pytest.mark.skip("OS prevent sending packages less then 14 bytes, ISSUE: 332"),
        ),
        # sizeof(ethhdr) = 14
        # sizeof(iphdr)[:10] = 10
        # (14 + 10) * 10
        pytest.param(
            PrometheusMetricsDiff(
                xfw_ip4_badhdr_egress_packets=10, xfw_ip4_badhdr_egress_bytes=240
            ),
            "send_bad_ip4_header_less",
            ETH_P_IP,
            id="ip4-tcp-header-less",
        ),
        # sizeof(ethhdr) = 14
        # sizeof(iphdr) = 20
        # sizeof(payload) = 12
        # (14 + 20 + 12) * 10
        pytest.param(
            PrometheusMetricsDiff(
                xfw_ip4_badhdr_egress_packets=10, xfw_ip4_badhdr_egress_bytes=460
            ),
            "send_bad_ip4_header_greater",
            ETH_P_IP,
            id="ip4-tcp-header-greater",
        ),
        # sizeof(ethhdr) = 14
        # sizeof(iphdr) = 20
        # (14 + 20) * 10
        pytest.param(
            PrometheusMetricsDiff(
                xfw_ip4_badhdr_egress_packets=10, xfw_ip4_badhdr_egress_bytes=340
            ),
            "send_bad_ip4_bad_ip_version",
            ETH_P_IP,
            id="ip4-bad-ip-version",
        ),
        # sizeof(ethhdr) = 14
        # sizeof(ipv6hdr)[:35] = 35
        # (14 + 35) * 10
        pytest.param(
            PrometheusMetricsDiff(
                xfw_ip6_badhdr_egress_packets=10, xfw_ip6_badhdr_egress_bytes=490
            ),
            "send_bad_ip6_header_less",
            ETH_P_IPV6,
            id="ip6-header-less",
        ),
        # sizeof(ethhdr) = 14
        # sizeof(ipv6hdr) = 40
        # (14 + 40) * 10
        pytest.param(
            PrometheusMetricsDiff(
                xfw_ip6_badhdr_egress_packets=10, xfw_ip6_badhdr_egress_bytes=540
            ),
            "send_bad_ip6_bad_ip_version",
            ETH_P_IPV6,
            id="ip6-bad-ip-version",
        ),
        # sizeof(ethhdr) = 14
        # sizeof(iphdr) = 20
        # sizeof(tcphdr)[:15] = 15
        # (14 + 20 + 15) * 10
        pytest.param(
            PrometheusMetricsDiff(
                xfw_tcp_badhdr_egress_packets=10, xfw_tcp_badhdr_egress_bytes=490
            ),
            "send_bad_tcp_headers",
            ETH_P_IP,
            id="tcp-bad-header-len",
        ),
        # sizeof(ethhdr) = 14
        # sizeof(iphdr) = 20
        # sizeof(tcphdr)[:6] = 6
        # (14 + 20 + 6) * 10
        pytest.param(
            PrometheusMetricsDiff(
                xfw_udp_badhdr_egress_packets=10, xfw_udp_badhdr_egress_bytes=400
            ),
            "send_bad_udp_headers",
            ETH_P_IP,
            id="udp-bad-header-len",
        ),
        # sizeof(ethhdr) = 14
        # sizeof(iphdr) = 20
        # sizeof(sctphdr) = 12
        # (14 + 20 + 12) * 10
        pytest.param(
            PrometheusMetricsDiff(
                xfw_l4_unsupported_egress_packets=10, xfw_l4_unsupported_egress_bytes=460
            ),
            "send_l4_unsupported_ip_proto",
            ETH_P_IP,
            id="ip4-block-unsupported-sctp",
        ),
        pytest.param(
            PrometheusMetricsDiff(
                xfw_total_upstream_egress_packets=10,
                xfw_total_upstream_egress_bytes=490,
                xfw_passed_upstream_egress_packets=10,
                xfw_passed_upstream_egress_bytes=490,
            ),
            "send_bad_tcp_headers",
            ETH_P_IP,
            id="upstream",
        ),
    ],
)
async def test_egress_metrics(
    counters: PrometheusMetricsDiff,
    method: str,
    sock_proto: int,
    metric_analyzer,
    xfw: XFW,
    config: ConfigSettings,
    logging_level: int,
    rpc_connection,
):
    server = server_fabric(
        rpc_connection=rpc_connection,
        config=config,
        logging_level=logging_level,
        local_class=InvalidEthTypeRawServer,
        remote_class=InvalidEthTypeRawServerRemote,
        force_ip4=sock_proto == ETH_P_IP,
    )

    client = client_fabric(
        config=config,
        logging_level=logging_level,
        local_class=InvalidEthTypeRawClient,
        force_ip4=sock_proto == ETH_P_IP,
    )
    client.socket_proto = socket.htons(ETH_P_ALL)

    await server.set_sock_proto(sock_proto)
    await server.set_remote_ip(client.ip)

    await server.start()
    await client.start()

    src_mac, dst_mac = await asyncio.gather(server.get_mac_address(), client.get_mac_address())

    await xfw.rules_set("xfw {}")

    async with metric_analyzer.expected_metrics_diff(xfw=xfw, expected_metrics=counters):
        await asyncio.gather(*[getattr(server, method)(src_mac, dst_mac) for _ in range(10)])
        responses = await asyncio.gather(*[client.receive_packet() for _ in range(10)])

    # some third party traffic could be received
    assert len([responses]) <= 5, "Broken packets where not filtered"


async def test_clean_metrics_after_restart(
    metric_analyzer,
    xfw: XFW,
    udp_ip4_client,
    udp_ip4_server,
):
    metric_1 = PrometheusMetrics()
    metric_2 = PrometheusMetrics()
    metric_3 = PrometheusMetrics()

    await xfw.rules_set("xfw {}")
    await metric_1.update(xfw)

    async with metric_analyzer.expected_metrics_diff(
        xfw=xfw,
        expected_metrics=PrometheusMetricsDiff(
            xfw_udp_total_ingress_packets=1, xfw_udp_total_ingress_bytes=47
        ),
    ):
        assert await check_connection(udp_ip4_client, udp_ip4_server)
    await metric_2.update(xfw)

    await xfw.restart()

    await metric_3.update(xfw)

    assert metric_1 != metric_2
    assert metric_2 != metric_3
