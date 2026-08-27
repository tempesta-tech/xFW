# SPDX-FileCopyrightText: (c) 2026 Tempesta Technologies, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later

import asyncio
import socket
from contextlib import asynccontextmanager

import pytest
from scapy.all import ETH_P_IP, ETH_P_IPV6, Raw
from scapy.data import ETH_P_ALL
from scapy.layers.inet import ICMP, IP, IP_PROTOS, TCP, UDP, Ether
from scapy.layers.inet6 import IPv6, IPv6ExtHdrFragment
from scapy.layers.sctp import SCTP

from config import ConfigSettings
from framework.asyn.ether_raw_client import EtherRawClient
from framework.asyn.ether_raw_server import EtherRawServer
from framework.fabrics import client_fabric, server_fabric
from framework.remote import RemoteServer
from framework.utils import compare_metrics_diff
from framework.xfw import XFW

ETH_P_EAPOL = 0x888E
ETH_P_CUSTOM = 0x1234
ETH_P_ARP = 0x0806


@pytest.fixture
def egress_metrics_counters() -> list[str]:
    return [
        "xfw_total_downstream_egress_packets",
        "xfw_total_downstream_egress_bytes",
        "xfw_total_upstream_egress_packets",
        "xfw_total_upstream_egress_bytes",
        "xfw_passed_downstream_egress_packets",
        "xfw_passed_downstream_egress_bytes",
        "xfw_passed_upstream_egress_packets",
        "xfw_passed_upstream_egress_bytes",
        "xfw_l2_unknown_egress_packets",
        "xfw_l2_unknown_egress_bytes",
        "xfw_eth_badhdr_egress_packets",
        "xfw_eth_badhdr_egress_bytes",
        "xfw_l4_unsupported_egress_packets",
        "xfw_l4_unsupported_egress_bytes",
        "xfw_ip4_badhdr_egress_packets",
        "xfw_ip4_badhdr_egress_bytes",
        "xfw_ip6_badhdr_egress_packets",
        "xfw_ip6_badhdr_egress_bytes",
        "xfw_tcp_badhdr_egress_packets",
        "xfw_tcp_badhdr_egress_bytes",
        "xfw_udp_badhdr_egress_packets",
        "xfw_udp_badhdr_egress_bytes",
    ]


class SendInvalidPacketsMixin(EtherRawClient):
    async def send_eth_eapol_packet(self, src_mac: str, dst_mac: str):
        packet = Ether(dst=dst_mac, src=src_mac, type=socket.ETHERTYPE_VLAN) / Raw(
            load=b"some_data"
        )
        await self.loop.sock_sendall(self.socket, bytes(packet))
        self.logger.info(f"Sending L2 packet {packet}")

    async def send_eth_custom_packet(self, src_mac: str, dst_mac: str):
        packet = Ether(dst=dst_mac, src=src_mac, type=ETH_P_CUSTOM) / Raw(load=b"some_data")
        await self.loop.sock_sendall(self.socket, bytes(packet))
        self.logger.info(f"Sending L2 packet {packet}")

    async def send_bad_eth_header(self, src_mac: str, dst_mac: str):
        packet = Ether(dst=dst_mac, src=src_mac, type=self.socket_proto)
        await self.loop.sock_sendall(self.socket, bytes(packet)[:13])
        self.logger.info(f"Sending L2 packet {packet}")

    async def send_bad_ip4_header_less(self, src_mac: str, dst_mac: str):
        packet = Ether(dst=dst_mac, src=src_mac, type=ETH_P_IP)
        packet = packet / bytes(IP(version=4, ihl=4, src=self.ipv4, dst=self.remote_ip))[:10]
        await self.loop.sock_sendall(self.socket, bytes(packet))
        self.logger.info(f"Sending L2 packet {packet}")

    async def send_bad_ip4_header_greater(self, src_mac: str, dst_mac: str):
        packet = Ether(dst=dst_mac, src=src_mac, type=ETH_P_IP)
        packet = packet / (
            bytes(IP(version=4, ihl=16, src=self.ipv4, dst=self.remote_ip)) + b"invalid_part"
        )
        await self.loop.sock_sendall(self.socket, bytes(packet))
        self.logger.info(f"Sending L2 packet {packet}")

    async def send_bad_ip4_bad_ip_version(self, src_mac: str, dst_mac: str):
        packet = Ether(dst=dst_mac, src=src_mac, type=ETH_P_IP)
        packet = packet / IP(version=5, ihl=16, src=self.ipv4, dst=self.remote_ip)
        await self.loop.sock_sendall(self.socket, bytes(packet))
        self.logger.info(f"Sending L2 packet {packet}")

    async def send_bad_ip4_fragmented(self, src_mac: str, dst_mac: str):
        packet = Ether(dst=dst_mac, src=src_mac, type=ETH_P_IP)
        packet = (
            packet
            / IP(src=self.ipv4, dst=self.remote_ip, id=12345, flags="MF", frag=10, len=30)
            / Raw(b"flag 10")
        )
        await self.loop.sock_sendall(self.socket, bytes(packet))
        self.logger.info(f"Sending L2 packet {packet}")

    async def send_bad_ip6_header_less(self, src_mac: str, dst_mac: str):
        packet = Ether(dst=dst_mac, src=src_mac, type=ETH_P_IPV6)

        # always 40 bytes
        ipv6_part = bytes(IPv6(version=6, src=self.ipv6, dst=self.remote_ip))[:35]

        await self.loop.sock_sendall(self.socket, bytes(packet / ipv6_part))
        self.logger.info(f"Sending L2 packet {packet}")

    async def send_bad_ip6_bad_ip_version(self, src_mac: str, dst_mac: str):
        packet = Ether(dst=dst_mac, src=src_mac, type=ETH_P_IPV6)
        packet = packet / IPv6(version=5, src=self.ipv4, dst=self.remote_ip)
        await self.loop.sock_sendall(self.socket, bytes(packet))
        self.logger.info(f"Sending L2 packet {packet}")

    async def send_bad_ip6_fragmented(self, src_mac: str, dst_mac: str):
        packet = Ether(dst=dst_mac, src=src_mac, type=ETH_P_IPV6)
        packet = (
            packet
            / IPv6(
                src=self.ipv6,
                dst=self.remote_ip,
            )
            / IPv6ExtHdrFragment(id=12345)
            / Raw(b"flag 10")
        )
        await self.loop.sock_sendall(self.socket, bytes(packet))
        self.logger.info(f"Sending L2 packet {packet}")

    async def send_bad_tcp_headers(self, src_mac: str, dst_mac: str):
        packet = Ether(dst=dst_mac, src=src_mac, type=ETH_P_IP)
        packet = packet / IP(src=self.ipv4, dst=self.remote_ip, proto=IP_PROTOS.tcp)
        # 20 bytes - minimal
        tcp_part = bytes(TCP())[:15]
        await self.loop.sock_sendall(self.socket, bytes(packet / tcp_part))
        self.logger.info(f"Sending L2 packet {packet}")

    async def send_bad_udp_headers(self, src_mac: str, dst_mac: str):
        packet = Ether(dst=dst_mac, src=src_mac, type=ETH_P_IP)
        packet = packet / IP(src=self.ipv4, dst=self.remote_ip, proto=IP_PROTOS.udp)
        # 8 bytes always
        udp_part = bytes(UDP(len=6))[:6]
        await self.loop.sock_sendall(self.socket, bytes(packet / udp_part))
        self.logger.info(f"Sending L2 packet {packet}")

    async def send_bad_icmp_headers(self, src_mac: str, dst_mac: str):
        packet = Ether(dst=dst_mac, src=src_mac, type=ETH_P_IP)
        packet = packet / IP(src=self.ipv4, dst=self.remote_ip, proto=IP_PROTOS.icmp)
        # 8 bytes min
        icmp_part = bytes(ICMP())[:6]
        await self.loop.sock_sendall(self.socket, bytes(packet / icmp_part))
        self.logger.info(f"Sending L2 packet {packet}")

    async def send_arp_headers(self, src_mac: str, dst_mac: str):
        packet = Ether(dst=dst_mac, src=src_mac, type=ETH_P_ARP)
        arp_part = bytes(ARP(op=1, pdst=self.remote_ip))
        await self.loop.sock_sendall(self.socket, bytes(packet / arp_part))
        self.logger.info(f"Sending L2 packet {packet}")

    async def send_l4_unsupported_ip_proto(self, src_mac: str, dst_mac: str):
        packet = Ether(dst=dst_mac, src=src_mac, type=ETH_P_IP)
        packet = packet / IP(src=self.ipv4, dst=self.remote_ip, proto=IP_PROTOS.sctp)
        packet = packet / SCTP(sport=3000, dport=3000)

        await self.loop.sock_sendall(self.socket, bytes(packet))
        self.logger.info(f"Sending L2 packet {packet}")

    async def test_ok_udp_request(self, src_mac: str, dst_mac: str):
        packet = Ether(dst=dst_mac, src=src_mac, type=ETH_P_IP)
        packet = packet / IP(src=self.ipv4, dst=self.remote_ip, proto=IP_PROTOS.udp)
        packet = packet / UDP(sport=3000, dport=3000) / Raw(b"flag 10")

        await self.loop.sock_sendall(self.socket, bytes(packet))
        self.logger.info(f"Sending L2 packet {packet}")


class InvalidEthTypeRawClient(SendInvalidPacketsMixin, EtherRawClient): ...


class InvalidEthTypeRawServer(SendInvalidPacketsMixin, EtherRawServer): ...


class InvalidEthTypeRawServerRemote(RemoteServer, InvalidEthTypeRawServer):
    remote_methods = [
        "run_stop",
        "start",
        "stop",
        "restart",
        "receive_packet",
        "receive_many_packets",
    ]

    def __init__(self, *args, **kwargs):
        RemoteServer.__init__(self, *args, **kwargs)
        InvalidEthTypeRawServer.__init__(self, *args, **kwargs)


@pytest.mark.parametrize(
    "counters, method, sock_proto",
    [
        # xfw_l2_unknown_egress_packets is diapason because
        # some kernel messages could be caught
        # sizeof(ethhdr) = 14
        # sizeof(payload) = 9
        # (14 + 9) * 10
        pytest.param(
            dict(xfw_l2_unknown_egress_packets=[10, 15], xfw_l2_unknown_egress_bytes=[230, 345]),
            "send_eth_eapol_packet",
            ETH_P_IP,
            id="eth-l2-bad-protocol-eapol",
        ),
        # sizeof(ethhdr) = 14
        # sizeof(payload) = 9
        # (14 + 9) * 10
        pytest.param(
            dict(xfw_l2_unknown_egress_packets=[10, 12], xfw_l2_unknown_egress_bytes=[230, 276]),
            "send_eth_custom_packet",
            ETH_P_IP,
            id="eth-l2-bad-protocol-custom",
        ),
        pytest.param(
            dict(xfw_eth_badhdr_egress_packets=10, xfw_eth_badhdr_egress_bytes=540),
            "send_bad_eth_header",
            ETH_P_IP,
            id="eth-send-bad-header",
            marks=pytest.mark.skip("OS prevent sending packages less then 14 bytes, ISSUE: 332"),
        ),
        # sizeof(ethhdr) = 14
        # sizeof(iphdr)[:10] = 10
        # (14 + 10) * 10
        pytest.param(
            dict(xfw_ip4_badhdr_egress_packets=10, xfw_ip4_badhdr_egress_bytes=240),
            "send_bad_ip4_header_less",
            ETH_P_IP,
            id="ip4-tcp-header-less",
        ),
        # sizeof(ethhdr) = 14
        # sizeof(iphdr) = 20
        # sizeof(payload) = 12
        # (14 + 20 + 12) * 10
        pytest.param(
            dict(xfw_ip4_badhdr_egress_packets=10, xfw_ip4_badhdr_egress_bytes=460),
            "send_bad_ip4_header_greater",
            ETH_P_IP,
            id="ip4-tcp-header-greater",
        ),
        # sizeof(ethhdr) = 14
        # sizeof(iphdr) = 20
        # (14 + 20) * 10
        pytest.param(
            dict(xfw_ip4_badhdr_egress_packets=10, xfw_ip4_badhdr_egress_bytes=340),
            "send_bad_ip4_bad_ip_version",
            ETH_P_IP,
            id="ip4-bad-ip-version",
        ),
        # sizeof(ethhdr) = 14
        # sizeof(ipv6hdr)[:35] = 35
        # (14 + 35) * 10
        pytest.param(
            dict(xfw_ip6_badhdr_egress_packets=10, xfw_ip6_badhdr_egress_bytes=490),
            "send_bad_ip6_header_less",
            ETH_P_IPV6,
            id="ip6-header-less",
        ),
        # sizeof(ethhdr) = 14
        # sizeof(ipv6hdr) = 40
        # (14 + 40) * 10
        pytest.param(
            dict(xfw_ip6_badhdr_egress_packets=10, xfw_ip6_badhdr_egress_bytes=540),
            "send_bad_ip6_bad_ip_version",
            ETH_P_IPV6,
            id="ip6-bad-ip-version",
        ),
        # sizeof(ethhdr) = 14
        # sizeof(iphdr) = 20
        # sizeof(tcphdr)[:15] = 15
        # (14 + 20 + 15) * 10
        pytest.param(
            dict(xfw_tcp_badhdr_egress_packets=10, xfw_tcp_badhdr_egress_bytes=490),
            "send_bad_tcp_headers",
            ETH_P_IP,
            id="tcp-bad-header-len",
        ),
        # sizeof(ethhdr) = 14
        # sizeof(iphdr) = 20
        # sizeof(tcphdr)[:6] = 6
        # (14 + 20 + 6) * 10
        pytest.param(
            dict(xfw_udp_badhdr_egress_packets=10, xfw_udp_badhdr_egress_bytes=400),
            "send_bad_udp_headers",
            ETH_P_IP,
            id="udp-bad-header-len",
        ),
        # sizeof(ethhdr) = 14
        # sizeof(iphdr) = 20
        # sizeof(sctphdr) = 12
        # (14 + 20 + 12) * 10
        pytest.param(
            dict(xfw_l4_unsupported_egress_packets=10, xfw_l4_unsupported_egress_bytes=460),
            "send_l4_unsupported_ip_proto",
            ETH_P_IP,
            id="ip4-block-unsupported-sctp",
        ),
        pytest.param(
            dict(
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
    counters: dict[str, int],
    method: str,
    sock_proto: int,
    egress_metrics_counters: list[str],
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

    async with xfw.metrics_diff(egress_metrics_counters) as diff:
        await asyncio.gather(*[getattr(server, method)(src_mac, dst_mac) for _ in range(10)])
        responses = await asyncio.gather(*[client.receive_packet() for _ in range(10)])

    invalid_metrics = compare_metrics_diff(
        compare_metrics=egress_metrics_counters,
        all_metrics=diff,
        diff_metrics=counters,
    )

    await client.stop()
    await server.stop()

    assert invalid_metrics == [], f"Some metrics are different: {invalid_metrics}"

    # some third party traffic could be received
    assert len([responses]) <= 5, "Broken packets where not filtered"


@asynccontextmanager
async def check_clean_counters(
    metrics_counters: list[str],
    xfw: XFW,
    udp_ip4_server,
    config: ConfigSettings,
    logging_level: int,
):
    counters = dict(xfw_udp_total_ingress_packets=10, xfw_udp_total_ingress_bytes=400)
    client = client_fabric(
        config=config,
        logging_level=logging_level,
        local_class=InvalidEthTypeRawClient,
        force_ip4=True,
    )

    await xfw.rules_set("xfw {}")
    await udp_ip4_server.start()
    await client.start()

    src_mac, dst_mac = await asyncio.gather(
        client.get_mac_address(),
        udp_ip4_server.get_mac_address(),
    )

    async with xfw.metrics_diff(metrics_counters) as diff:
        await asyncio.gather(*[client.send_bad_udp_headers(src_mac, dst_mac) for _ in range(10)])

    invalid_metrics = compare_metrics_diff(
        compare_metrics=metrics_counters, all_metrics=diff, diff_metrics=counters, strict=True
    )

    assert invalid_metrics == [], f"Some metrics are different: {invalid_metrics}"

    yield

    metrics = await xfw.metrics()
    assert metrics["xfw_udp_total_ingress_packets"] == 0
    assert metrics["xfw_udp_total_ingress_bytes"] == 0


async def test_clean_metrics_after_restart(
    egress_metrics_counters: list[str],
    xfw: XFW,
    udp_ip4_client,
    udp_ip4_server,
    config: ConfigSettings,
    logging_level: int,
):
    verify_metrics_while_app_reloads = check_clean_counters(
        metrics_counters=["xfw_udp_total_ingress_packets", "xfw_udp_total_ingress_bytes"],
        xfw=xfw,
        udp_ip4_server=udp_ip4_server,
        config=config,
        logging_level=logging_level,
    )
    async with verify_metrics_while_app_reloads:
        await xfw.restart()


async def test_clean_metrics_after_stop_start(
    xfw: XFW,
    udp_ip4_client,
    udp_ip4_server,
    config: ConfigSettings,
    logging_level: int,
):
    verify_metrics_while_app_reloads = check_clean_counters(
        metrics_counters=["xfw_udp_total_ingress_packets", "xfw_udp_total_ingress_bytes"],
        xfw=xfw,
        udp_ip4_server=udp_ip4_server,
        config=config,
        logging_level=logging_level,
    )
    async with verify_metrics_while_app_reloads:
        await xfw.stop()
        await xfw.start()
