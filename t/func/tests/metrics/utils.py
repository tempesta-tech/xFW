# SPDX-FileCopyrightText: (c) 2026 Tempesta Technologies, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later
import socket
import struct

from dnslib import NS, QTYPE, RCODE, RR, SOA, A, DNSQuestion, DNSRecord
from scapy.all import ETH_P_IP, ETH_P_IPV6
from scapy.layers.inet import ICMP, IP, IP_PROTOS, TCP, UDP, Ether
from scapy.layers.inet6 import IPv6, IPv6ExtHdrFragment
from scapy.layers.l2 import ARP
from scapy.layers.sctp import SCTP
from scapy.packet import Raw

from framework.asyn import DnsUdpClient
from framework.asyn.ether_raw_client import EtherRawClient
from framework.asyn.ether_raw_server import EtherRawServer
from framework.remote import RemoteServer

ETH_P_EAPOL = 0x888E
ETH_P_CUSTOM = 0x1234
ETH_P_ARP = 0x0806


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


class DnsRequests:
    @staticmethod
    def non_zero_rcode() -> DNSRecord:
        query = DNSRecord.question("google.com", qtype="A")
        query.header.rcode = RCODE.FORMERR
        return query

    @staticmethod
    def more_than_one_question() -> DNSRecord:
        query = DNSRecord.question("google.com", qtype="A")
        query.add_question(DNSQuestion("example.com"))
        return query

    @staticmethod
    def answers_or_authority_sections_in_dns_query() -> DNSRecord:
        query = DNSRecord.question("google.com", qtype="A")
        query.add_answer(RR("google.com.", ttl=300, rdata=A("1.2.3.4")))
        return query

    @staticmethod
    def invalid_ixfr_query() -> DNSRecord:
        query = DNSRecord.question("google.com", qtype="IXFR")
        query.add_auth(RR("google.com.", ttl=300, rdata=NS("ns.google.com.")))
        return query

    @staticmethod
    def more_than_two_additional_sections() -> DNSRecord:
        query = DNSRecord.question("google.com", qtype="A")
        query.add_ar(RR("foo.bar.", rtype=QTYPE.A, rdata=A("192.0.2.1")))
        query.add_ar(RR("boo.bar.", rtype=QTYPE.A, rdata=A("192.0.2.2")))
        query.add_ar(RR("zoo.bar.", rtype=QTYPE.A, rdata=A("192.0.2.3")))
        return query

    @staticmethod
    async def reply_for_non_existing_query(server) -> bool:
        return await server.reply_for_non_existing_query()

    @staticmethod
    async def reply_with_ttl_0(server) -> bool:
        return await server.reply_with_ttl(0)

    @staticmethod
    async def reply_with_malformed_rr(server: DnsUdpClient) -> bool:
        request_record = await server.receive_dns_record()
        if not request_record:
            return False

        response_bytes = (
            struct.pack("!HHHHHH", request_record.header.id, 0x8100, 1, 1, 0, 0)
            + b"\x06google\x00"
            + struct.pack("!HH", 1, 1)
            + b"\x00"
            + struct.pack("!HHIH", 1, 1, 300, 4)
            + b"\x01"  # invalid RDATA (1 byte instead of 4)
        )

        await server._send(response_bytes)
        return True

    @staticmethod
    async def reply_with_size_bytes_4096(server) -> bool:
        return await server.reply_with_size_bytes(4096)

    @staticmethod
    async def reply_with_multiple_answers_101(server) -> bool:
        return await server.reply_with_multiple_answers(101)
