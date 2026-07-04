# SPDX-FileCopyrightText: (c) 2026 Tempesta Technologies, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later

import asyncio
import logging
import os
import time
import zipfile
from io import BytesIO

import httpx
import pytest
from scapy.all import rdpcap

from config import ConfigSettings
from framework.asyn.ether_raw_server import EtherRawServer
from framework.asyn.traffic_replay import TrafficReplayClient
from framework.xfw import XFW


async def count_packets(server: EtherRawServer, start_time: float, wait_time_sec: float):
    counter = 0
    packets = []

    while True:
        request = await server._receive()

        if request is None:
            continue

        packets.append(request)
        counter += 1

        if time.time() - start_time > wait_time_sec:
            return packets


@pytest.fixture(scope="module")
async def download_ddos_archive(config: ConfigSettings, conf_logger):
    if os.path.exists(config.xfw_ddos_examples_temp_dir):
        conf_logger.info("Skipped downloading ddos examples. " "File already exists")
        return

    async with httpx.AsyncClient() as client:
        response = await client.get(config.xfw_ddos_examples_url)

    if response.status_code != 200:
        raise FileExistsError("Can not download GeoIP DB from Nexus")

    file = BytesIO(response.content)

    if not os.path.exists(config.xfw_ddos_examples_temp_dir):
        os.makedirs(config.xfw_ddos_examples_temp_dir)

    with zipfile.ZipFile(file, "r") as ddos_archive:
        for filename in ddos_archive.namelist():
            with ddos_archive.open(filename) as ddos_file:
                with open(f"{config.xfw_ddos_examples_temp_dir}/{filename}", "wb") as file:
                    file.write(ddos_file.read())

    conf_logger.info("Downloaded ddos-examples.zip")


@pytest.mark.ddos_simulating
@pytest.mark.parametrize(
    "file_name, dst_original_ip, packets_per_second, percent_blocked, rewrite_ports, xfw_rule",
    [
        # udp anomaly filter is turned on by-default. DDoS attack
        # with zero SRC/DST port
        pytest.param(
            "pkt.UDP.null.pcapng",
            "10.10.10.10",
            500,
            98,
            False,
            "xfw {{}}",
            id="udp-zero-src-dst-port",
        ),
        # fragmented IP traffic is blocked by default
        pytest.param(
            "pkt.UDP.fragmented.pcap",
            "10.10.10.10",
            500,
            98,
            False,
            "xfw {{}}",
            id="udp-fragmented",
        ),
        # Reflecting attack with UDP packets of BACNet protocol data
        # from IoT devices should be ratelimited
        pytest.param(
            "amp.UDP.bacnet.IOT.37810.pcapng",
            "10.10.10.1",
            500,
            98,
            False,
            """
            xfw {{ 
                ratelimit=iot pps=10 bps=10000;
                dst ip4.udp : ratelimit=iot {{
                    {host}:{port}
                }}
            }}
            """,
            id="bacnet-protocol",
        ),
        # DNS reflecting attack. Turning on the dns_filter prevents incoming traffic
        # from DNS server which was not requested ~ 60% of all traffic.
        # Another part of traffic ~39% - fragmented IP
        pytest.param(
            "amp.UDP.DNSANY.pcap",
            "10.10.10.10",
            500,
            98,
            False,
            "xfw {{ dns_filter; }}",
            id="udp-dns-any",
        ),
        # Reflecting attack with UDP packets from SAME SRC PORT and DIFFERENT SRC IP.
        # Average packet size - 750 bytes.
        # In a general case we can apply ratelimits. But it's possible to
        # block SRC PORT = 37810 directly
        pytest.param(
            "amp.UDP.IOT.port37810.JSON.pcap",
            "10.10.10.10",
            500,
            60,
            True,
            """
            xfw {{ 
                ratelimit=iot pps=10 bps=10000;
                dst ip4.udp : ratelimit=iot {{
                    {host}:{port}
                }}
            }}
            """,
            id="udp-iot-high-traffic",
        ),
        # Reflection attack used public IPSEC servers to reflect the
        # traffic.The SRC PORT is the same in all packets
        pytest.param(
            "amp.UDP.isakmp.pcap",
            "10.10.10.10",
            500,
            98,
            True,
            """
            xfw {{ 
                src ip4.udp : block {{
                    :4500
                }} 
            }}
            """,
            id="udp-isakmp",
        ),
        # Combined attack with about 12 of different protocols. The DST
        # port is different and depends on used protocol
        pytest.param(
            "amp.UDP.manyprotocols.pcapng",
            "10.10.10.10",
            500,
            98,
            True,
            """
            xfw {{ 
                defaults {{ dst: block; }}
                ratelimit=whitelisted_rl pps=1000 bps=100000;
                dst ip4.udp : ratelimit=whitelisted_rl {{
                    {host}:{port}
                }} 
            }}
            """,
            id="udp-multiple",
        ),
        # Combined reflecting attack used Memcached and CLDAP. The DST port
        # is the same.
        pytest.param(
            "amp.UDP.memcached.ntp.cldap.pcap",
            "10.10.10.10",
            500,
            98,
            True,
            """
            xfw {{ 
                ratelimit=whitelisted_rl pps=10 bps=100000;
                dst ip4.udp : ratelimit=whitelisted_rl {{
                    {host}:{port}
                }} 
            }}
            """,
            id="udp-memcached",
        ),
        # Reflection attack used SNMP protocol and directed to
        # random port of defending machine. The reflecting machines
        # has different src host, but same src port. Also part of the
        # packets are fragmented ip4 and icmp ip4
        pytest.param(
            "amp.UDP.snmp.src161.pcapng",
            "10.10.10.10",
            500,
            98,
            True,
            """
            xfw {{ 
                defaults {{ icmp ip4: block; }}
                src ip4.udp : block {{
                    :161
                }} 
            }}
            """,
            id="udp-snmp",
        ),
        # Reflection attack used UBNT protocol and directed to
        # random port of defending machine. The reflecting machines
        # has different src host, but same src port
        pytest.param(
            "amp.UDP.UBNT.src10001.pcapng",
            "10.10.10.10",
            500,
            98,
            True,
            """
            xfw {{ 
                src ip4.udp : block {{
                    :10001
                }} 
            }}
            """,
            id="udp-ubnt",
        ),
        # The attack is directed to port 20480, sends huge packets 1336 bytes
        # from different sources
        pytest.param(
            "pkt.UDP.rdm.fixedlength.pcapng",
            "10.10.10.10",
            500,
            98,
            True,
            """
            xfw {{ 
                ratelimit=rdm_rl pps=100 bps=10000;
                dst ip4.udp : ratelimit=rdm_rl {{
                    {host}:20480
                }} 
            }}
            """,
            id="udp-rdm",
        ),
        # Lots of different machines send ICMP Echo packets with
        # the different body size filled with zeros: 100-1500 bytes.
        # In the dataset some noise packets exists, like ssh, udp, openvpn
        pytest.param(
            "pkt.ICMP.largeempty.pcap",
            "10.10.10.10",
            500,
            98,
            True,
            """
            xfw {{ 
                defaults {{ icmp ip4: block; }}
            }}
            """,
            id="icmp-zeros",
        ),
        # The ip4 reflecting attack where PROTOCOL is random as a data inside.
        # Some packets have even broken SRC HOST, like a random or empty string
        pytest.param(
            "pkt.IPV4.randomprotofield.pcap",
            "10.10.10.10",
            500,
            98,
            True,
            """
            xfw {{ }}
            """,
            id="ip4-random-proto",
        ),
        # Reflecting TCP SYN-ACK packets on random DST PORT, Sec and Ack are always 0.
        # 95% because a low amount of packets - 7.5k, lots of noise while tests go.
        # SRC PORT is always the same - 80, we also can block it by SRC PORT
        pytest.param(
            "amp.TCP.reflection.SYNACK.pcap",
            "10.10.10.10",
            500,
            95,
            True,
            """
            xfw {{ 
                tcp_auth_filter;
            }}
            """,
            id="tcp-syn-ack",
        ),
        # TCP SYN/ SYN-ACK packets on random DST PORT, Sec and Ack are always 0.
        # Half of the traffic (SYN-ACK) could be blocked by the tcp_auth_filter,
        # but we also need to ratelimit the new connection
        pytest.param(
            "amp.TCP.syn.optionallyACK.optionallysamePort.pcapng",
            "10.10.10.10",
            500,
            95,
            True,
            """
            xfw {{ 
                tcp_auth_filter;
                
                ratelimit=syn_rl pps=10 bps=100000;
                tcp_flags syn: ratelimit=syn_rl;
            }}
            """,
            id="tcp-syn-syn-ack",
        ),
        # TCP SYN and RST packets on same DST PORT = 30120, Sec and Ack are always 0.
        # Most of the packets was empty options
        pytest.param(
            "pkt.TCP.DOMINATE.syn.ecn.cwr.pcapng",
            "10.10.10.10",
            500,
            98,
            True,
            """
            xfw {{ 
                tcp_anomaly_filter;
                tcp_auth_filter;
            }}
            """,
            id="tcp-syn-rst",
        ),
        # TCP SYN flood directed on DST PORT = 25565. Seq is 0 always, packet options are empty
        pytest.param(
            "pkt.TCP.synflood.spoofed.pcap",
            "10.10.10.10",
            500,
            98,
            True,
            """
            xfw {{ 
                tcp_anomaly_filter;
            }}
            """,
            id="tcp-syn-flood",
        ),
        # DNS Reflected attack with combined IP4 fragmented. DST PORT is random if included.
        # This dataset looks like have not filtered regular TCP traffic. Only 29%
        # of traffic is real attack
        pytest.param(
            "amp.dns.RRSIG.fragmented.pcap",
            "10.10.10.10",
            500,
            28,
            True,
            """
            xfw {{ 
                dns_filter;
            }}
            """,
            id="dns-rrsig",
        ),
    ],
)
async def test_execute_pcap(
    file_name: str,
    dst_original_ip: str,
    packets_per_second: int,
    percent_blocked: float,
    rewrite_ports: bool,
    xfw_rule: str,
    config: ConfigSettings,
    conf_logger: logging.Logger,
    xfw: XFW,
    traffic_replay_client: TrafficReplayClient,
    ether_raw_server: EtherRawServer,
    download_ddos_archive,
):
    file_path = f"{config.xfw_ddos_examples_temp_dir}/{file_name}"
    packets = rdpcap(file_path)
    packets_amount = len(packets)

    total_time_sec = packets_amount / packets_per_second
    tcpreplay_startup_sec = 5
    minimal_amount_to_block = int(packets_amount * percent_blocked / 100)

    conf_logger.info(
        f"{file_name} includes {packets_amount} packets. "
        f"PPS={packets_per_second} "
        f"/TOTAL_TIME={total_time_sec}sec "
        f"/EXPECTING_TO_BLOCK={minimal_amount_to_block} packets "
    )

    ports_original = ""
    port_dst = None

    if rewrite_ports:
        ports_original = "0-65535"
        port_dst = traffic_replay_client.port

    await traffic_replay_client.prepare_pcap(
        file_path=file_path,
        dst_original_ip=dst_original_ip,
        dst_original_port=ports_original,
        dst_rewrote_port=port_dst,
    )
    conf_logger.info("prepared pcap file")

    await ether_raw_server.start()
    await traffic_replay_client.start()
    await xfw.rules_set(
        xfw_rule.format(host=ether_raw_server.ip_testing, port=ether_raw_server.port)
    )

    received_packets_task = asyncio.create_task(
        count_packets(
            server=ether_raw_server,
            start_time=time.time(),
            wait_time_sec=total_time_sec + tcpreplay_startup_sec,
        )
    )
    tcpreplay_task = asyncio.create_task(
        traffic_replay_client.replay_pcap(
            file_path=file_path, packets_per_second=packets_per_second
        )
    )

    async with xfw.metrics_diff(non_zero=True) as diff:
        await asyncio.gather(received_packets_task, tcpreplay_task)

    received_packets = received_packets_task.result()
    received_packets_amount = len(received_packets)
    blocked_packets = packets_amount - received_packets_amount
    blocked_packets_pct = int((blocked_packets / packets_amount) * 100)

    conf_logger.info(
        f"total received packages: {received_packets_amount}, "
        f"blocked={blocked_packets} ({blocked_packets_pct}%)"
    )

    results = [(metric, value) for metric, value in diff.items()]
    results.sort(key=lambda item: item[1], reverse=True)

    table = f'\n| {"METRIC":50} | {"DIFF":10} |\n'
    for metric, value in results:
        table += f"| {metric:50} | {value:10} |\n"

    conf_logger.info(table)

    assert minimal_amount_to_block <= blocked_packets, (
        f"Blocked {blocked_packets} packets ({blocked_packets_pct}%), but expected at least "
        f"{minimal_amount_to_block} ({percent_blocked}%)"
    )
