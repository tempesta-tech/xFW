# SPDX-FileCopyrightText: (c) 2026 Tempesta Technologies, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later

from abc import ABC

from dnslib import DNSRecord

from framework.asyn.dns_base import BaseDnsStateful
from framework.remote import RemoteServer
from framework.stateful import IP4Mixin, IP6Mixin

__all__ = [
    "DnsUdpServer",
    "DnsUdpV4Server",
    "DnsUdpV6Server",
    "DnsUdpV4ServerRemote",
    "DnsUdpV6ServerRemote",
]


class DnsUdpServer(BaseDnsStateful, ABC):
    async def update_config(self, client_ip: str, client_port: int, my_port: int):
        self.port = my_port
        self.remote_ip = client_ip
        self.remote_port = client_port

    async def request_dns_server(self):
        await self._send(DNSRecord.question("google.com.", qtype="A").pack())


class DnsUdpV4Server(DnsUdpServer, IP4Mixin): ...


class DnsUdpV6Server(DnsUdpServer, IP6Mixin): ...


class DnsUdpV4ServerRemote(RemoteServer, DnsUdpV4Server):
    remote_methods = [
        "run_stop",
        "start",
        "stop",
        "restart",
        "update_config",
        "receive_message",
        "request_dns_server",
    ]


class DnsUdpV6ServerRemote(RemoteServer, DnsUdpV6Server):
    remote_methods = [
        "run_stop",
        "start",
        "stop",
        "restart",
        "update_config",
        "receive_message",
        "request_dns_server",
    ]
