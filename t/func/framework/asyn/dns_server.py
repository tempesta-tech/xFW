# SPDX-FileCopyrightText: (c) 2026 Tempesta Technologies, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later

from abc import ABC
from typing import Optional

from dnslib import DNSRecord

from framework.asyn.dns_client import DnsUdpClientProtocol
from framework.asyn.udp_server import UdpServer
from framework.stateful import IP4Mixin, IP6Mixin
from framework.remote import RemoteServer


__all__ = [
    'DnsUdpServer',
    'DnsUdpV4Server',
    'DnsUdpV6Server',
    'DnsUdpV4ServerRemote',
    'DnsUdpV6ServerRemote',
]


class DnsUdpServer(UdpServer, ABC):
    transmitting_protocol = DnsUdpClientProtocol

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    async def receive(self, *args, **kwargs) -> Optional[DNSRecord]:
        return await super().receive(*args, **kwargs)

    async def update_config(self, client_ip: str, client_port: int, my_port: int):
        self.port = my_port
        self.remote_ip = client_ip
        self.remote_port = client_port

    async def send(self, data: DNSRecord):
        self.logger.info(f'sending "{data}" to {self.remote_ip}:{self.remote_port}')
        await self.send_bytes(data.pack())

    async def receive_message(self) -> Optional[str]:
        message: DNSRecord = await self.receive()

        if not message:
            return None

        return message.q.get_qname().idna()

    async def request_dns_server(self):
        await self.send(DNSRecord.question('google.com.', qtype="A"))


class DnsUdpV4Server(DnsUdpServer, IP4Mixin):
    ...


class DnsUdpV6Server(DnsUdpServer, IP6Mixin):
    ...


class DnsUdpV4ServerRemote(RemoteServer, DnsUdpV4Server):
    remote_methods = [
        'run_stop',
        'start',
        'stop',
        'restart',

        'update_config',
        'receive_message',
        'request_dns_server',
    ]

    def __init__(self, *args, **kwargs) -> None:
        RemoteServer.__init__(self, *args, **kwargs)
        DnsUdpV4Server.__init__(self, *args, **kwargs)


class DnsUdpV6ServerRemote(RemoteServer, DnsUdpV6Server):
    remote_methods = [
        'run_stop',
        'start',
        'stop',
        'restart',

        'update_config',
        'receive_message',
        'request_dns_server',
    ]
    def __init__(self, *args, **kwargs) -> None:
        RemoteServer.__init__(self, *args, **kwargs)
        DnsUdpV6Server.__init__(self, *args, **kwargs)
