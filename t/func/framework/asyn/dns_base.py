# SPDX-FileCopyrightText: (c) 2026 Tempesta Technologies, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later
import abc
from typing import Optional

from dnslib import DNSRecord

from framework.asyn.udp_base import BaseUdpProtocol, BaseUdpStateful

__all__ = ["BaseDnsStateful"]


class DnsUdpClientProtocol(BaseUdpProtocol):
    def datagram_received(self, data, addr):
        self.messages.put_nowait(data)
        self.last_address = addr
        self.logger.info(f"received from {addr} : {data}")


class BaseDnsStateful(BaseUdpStateful, abc.ABC):
    transmitting_protocol = DnsUdpClientProtocol

    @property
    def ping_message(self) -> bytes:
        return b"google.com."

    async def receive_dns_record(self) -> Optional[DNSRecord]:
        data = await self._receive()

        if data is None:
            return data

        return DNSRecord().parse(data)

    async def send_query(self, query: DNSRecord):
        self.logger.info(f"sending: {query} to {self.remote_ip}:{self.remote_port}")
        return await self._send(query.pack())

    async def request(self, domain: str):
        await self.send_query(DNSRecord.question(domain, qtype="A"))

    async def ping(self):
        return await self.request(self.ping_message.decode())

    async def pong(self) -> bool:
        message = await self.receive_dns_record()

        if not message:
            return None

        return message.q.get_qname().idna().encode() == self.ping_message
