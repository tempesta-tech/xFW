# SPDX-FileCopyrightText: (c) 2026 Tempesta Technologies, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later

from abc import ABC
from typing import Optional

from dnslib import RR, A, DNSRecord

from framework.asyn.udp_base import BaseUdpProtocol
from framework.asyn.udp_client import UdpClient
from framework.stateful import IP4Mixin, IP6Mixin

__all__ = ["DnsUdpClient", "DnsUdpV4Client", "DnsUdpV6Client", "DnsUdpClientProtocol"]


class DnsUdpClientProtocol(BaseUdpProtocol):
    def datagram_received(self, data, addr):
        message = DNSRecord.parse(data)
        self.messages.put_nowait(message)
        self.last_address = addr
        self.logger.info(f"received from {addr} : {message}")


class DnsUdpClient(UdpClient, ABC):
    transmitting_protocol = DnsUdpClientProtocol

    async def receive(self, *args, **kwargs) -> Optional[DNSRecord]:
        return await super().receive(*args, **kwargs)

    async def send_query(self, query: DNSRecord):
        self.logger.info(f"sending: {query}")
        return await self.send_bytes(query.pack())

    async def request(self, domain: str):
        await self.send_query(DNSRecord.question(domain, qtype="A"))

    async def send_message(self):
        return await self.request("google.com")

    async def reply_for_non_existing_query(self):
        message: DNSRecord = await self.receive()

        if not message:
            return False

        reply = message.reply()
        reply.header.id += 1
        reply.add_answer(RR("google.com.", ttl=300, rdata=A("1.2.3.4")))

        await self.send_query(reply)
        return True

    async def reply_with_size_bytes(self, response_size: int):
        message: DNSRecord = await self.receive()

        if not message:
            return False

        reply = message.reply()

        ip_counter = 1

        while len(reply.pack()) < response_size:
            fake_name = f"big{ip_counter}.google_com"
            reply.add_ar(
                RR(fake_name, ttl=60, rdata=A(f"10.0.{ip_counter % 256}.{ip_counter // 256}"))
            )
            ip_counter += 1

        await self.send_query(reply)
        return True

    async def reply_with_multiple_answers(self, answers_amount: int):
        message: DNSRecord = await self.receive()

        if not message:
            return False

        reply = message.reply()

        for ip_counter in range(answers_amount):
            fake_name = f"big{ip_counter}.google_com"
            reply.add_answer(
                RR(fake_name, ttl=60, rdata=A(f"10.0.{ip_counter % 256}.{ip_counter // 256}"))
            )
            ip_counter += 1

        await self.send_query(reply)
        return True

    async def reply_with_ttl(self, ttl: int) -> bool:
        message: DNSRecord = await self.receive()

        if not message:
            return False

        reply = message.reply()
        reply.add_answer(RR("google.com.", ttl=ttl, rdata=A("1.2.3.4")))

        await self.send_query(reply)
        return True


class DnsUdpV4Client(DnsUdpClient, IP4Mixin): ...


class DnsUdpV6Client(DnsUdpClient, IP6Mixin): ...
