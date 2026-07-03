# SPDX-FileCopyrightText: (c) 2026 Tempesta Technologies, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later

import abc
import asyncio
import socket
import time
import typing
from typing import Optional

from scapy.layers.inet import TCP, Packet

from framework.stateful import SocketBaseNetworkStateful
from framework.utils import switch_coroutine

__all__ = [
    "BaseTcpRawStateful",
]


class BaseTcpRawStateful(SocketBaseNetworkStateful):
    iptables_binary_name: str
    socket_type = socket.SOCK_RAW
    socket_proto = socket.IPPROTO_TCP

    def __init__(
        self,
        *args,
        auto_add_host: bool = True,
        auto_ack_seq: bool = True,
        log_requests: bool = True,
        **kwargs,
    ):
        super().__init__(*args, **kwargs)

        self.auto_add_host = auto_add_host
        self.auto_ack_seq = auto_ack_seq
        self.log_requests = log_requests
        self.block_kernel_rst = True
        self.filter_packets = True

        self.sock_marker = 0x10
        self.seq = None
        self.ack = None
        self.last_request: typing.Optional[TCP] = None
        self.last_response: typing.Optional[TCP] = None
        self.sender_info: tuple[str, int] = None

    @staticmethod
    def has_flag(packet: TCP | None, flag: str) -> bool:
        if not packet:
            return False

        return flag in str(packet.flags)

    @classmethod
    def has_any_flag(cls, packet: TCP, flags: set[str]) -> bool:
        for flag in flags:
            if cls.has_flag(packet, flag):
                return True

        return False

    def is_packet_my(self, packet: Packet) -> bool:
        if not packet.haslayer(TCP):
            return False

        if packet[TCP].dport != self.port:
            return False

        return True

    async def block_kernel_rst_package_from_unknown_client(self):
        """
        Linux kernel sends RST packet if incoming package is
        addressed to the socket which is not created in
        the kernel. Kernel sees that raw packet is TCP, but
        there is not such SOCK_STREAM.

        To prevent RST from kernel we can block them with
        iptables by special SKB MARKER that was
        added to the socket on socket creating
        """
        code, _, error = await self.run_host_cmd(
            f"{self.iptables_binary_name} -I OUTPUT 1 -p tcp --tcp-flags RST RST "
            f"-m mark --mark {self.sock_marker} -j ACCEPT",
        )
        assert code == 0, f"Can not set iptables rule to allow RST from current app: {error}"

        code, _, error = await self.run_host_cmd(
            f"{self.iptables_binary_name} -A OUTPUT -p tcp --tcp-flags RST RST -j DROP"
        )
        assert code == 0, f"Can not set iptables rule to block RST from kernel: {error}"

    async def on_socket_created(self):
        if not self.block_kernel_rst:
            return

        await self.block_kernel_rst_package_from_unknown_client()

    async def receive(self, buffer_len: int = 1024) -> typing.Optional[TCP]:
        try:
            response = await asyncio.wait_for(
                self.loop.sock_recvfrom(self.socket, buffer_len), timeout=self.timeout
            )
        except asyncio.TimeoutError:
            if self.log_requests:
                self.logger.info(f"{self} timeout - no data received")

            return None

        data, self.sender_info = response
        decoded = self.decode_data(data)

        if self.filter_packets and not self.is_packet_my(decoded):
            self.logger.debug(f"{self} Skipped packet : {decoded}")
            return await self.receive()

        self.last_response = decoded[TCP]

        if self.has_flag(self.last_response, "S"):
            self.ack = self.last_response.seq + 1
        elif self.has_flag(self.last_response, "F"):
            self.ack = self.last_response.seq + 1
        elif self.has_flag(self.last_response, "P"):
            self.ack = self.last_response.seq + len(self.last_response.payload)

        if self.log_requests:
            self.logger.info(
                f"received from {self.remote_ip}:{self.remote_port} "
                f'"{self.last_response}, seq={self.last_response.seq}, ack={self.last_response.ack}"'
            )

        return self.last_response

    async def receive_data(self) -> Optional[str]:
        response = await self.receive()

        if not response:
            return None

        if self.has_flag(response, "PA"):
            await self.send(TCP(flags="A"))

        return response.payload.load.decode()

    async def send(self, packet: TCP) -> int:
        if self.seq is None:
            self.seq = packet.seq or 0

        if self.last_request:
            packet.options = packet.options

        if self.auto_add_host:
            packet.sport = self.port
            packet.dport = self.remote_port

        if self.auto_ack_seq:
            packet.seq = self.seq
            packet.ack = self.ack

            for index, option in enumerate(packet.options):
                if option[0].lower() == "timestamp":
                    packet.options[index] = ("Timestamp", (int(time.time()), 0))

        scapy_packet = self.create_packet(packet)

        if self.has_flag(packet, "S"):
            self.seq += 1
        elif self.has_flag(packet, "F"):
            self.seq += 1
        elif self.has_flag(packet, "P"):
            self.seq += len(packet.payload)

        self.last_request = scapy_packet

        if self.log_requests:
            self.logger.info(
                f'{self} sending to {self.remote_ip}:{self.remote_port} "{scapy_packet}, '
                f'seq={scapy_packet.seq}, ack={scapy_packet.ack}"'
            )

        return await asyncio.wait_for(
            self.loop.sock_sendto(self.socket, bytes(scapy_packet), self.get_sendto_dst()),
            timeout=3,
        )

    async def send_data(self, payload: str) -> bool:
        await self.send(TCP(flags="PA") / payload.encode())
        response = await self.receive()

        if not response:
            return False

        return self.has_flag(response, "A")

    @abc.abstractmethod
    async def handshake(self) -> bool:
        """
        3-step handshake realization
        """

    async def close_connection(self) -> bool:
        await self.send(TCP(flags="FA"))

        response = await self.receive()
        assert response is not None, "Server did not replied"

        if self.has_any_flag(response, {"RA", "AR"}):
            return True

        if self.has_any_flag(response, {"FA", "AF"}):
            await self.send(TCP(flags="A"))
            return True

        assert self.has_flag(
            response, "A"
        ), f"Unexpected reply packet with flags = {response.flags}. Expected A"

        await switch_coroutine()

        response = await self.receive()
        assert response is not None, "Server did not replied"

        assert self.has_any_flag(
            response, {"FA", "AF"}
        ), f"Server replied with invalid packet: {response.flags}. Expected FA"

        await self.send(TCP(flags="A"))

        return True

    async def reset_send(self):
        await self.send(TCP(flags="R"))
        return True

    async def reset_receive(self) -> bool:
        response = await self.receive()
        assert response is not None, "RST was not received"

        return self.has_flag(response, "R")
