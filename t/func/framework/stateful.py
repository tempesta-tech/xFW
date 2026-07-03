# SPDX-FileCopyrightText: (c) 2026 Tempesta Technologies, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later

"""The base class for all services. Contains their state."""

import abc
import asyncio
import enum
import ipaddress
import logging
import socket
import struct
import typing

from scapy.all import Packet

from config import TestingModel
from framework.namespaces import Netns
from framework.rpc.client import RpcClient
from framework.utils import run_cmd


class State(enum.StrEnum):
    begin_start = "begin_start"
    started = "started"
    stopped = "stopped"
    error = "error"


class Stateful(abc.ABC):
    """
    Implements the state machine which is based for all
    clients and servers
    """

    def __init__(
        self,
        logger: logging.Logger = None,
        loop: asyncio.AbstractEventLoop = None,
        testing_model: TestingModel = None,
    ):
        self._state: State = State.stopped
        self.logger: logging.Logger = logger
        self.loop: asyncio.AbstractEventLoop = loop or asyncio.get_event_loop()
        self.testing_model: TestingModel = testing_model

        if not self.logger:
            self.logger = logging.getLogger(self.__class__.__name__)

    @classmethod
    def name(cls):
        """
        Returns the class name
        """
        return cls.__name__

    @property
    def state(self) -> State:
        """
        Returns the current state
        """
        return self._state

    @state.setter
    def state(self, new_state: State) -> None:
        """
        Install the new machine state
        """
        self._state = new_state

    @property
    def is_running(self):
        """
        Shows if the machine is running
        """
        return self.state == State.started

    @abc.abstractmethod
    async def run_start(self):
        """
        Start procedure
        """

    async def start(self):
        """Try to start object."""
        self.logger.debug("Starting")

        if self.state != State.stopped:
            self.logger.warning("can not start. Not stopped")
            return None

        self.state = State.begin_start
        await self.run_start()
        self.state = State.started
        self.logger.debug("successfully started")

    @abc.abstractmethod
    async def run_stop(self):
        """Base stop procedures."""

    async def stop(self):
        """Try to stop object."""
        if self.state in {State.started, State.begin_start}:
            self.logger.debug("stopping ...")
            await self.run_stop()
            self.state = State.stopped

        self.logger.info("stopped")

    async def restart(self):
        """
        Restart the state machine
        """
        self.logger.debug("going to restart")
        await self.stop()
        await self.start()


class NetworkStateful(Stateful, abc.ABC):
    """
    Provides methods for network configuration of the machine
    """

    def __init__(
        self,
        network_interface: str,
        port: int,
        *args,
        ipv4: typing.Optional[str] = None,
        ipv4_mask: int = 24,
        ipv4_testing: typing.Optional[str] = None,
        ipv6: typing.Optional[str] = None,
        ipv6_mask: int = 64,
        ipv6_testing: typing.Optional[str] = None,
        rpc_connection: RpcClient = None,
        remote_ip: str = None,
        remote_port: int = None,
        timeout: float = 0.1,
        namespace: str = None,
        **kwargs,
    ):
        super().__init__(*args, **kwargs)
        self.network_interface = network_interface
        self.port = port
        self.ipv4 = ipv4
        self.ipv4_mask = ipv4_mask
        self.ipv4_testing = ipv4_testing
        self.ipv6 = ipv6
        self.ipv6_mask = ipv6_mask
        self.ipv6_testing = ipv6_testing
        self.timeout = timeout
        self.remote_ip = remote_ip
        self.remote_port = remote_port
        self.rpc_connection = rpc_connection
        self.namespace = namespace

    def __repr__(self):
        return f"{self.ip}:{self.port}"

    @property
    def command_prefix(self) -> str:
        """
        This prefixes uses at all host commands.
        Useful to set global env vars or netns
        """
        if self.namespace and self.testing_model == TestingModel.same_host:
            return f"ip netns exec {self.namespace}"

        return ""

    async def run_host_cmd(self, cmd: str) -> tuple[int, str, str]:
        return await run_cmd(cmd=f"{self.command_prefix} {cmd}", logger=self.logger)

    @property
    def destination_address(self):
        raise NotImplementedError

    @property
    def scope_id(self):
        """
        Return the scope id of the network interfaces.
        Required by the ipv6 sockets
        """
        return socket.if_nametoindex(self.network_interface)

    @property
    def ip(self) -> str:
        """
        Return current using ip address to bind on interface
        """
        return self.ipv4 or self.ipv6

    @property
    def ip_testing(self) -> str:
        """
        Return the ip address that used in the
        XFW rules. It could be any address (if you
        are using NAT) or the real one
        """
        ip = self.ipv4_testing or self.ipv6_testing

        if ip:
            return self.ip_format(ip)

        return self.ip_format(self.ip)

    @property
    def is_ip4(self) -> bool:
        if self.ipv4:
            return True

        if self.ipv6:
            return False

        raise ValueError("Missing any IP")

    def ip_format(self, ip_address: str) -> str:
        """
        Return the ip address as a string with format acceptable by
        the XFW app
        """
        if self.ipv4:
            return ip_address

        return f"[{ip_address}]"

    @property
    def mask_formatted(self):
        """
        Return current mask
        """
        if self.ipv4:
            return self.mask_format(self.ipv4)

        return self.mask_format(self.ipv6)

    def mask_format(self, value: str):
        """
        Create mask from provided IP
        """
        if self.ipv4:
            return f"{value}/32"

        return f"{value}/128"

    def generate_new_addresses(self, amount: int = 1) -> list[str]:
        """
        Generate a list of new ip address starting from the current ip
        """
        if self.ipv4:
            return [str(ipaddress.IPv4Address(self.ipv4) + i + 1) for i in range(amount)]

        if self.ipv6:
            return [str(ipaddress.IPv6Address(self.ipv6) + i + 1) for i in range(amount)]

        raise ValueError("IP is not installed")

    def generate_new_address(self) -> str:
        """
        Generate a new one ip address based on current ip
        """
        return self.generate_new_addresses()[0]

    def generate_new_ports(self, amount: int = 1) -> list[int]:
        """
        Generate a list of new ports starting from the current port
        """
        return [self.port + i + 1 for i in range(amount)]

    def generate_new_port(self) -> int:
        """
        Generate a new port based on current port
        """
        return self.generate_new_ports()[0]

    async def additional_netns_configuration_on_start(self):
        """
        The callback called in the network namespace when the
        client socket just created
        """

    async def additional_netns_configuration_on_finish(self):
        """
        The callback called in the network namespace when the
        client socket just closed
        """

    async def start_on(self, ip: str = None, port: int = None):
        """
        Bind the current object to specified ip or port
        """
        if self.ipv4:
            self.ipv4 = ip

        if self.ipv6:
            self.ipv6 = ip

        if port is not None:
            self.port = port

        if self.state in {State.started, State.begin_start}:
            return await self.restart()

        await self.start()

    async def start(self):
        """
        Before the start add a new ip to the network
        interface used by the current object. Apply changes
        in the Network Namespace if required
        """
        try:
            if self.testing_model == TestingModel.same_host:
                async with Netns(name=self.namespace, logger=self.logger):
                    await self.set_host(
                        ipv4=self.ipv4,
                        ipv6=self.ipv6,
                        port=self.port,
                    )
                    await super().start()
                    await self.additional_netns_configuration_on_start()
            else:
                await self.set_host(
                    ipv4=self.ipv4,
                    ipv6=self.ipv6,
                    port=self.port,
                )
                await super().start()

        except OSError as e:
            if "101" in str(e):
                raise ValueError(f"Problem with network configuration: {e}") from e

            if "[Errno 49]" in str(e):
                raise ValueError(
                    f"{e}. IP={self.ip}, PORT={self.port}, SCOPE={self.scope_id}"
                ) from e

            raise ConnectionError(f"Can not start: {e}") from e

        self.logger.info(f"starting on {self.ip}:{self.port}")

    async def stop(self):
        """
        Close the client socket and call the callback function
        """
        if self.testing_model == TestingModel.same_host:
            async with Netns(name=self.namespace, logger=self.logger):
                await super().stop()
                await self.additional_netns_configuration_on_finish()

        await super().stop()

    async def set_host(
        self, ipv4: str = None, ipv6: str = None, port: int = None, iface: str = None
    ):
        """
        Add new ip address to the network interface
        """
        if ipv4 is None and ipv6 is None:
            raise ValueError("ipv4 or ipv6 should be installed")

        if port is not None:
            self.port = port

        if ipv4 is not None:
            self.ipv4 = ipv4
            cmd = f"ip addr add {self.ipv4}/{self.ipv4_mask} dev {iface or self.network_interface}"
        else:
            self.ipv6 = ipv6
            cmd = f"ip -6 addr add {self.ipv6}/{self.ipv6_mask} dev {iface or self.network_interface} nodad"

        code, _, stderr = await self.run_host_cmd(cmd=cmd)
        assert (
            code == 0 or "already assigned" in stderr or "File exists" in stderr
        ), f"Failed to add new ip address: {stderr}"

    async def set_mtu(self, size: int = 1500) -> None:
        code, _, stderr = await self.run_host_cmd(
            cmd=f"ip link set {self.network_interface} mtu {size}"
        )
        assert code == 0, f"Can not set MTU: {stderr}"

        self.logger.info(f"MTU changed to {size}")

    async def get_mac_address(self) -> str:
        code, stdout, stderr = await self.run_host_cmd(
            f"cat /sys/class/net/{self.network_interface}/address"
        )
        assert code == 0, f"Can not get MAC address: {stderr}"

        return stdout.replace("\n", "")


class SocketBaseNetworkStateful(NetworkStateful, abc.ABC):
    socket_family: int
    socket_type: int
    socket_proto: int = -1

    def __init__(self, log_msg: bool = True, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.socket: typing.Optional[socket.socket] = None
        self.sock_marker = 0x10
        self.message_polling_interval = 0.01
        self.log_msg = log_msg
        self.last_response = None
        self.last_request = None

    def create_socket(self) -> socket.socket:
        """
        Create a new socket
        """
        return socket.socket(self.socket_family, self.socket_type, self.socket_proto)

    @property
    @abc.abstractmethod
    def bind_params(self):
        """
        Define some special binding params
        """

    def set_socket_options(self, sock: socket.socket):
        """
        Set socket options
        """
        sock.setblocking(False)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_MARK, struct.pack("I", self.sock_marker))

    async def on_socket_created(self):
        """
        Callback called when socket is created
        """

    async def run_start(self):
        """
        Create new socket, bind with params and call the callback function
        """
        self.socket = self.create_socket()
        self.set_socket_options(self.socket)
        stdout, _, stderr = await run_cmd(cmd="ip a", logger=self.logger, log_output=True)
        self.socket.bind(self.bind_params)

        await self.on_socket_created()

    async def check_socket_closed(self, repeat=0, interval=0.1, retry=50):
        if self.socket_type == socket.SOCK_STREAM:
            cmd = "ss -tan"
        elif self.socket_type == socket.SOCK_DGRAM:
            cmd = "ss -uan"
        elif self.socket_type == socket.SOCK_RAW:
            cmd = "ss -wan"
        else:
            raise ValueError("Socket type not supported. Please, add filtration rule")

        formatted_ip = self.ip_format(self.ip)
        escaped_ip = formatted_ip.replace("[", "\\[").replace("]", "\\]")
        cmd = f'{cmd} | grep "{escaped_ip}:{self.port}"'
        code, stdout, stderr = await self.run_host_cmd(cmd=cmd)

        if not stdout:
            return True

        repeat += 1

        if repeat > retry:
            raise ValueError(f"{self.name()}({self}) socket is still exists: {stdout}")

        await asyncio.sleep(interval)
        return await self.check_socket_closed(repeat, interval, retry)

    async def run_stop(self):
        """
        Set RST connection close if required and close the socket
        """
        if self.socket is not None:
            self.socket.close()

        await self.check_socket_closed()
        self.logger.debug("socket is cleaned")


class RegularKernelSocketNetworkStateful(SocketBaseNetworkStateful, abc.ABC):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.transport: typing.Optional[asyncio.BaseTransport] = None
        self.protocol: typing.Optional[asyncio.BaseProtocol] = None
        self.messages: asyncio.Queue[typing.Optional[Exception | str]] = asyncio.Queue()

    @abc.abstractmethod
    async def send(self, data: str):
        """
        send data
        """

    async def send_message(self):
        """
        Send the message to the already connected server
        """
        return await self.send(data="test\n")

    async def receive(self, *_, **__) -> typing.Optional[str]:
        """
        Receive a new message from the client
        """
        try:
            msg = await asyncio.wait_for(self.messages.get(), timeout=self.timeout)

            if isinstance(msg, Exception):
                self.logger.info(f"({self}) connection closed by remote side")
                raise msg

            if self.log_msg:
                self.logger.info(f'({self}) received = "{msg}"')
            return msg
        except asyncio.TimeoutError:
            if self.log_msg:
                self.logger.info(f"({self}) timeout - no data received")
            return None

    async def receive_message(self, *args, **kwargs) -> bool:
        """
        Receive a special text message from the client
        """
        data = await self.receive()

        if not data:
            return False

        return data == "test\n"

    async def run_stop(self):
        if self.transport:
            self.transport.abort()

        await super().run_stop()


class RawSocketNetworkStateful(RegularKernelSocketNetworkStateful, abc.ABC):
    """
    The abstract class for the services based on the custom defined protocol
    uses the SOCK_RAW
    """

    socket_type = socket.SOCK_RAW

    def __init__(self, *args, auto_add_host: bool = True, **kwargs):
        super().__init__(*args, **kwargs)
        self.auto_add_host = auto_add_host

    @abc.abstractmethod
    def create_packet(self, packet: Packet) -> Packet:
        """
        Build or modify packet to send
        """

    @abc.abstractmethod
    def get_sendto_dst(self) -> tuple:
        """
        The tuple with destination address and destination port
        """

    @abc.abstractmethod
    def decode_data(self, data: bytes) -> Packet:
        """
        Decode received data from the server
        """


class IP4Mixin(SocketBaseNetworkStateful, abc.ABC):
    socket_family = socket.AF_INET
    iptables_binary_name = "iptables"

    @property
    def bind_params(self):
        return self.ip, self.port

    @property
    def destination_address(self):
        return self.remote_ip, self.remote_port


class IP6Mixin(SocketBaseNetworkStateful, abc.ABC):
    socket_family = socket.AF_INET6
    iptables_binary_name = "ip6tables"

    @property
    def bind_params(self):
        return self.ip, self.port, 0, self.scope_id

    @property
    def destination_address(self):
        return self.remote_ip, self.remote_port, 0, 0
