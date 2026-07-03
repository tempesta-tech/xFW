# SPDX-FileCopyrightText: (c) 2026 Tempesta Technologies, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later

from abc import ABC

from framework.asyn.udp_base import BaseUdpStateful
from framework.remote import RemoteServer
from framework.stateful import IP4Mixin, IP6Mixin

__all__ = [
    "UdpServer",
    "UdpV4Server",
    "UdpV6Server",
    "UdpV4ServerRemote",
    "UdpV6ServerRemote",
]


class UdpServer(BaseUdpStateful, ABC): ...


class UdpV4Server(UdpServer, IP4Mixin): ...


class UdpV6Server(UdpServer, IP6Mixin): ...


class UdpV4ServerRemote(RemoteServer, UdpV4Server): ...


class UdpV6ServerRemote(RemoteServer, UdpV6Server): ...
