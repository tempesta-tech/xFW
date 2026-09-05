# SPDX-FileCopyrightText: (c) 2026 Tempesta Technologies, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later

from abc import ABC

from framework.asyn.udp_base import BaseUdpStateful
from framework.stateful import IP4Mixin, IP6Mixin

__all__ = ["UdpClient", "UdpV4Client", "UdpV6Client", "BaseUdpStateful"]


class UdpClient(BaseUdpStateful): ...


class UdpV4Client(UdpClient, IP4Mixin): ...


class UdpV6Client(UdpClient, IP6Mixin): ...
