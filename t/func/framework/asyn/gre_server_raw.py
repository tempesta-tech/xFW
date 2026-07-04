# SPDX-FileCopyrightText: (c) 2026 Tempesta Technologies, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later
from scapy.layers.inet6 import ICMPv6EchoReply

from framework.asyn.gre_raw_base import BaseGreRawStateful, GreIP4Mixin, GreIP6Mixin

__all__ = ["GreRawV4Server", "GreRawV6Server"]


class GreRawV4Server(GreIP4Mixin, BaseGreRawStateful): ...


class GreRawV6Server(GreIP6Mixin, BaseGreRawStateful):
    @property
    def _icmp_layer(self):
        return ICMPv6EchoReply()
