# SPDX-FileCopyrightText: (c) 2026 Tempesta Technologies, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later
from scapy.layers.inet6 import ICMPv6EchoRequest

from framework.asyn.gre_raw_base import BaseGreRawStateful, GreIP4Mixin, GreIP6Mixin

__all__ = ["GreRawV4Client", "GreRawV6Client"]


class GreRawV4Client(GreIP4Mixin, BaseGreRawStateful): ...


class GreRawV6Client(GreIP6Mixin, BaseGreRawStateful):
    @property
    def _icmp_layer(self):
        return ICMPv6EchoRequest()
