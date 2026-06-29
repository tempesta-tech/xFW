# SPDX-FileCopyrightText: (c) 2026 Tempesta Technologies, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later

from abc import ABC

from framework.stateful import IP4Mixin, IP6Mixin
from framework.asyn.udp_base import BaseUdpStateful


__all__ = ['UdpClient', 'UdpV4Client', 'UdpV6Client', 'BaseUdpStateful']


class UdpClient(BaseUdpStateful, ABC):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)


class UdpV4Client(UdpClient, IP4Mixin):
    def __init__(self, *args, **kwargs):
        UdpClient.__init__(self, *args, **kwargs)
        IP4Mixin.__init__(self, *args, **kwargs)



class UdpV6Client(UdpClient, IP6Mixin):
    def __init__(self, *args, **kwargs):
        UdpClient.__init__(self, *args, **kwargs)
        IP6Mixin.__init__(self, *args, **kwargs)
