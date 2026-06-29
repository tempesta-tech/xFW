# SPDX-FileCopyrightText: (c) 2026 Tempesta Technologies, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later

from abc import ABC

from framework.stateful import IP4Mixin, IP6Mixin
from framework.remote import RemoteServer
from framework.asyn.udp_base import BaseUdpStateful


__all__ = [
    'UdpServer', 'UdpV4Server', 'UdpV6Server',
    'UdpV4ServerRemote', 'UdpV6ServerRemote',
]


class UdpServer(BaseUdpStateful, ABC):
    ...


class UdpV4Server(UdpServer, IP4Mixin):
    def __init__(self, *args, **kwargs) -> None:
        UdpServer.__init__(self, *args, **kwargs)
        IP4Mixin.__init__(self, *args, **kwargs)


class UdpV6Server(UdpServer, IP6Mixin):
    def __init__(self, *args, **kwargs) -> None:
        UdpServer.__init__(self, *args, **kwargs)
        IP6Mixin.__init__(self, *args, **kwargs)


class UdpV4ServerRemote(RemoteServer, UdpV4Server):
    def __init__(self, *args, **kwargs) -> None:
        RemoteServer.__init__(self, *args, **kwargs)
        UdpV4Server.__init__(self, *args, **kwargs)


class UdpV6ServerRemote(RemoteServer, UdpV6Server):
    def __init__(self, *args, **kwargs) -> None:
        RemoteServer.__init__(self, *args, **kwargs)
        UdpV6Server.__init__(self, *args, **kwargs)
