# SPDX-FileCopyrightText: (c) 2026 Tempesta Technologies, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later

import socket

from scapy.data import ETH_P_ALL

from framework.asyn.ether_raw_client import EtherRawClient
from framework.remote import RemoteServer


class EtherRawServer(EtherRawClient):
    socket_proto = socket.htons(ETH_P_ALL)


class EtherRawServerRemote(RemoteServer, EtherRawServer):
    def __init__(self, *args, **kwargs):
        RemoteServer.__init__(self, *args, **kwargs)
        EtherRawServer.__init__(self, *args, **kwargs)
