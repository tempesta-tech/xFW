# SPDX-FileCopyrightText: (c) 2026 Tempesta Technologies, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later

import socket

from scapy.data import ETH_P_ALL

from framework.asyn.ether_raw_client import EtherRawClient


class EtherRawServer(EtherRawClient):
    socket_proto = socket.htons(ETH_P_ALL)
