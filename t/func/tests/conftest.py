# SPDX-FileCopyrightText: (c) 2026 Tempesta Technologies, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later


pytest_plugins = [
    # the most important
    "tests.fixtures.common",
    "tests.fixtures.network",
    # other utils and hooks
    "tests.fixtures.parameters",
    "tests.fixtures.clickhouse",
    "tests.fixtures.xfw",
    "tests.fixtures.clonners",
    "tests.fixtures.rpc",
    "tests.fixtures.rules",
    "tests.fixtures.hooks",
    # client and servers
    "tests.fixtures.proto.base",
    "tests.fixtures.proto.eth",
    "tests.fixtures.proto.gre",
    "tests.fixtures.proto.udp",
    "tests.fixtures.proto.tcp",
    "tests.fixtures.proto.icmp",
    "tests.fixtures.proto.dns",
    "tests.fixtures.proto.traffic_replay",
    "tests.fixtures.proto.shared",
]
