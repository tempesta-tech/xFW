# SPDX-FileCopyrightText: (c) 2026 Tempesta Technologies, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later


pytest_plugins = [
    # the most important
    "tests.fixtures.common",
    "tests.fixtures.network",
    # other utils and hooks
    "tests.fixtures.metrics",
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


def pytest_configure(config):
    markers = [
        "prepare_network: The specific task for network preparation",
        "nic_e1000_warmup: The NIC e1000 requires ipv4 and ipv6 warmup",
        "skip_on_e1000: Skip the test running on e1000 NIC",
        "skip_on_virtio: Skip the test running on virtio",
        "only_in_gate_mode: Tests are allowed only in Gate Mode",
        "fail_in_gate_mode: Test does not work XFW Gateway Mode",
        "clickhouse: Tests require Clickhouse to be installed. Test cases are running not on all network configurations",
        "long: Test takes too much time to be launched locally usually. However it should be run on CI.",
        "ddos_simulating: In the test DDoS simulating and it can take more time and more machine resources",
        "not_in_fast_mode: dont run the test in fast mode",
    ]

    for marker in markers:
        config.addinivalue_line("markers", marker)
