# SPDX-FileCopyrightText: (c) 2026 Tempesta Technologies, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later
import pytest
from pluggy import Result
from pytest import CallInfo, Item, TestReport

from framework.xfw import XfwMode

pytest_plugins = [
    # the most important
    "tests.fixtures.common",
    "tests.fixtures.network",
    # other utils and hooks
    "tests.fixtures.clickhouse",
    "tests.fixtures.clonners",
    "tests.fixtures.logs",
    "tests.fixtures.metrics",
    "tests.fixtures.parameters",
    "tests.fixtures.rpc",
    "tests.fixtures.rules",
    "tests.fixtures.xfw",
    # client and servers
    "tests.fixtures.proto.base",
    "tests.fixtures.proto.dns",
    "tests.fixtures.proto.eth",
    "tests.fixtures.proto.gre",
    "tests.fixtures.proto.icmp",
    "tests.fixtures.proto.shared",
    "tests.fixtures.proto.tcp",
    "tests.fixtures.proto.traffic_replay",
    "tests.fixtures.proto.udp",
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
        "xfw_mode(mode): set up mode for XFW",
        "disable_tcpdump: not run tcpdump fixture for a test",
    ]

    for marker in markers:
        config.addinivalue_line("markers", marker)


def pytest_generate_tests(metafunc):
    """
    Pytest hook for dynamic test parameterization based on XFW modes.

    This hook checks if the test context requests the 'xfw_mode' fixture.
    If a specific mode is provided via the '@pytest.mark.xfw_mode' marker,
    the test is parameterized with that single mode. Otherwise, it automatically
    parameterizes the test across all available modes in `XfwMode`.
    """
    if "xfw_mode_param" not in metafunc.fixturenames:
        return

    cli_mode = metafunc.config.getoption("--xfw-mode")
    marker = metafunc.definition.get_closest_marker("xfw_mode")
    allowed_modes = [marker.args[0]] if marker else list(XfwMode)

    modes = [cli_mode] if cli_mode is not None else allowed_modes
    metafunc.parametrize("xfw_mode_param", modes)


def pytest_collection_modifyitems(config, items):
    """
    Deselect tests whose 'xfw_mode' marker conflicts with '--xfw-mode'.

    If no CLI mode is specified, leave all collected tests selected.
    Otherwise, retain tests without the marker or with a matching mode,
    remove incompatible tests from 'items' in place, and notify pytest
    via 'pytest_deselected' so they are reported as deselected.
    """
    cli_mode = config.getoption("--xfw-mode")
    if cli_mode is None:
        return

    selected = []
    deselected = []

    for item in items:
        marker = item.get_closest_marker("xfw_mode")

        if marker is not None and cli_mode != marker.args[0]:
            deselected.append(item)
        else:
            selected.append(item)

    if deselected:
        items[:] = selected
        config.hook.pytest_deselected(items=deselected)


@pytest.hookimpl(tryfirst=True, hookwrapper=True)
def pytest_runtest_makereport(item: Item, call: CallInfo) -> None:
    """
    Save test result to item.
    After completing the test in other hooks or fixtures, you can ger report:
    report_call: TestReport = getattr(request.node, "rep_call", None) # fixtures
    report_call: TestReport = getattr(item, "rep_call", None) # hooks
    """
    outcome: Result = yield
    report: TestReport = outcome.get_result()
    setattr(item, f"rep_{report.when}", report)
