# SPDX-FileCopyrightText: (c) 2026 Tempesta Technologies, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later

import pytest


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption(
        "--xfw-use-rule-reset",
        action="store_true",
        default=False,
        help=(
            "After each test that uses the xfw fixture, reset XFW rules instead of "
            "restarting XFW. Without this flag xfw is restarted after each test. "
            "Tests that always need a reboot should request the xfw_restart fixture."
        ),
    )


@pytest.fixture(scope="session")
def xfw_use_rule_reset(pytestconfig: pytest.Config) -> bool:
    return pytestconfig.getoption("--xfw-use-rule-reset")
