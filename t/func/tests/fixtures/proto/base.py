# SPDX-FileCopyrightText: (c) 2026 Tempesta Technologies, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later

from typing import Literal

import pytest


@pytest.fixture(params=["udp", "tcp"])
def protocol(request) -> Literal["udp", "tcp"]:
    return request.param


@pytest.fixture(params=["ip4", "ip6"])
def ip_version(request) -> Literal["ip4", "ip6"]:
    return request.param
