# SPDX-FileCopyrightText: (c) 2026 Tempesta Technologies, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later

from typing import Literal

import pytest

_protocol_type = Literal["udp", "tcp"]
_ip_version_type = Literal["ip4", "ip6"]

_PROTOCOLS = ("udp", "tcp")
_IP_VERSIONS = ("ip4", "ip6")


@pytest.fixture(scope="session")
def protocols() -> set[_protocol_type]:
    return _PROTOCOLS


@pytest.fixture(scope="session")
def ip_versions() -> set[_ip_version_type]:
    return _IP_VERSIONS


@pytest.fixture(params=_PROTOCOLS)
def protocol(request) -> _protocol_type:
    return request.param


@pytest.fixture(params=_IP_VERSIONS)
def ip_version(request) -> _ip_version_type:
    return request.param
