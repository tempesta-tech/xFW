# SPDX-FileCopyrightText: (c) 2026 Tempesta Technologies, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later

import pytest


@pytest.fixture(
    params=["allow", "block"],
    ids=["allow", "block"],
)
def dst_defaults(request) -> str:
    return request.param


@pytest.fixture(
    params=["allow", "block"],
    ids=["allow", "block"],
)
def src_defaults(request) -> str:
    return request.param
