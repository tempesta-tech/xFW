# SPDX-FileCopyrightText: (c) 2026 Tempesta Technologies, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later

import json
from typing import AsyncGenerator

import pytest

from framework.xfw import XFW


@pytest.fixture
async def xfw_disable_dns_mode(
    xfw_global: XFW,
    xfw_use_rule_reset: bool,
) -> AsyncGenerator[XFW, None]:
    config = json.loads(xfw_global.config)
    original_dns_mode = config.get("dns", True)
    config["dns"] = False
    xfw_global.config = json.dumps(config)
    await xfw_global.restart()

    yield xfw_global

    config["dns"] = original_dns_mode
    xfw_global.config = json.dumps(config)
    await xfw_global.stop_or_reset(xfw_use_rule_reset)


@pytest.fixture(params=["gw", "scrubbing"])
async def xfw_deployment_mode(
    request,
    xfw_global: XFW,
    xfw_use_rule_reset: bool,
) -> AsyncGenerator[XFW, None]:
    config = json.loads(xfw_global.config)
    config["deployment-mode"] = request.param
    xfw_global.config = json.dumps(config)
    await xfw_global.restart()

    yield xfw_global

    config["deployment-mode"] = request.param
    xfw_global.config = json.dumps(config)
    await xfw_global.stop_or_reset(xfw_use_rule_reset)


async def test_dns_filter_requires_dns_mode(xfw_disable_dns_mode):
    with pytest.raises(ValueError, match="dns_filter requires DNS mode"):
        await xfw_disable_dns_mode.rules_set("xfw { dns_filter; }")


async def test_syncookies_require_host_mode(xfw_deployment_mode):
    with pytest.raises(ValueError, match="tcp_syncookies requires host deployment mode"):
        await xfw_deployment_mode.rules_set("xfw { tcp_syncookies flood_timer=1 passive_timer=1; }")
