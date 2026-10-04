# SPDX-FileCopyrightText: (c) 2026 Tempesta Technologies, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later

import json

import pytest

from framework.xfw import XFW


async def test_dns_filter_requires_dns_mode(xfw: XFW):
    config = json.loads(xfw.config)
    config["dns"] = False
    await xfw.set_config(json.dumps(config))
    await xfw.restart()

    with pytest.raises(ValueError, match="dns_filter requires DNS mode"):
        await xfw.rules_set("xfw { dns_filter; }")


@pytest.mark.parametrize("deployment_mode", ["gw", "scrubbing"])
async def test_syncookies_require_host_mode(xfw: XFW, deployment_mode: str):
    config = json.loads(xfw.config)
    config["deployment-mode"] = deployment_mode
    await xfw.set_config(json.dumps(config))
    await xfw.restart()

    with pytest.raises(ValueError, match="tcp_syncookies requires host deployment mode"):
        await xfw.rules_set("xfw { tcp_syncookies flood_timer=1 passive_timer=1; }")
