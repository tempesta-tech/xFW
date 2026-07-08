# SPDX-FileCopyrightText: (c) 2026 Tempesta Technologies, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later

import pytest

from config import ConfigSettings, NetworkType, TestingModel
from framework.asyn import *
from framework.networks import (
    LocalGateVeth,
    LocalNatVeth,
    LocalVeth,
    LocalVirtualizedNIC,
)


@pytest.fixture(scope="session")
async def network(config: ConfigSettings, conf_logger) -> LocalVeth:
    network_class = {
        NetworkType.nic: LocalVirtualizedNIC,
        NetworkType.veth: LocalVeth,
        NetworkType.veth_gate: LocalGateVeth,
        NetworkType.veth_nat: LocalNatVeth,
    }.get(config.network_type)

    if not network_class:
        raise RuntimeError(
            f"Network type with config.network_type = {config.network_type}" f" does not exists."
        )

    conf_logger.info(f"Create network using {network_class.__name__} network")
    network = network_class(logger=conf_logger, config=config)
    yield network


@pytest.fixture(scope="session", autouse=True)
async def prepare_network(config: ConfigSettings, network: LocalVeth, conf_logger):
    if config.testing_model != TestingModel.same_host:
        yield
        return

    conf_logger.info("starting to prepare network")
    await network.prepare()
    conf_logger.info("network prepared")

    yield

    await network.destroy()
    conf_logger.info("network destroyed")


@pytest.fixture(scope="function")
async def flush_arp_cache(config: ConfigSettings, network: LocalVeth) -> None:
    """
    Clears the ARP and IPv6 Neighbor cache before each test.

    Why it's needed:
        Network namespaces are created once for all tests.
        If one test sends packets, the operating system remembers
        The MAC addresses of the neighbors are in a special table (cache).

    Without this fix, a domino effect occurs:
        The last test may leave "rotten" or incorrect entries in the cache.
        The next test will start using the old data from the cache instead real sending of network requests.
        The tests will become dependent on each other, which will lead to false failures (flaky tests).
    """
    await asyncio.gather(
        network.flush_arp_cache(config.backend_namespace),
        network.flush_arp_cache(config.client_namespace),
    )
    yield
