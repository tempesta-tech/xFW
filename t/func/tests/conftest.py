# SPDX-FileCopyrightText: (c) 2026 Tempesta Technologies, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later

import logging
import os.path
import subprocess
import tarfile
from io import BytesIO
from pathlib import Path
from typing import Literal

import httpx
import pytest
from pluggy import Result
from pytest import CallInfo, FixtureRequest, Item, TestReport

from config import ConfigSettings, NetworkType, TestingModel
from framework.asyn import *
from framework.clickhouse import ClickhouseClient
from framework.fabrics import client_fabric, server_fabric, xfw_fabric
from framework.logger import get_logger
from framework.networks import (
    LocalGateVeth,
    LocalNatVeth,
    LocalVeth,
    LocalVirtualizedNIC,
)
from framework.rpc.client import RpcClient
from framework.stateful import RegularKernelSocketNetworkStateful
from framework.utils import ClonerCallable
from framework.xfw import XFW, XFWRemote


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


@pytest.fixture
def event_loop(event_loop_policy: asyncio.AbstractEventLoopPolicy) -> asyncio.AbstractEventLoop:
    return event_loop_policy.get_event_loop()


@pytest.fixture(scope="session")
def config() -> ConfigSettings:
    settings = ConfigSettings()
    yield settings


@pytest.fixture(scope="session")
def logging_level(config) -> int:
    root_logger = logging.getLogger()
    # Take config.log_level if set, otherwise root_logger.level
    config_level = config.log_level or root_logger.level
    # Return the minimum (more detailed) between config and root
    return min(config_level, root_logger.level)


@pytest.fixture(scope="session")
def conf_logger(logging_level) -> logging.Logger:
    logger = get_logger("root", level=logging_level)
    logger.propagate = False

    logger = get_logger("pytest-conf", level=logging_level)
    yield logger


@pytest.fixture(scope="session", autouse=True)
async def prepare_geolite2_country_db(config: ConfigSettings, conf_logger):
    if os.path.exists(config.xfw_geolite2_country_db_path):
        conf_logger.info("Skipped downloading GeoIP2-Country.mmdb. " "File already exists")
        return

    async with httpx.AsyncClient() as client:
        response = await client.get(config.xfw_geolite2_country_db_url)

    if response.status_code != 200:
        raise FileExistsError("Can not download GeoIP DB from Nexus")

    file = BytesIO(response.content)
    tar = tarfile.open(fileobj=file)
    mmdb_filename = [key for key in tar.getnames() if "mmdb" in key]

    if not len(mmdb_filename):
        raise FileNotFoundError("Can not find mmdb file in geolite2 db archive")

    mmdb_filename = mmdb_filename[0]
    mmdb = tar.extractfile(mmdb_filename)

    with open(config.xfw_geolite2_country_db_path, "wb") as f:
        f.write(mmdb.read())

    conf_logger.info("Downloaded GeoIP2-Country.mmdb")


@pytest.fixture(autouse=True, scope="session")
async def rpc_connection(config: ConfigSettings, conf_logger) -> RpcClient:
    if config.testing_model == TestingModel.same_host:
        yield
        return

    server = f"{config.rpc_host}:{config.rpc_port}"
    rpc_client = RpcClient(host=config.rpc_host, port=config.rpc_port)

    conf_logger.info(f"establishing connection to RPC Server {server}")
    await rpc_client.run()

    yield rpc_client

    await rpc_client.shutdown_server()
    await rpc_client.shutdown()

    conf_logger.info(f"closed connection to RPC Server {server}")


@pytest.fixture(scope="session")
def network_class(config: ConfigSettings):
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

    return network_class


@pytest.fixture(scope="session", autouse=True)
async def prepare_network(config: ConfigSettings, network_class, conf_logger):
    if config.testing_model != TestingModel.same_host:
        yield
        return

    conf_logger.info("starting to prepare network")

    conf_logger.info(f"using {network_class.__name__} network")
    network = network_class(logger=conf_logger, config=config)

    await network.prepare()
    conf_logger.info("network prepared")

    yield

    await network.destroy()
    conf_logger.info("network destroyed")


@pytest.fixture(autouse=True, scope="function")
def __log_test_lifecycle(request: FixtureRequest, config: ConfigSettings):
    """Save XFW logs."""
    relative_file_path = Path(request.node.path).relative_to(Path(os.getcwd()))
    test_function_name = request.node.name
    test_name = f"{relative_file_path}::{test_function_name}"

    temporary_log_file = Path(f"{config.tests_log_dir}/temporary.log")
    temporary_log_file.unlink(missing_ok=True)
    temporary_log_file.parent.mkdir(parents=True, exist_ok=True)

    # we must kill all zombie processes for trace_pipe before the test
    subprocess.run(
        "fuser -k -9 /sys/kernel/tracing/trace_pipe",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=True,
    )
    with open(temporary_log_file, "w") as log_file:
        p = subprocess.Popen(
            ["cat", "/sys/kernel/tracing/trace_pipe"],
            stdout=log_file,
            stderr=subprocess.DEVNULL,
        )
        subprocess.run(
            f'echo "{'\t' * 7}START TEST: "{test_name}"" >> {config.xfw_logger_log_file}',
            shell=True,
        )
        subprocess.run(
            f'echo "START TEST: "{test_name}"" >> {config.xfw_manager_log_file}', shell=True
        )
        yield
        subprocess.run(
            f'echo "FINISH TEST: "{test_name}"" >> {config.xfw_manager_log_file}', shell=True
        )
        subprocess.run(
            f'echo "{'\t' * 7}FINISH TEST: "{test_name}"" >> {config.xfw_logger_log_file}',
            shell=True,
        )
        p.kill()
        p.wait()
    report_call: TestReport = getattr(request.node, "rep_call", None)
    if report_call is None or report_call.failed:
        subprocess.run(
            f"mv {temporary_log_file} {config.tests_log_dir}{test_function_name}.log", shell=True
        )


@pytest.fixture
async def clickhouse_client(
    config: ConfigSettings,
    logging_level: int,
):
    new_client = ClickhouseClient(
        host=config.tfw_logger_clickhouse_host,
        binary_port=config.tfw_logger_clickhouse_binary_port,
        http_port=config.tfw_logger_clickhouse_http_port,
        user=config.tfw_logger_clickhouse_user,
        password=config.tfw_logger_clickhouse_password,
        database=config.tfw_logger_clickhouse_db,
        table=ClickhouseClient.gen_new_table_name(),
        logger=get_logger("clickhouse", level=logging_level),
    )
    yield new_client

    if not new_client.was_connected:
        return

    await new_client.connect()
    await new_client.table_drop()


@pytest.fixture
async def xfw(
    config: ConfigSettings,
    logging_level: int,
    rpc_connection: Optional[RpcClient],
    clickhouse_client: ClickhouseClient,
) -> XFW:
    xfw = xfw_fabric(
        config=config,
        logging_level=logging_level,
        rpc_connection=rpc_connection,
        local_class=XFW,
        remote_class=XFWRemote,
        clickhouse_client=clickhouse_client,
    )
    try:
        await xfw.start()
        yield xfw
    finally:
        await xfw.stop()


@pytest.fixture
async def xfw_geoip(
    config: ConfigSettings,
    logging_level: int,
    rpc_connection: Optional[RpcClient],
    clickhouse_client: ClickhouseClient,
) -> XFW:
    xfw = xfw_fabric(
        config=config,
        logging_level=logging_level,
        rpc_connection=rpc_connection,
        local_class=XFW,
        remote_class=XFWRemote,
        geo=True,
        clickhouse_client=clickhouse_client,
    )

    try:
        await xfw.start()
    except AssertionError as e:
        await xfw.stop()
        pytest.fail(f"The XFW service have not started in time. Error: {e}")

    yield xfw
    await xfw.stop()


@pytest.fixture
async def tcp_ip4_server(
    config: ConfigSettings, logging_level: int, rpc_connection: Optional[RpcClient]
) -> TcpServer:
    new_server = server_fabric(
        config=config,
        logging_level=logging_level,
        rpc_connection=rpc_connection,
        local_class=TcpV4Server,
        remote_class=TcpV4ServerRemote,
    )
    yield new_server
    await new_server.stop()


@pytest.fixture
async def tcp_ip4_raw_server(
    config: ConfigSettings, logging_level: int, rpc_connection: Optional[RpcClient]
) -> TcpRawServer:
    new_server = server_fabric(
        config=config,
        logging_level=logging_level,
        rpc_connection=rpc_connection,
        local_class=TcpIpV4RawServer,
        remote_class=TcpIpV4RawServerRemote,
    )
    yield new_server
    await new_server.stop()


@pytest.fixture
async def tcp_ip6_server(
    config: ConfigSettings, logging_level: int, rpc_connection: Optional[RpcClient]
) -> TcpServer:
    new_server = server_fabric(
        config=config,
        logging_level=logging_level,
        rpc_connection=rpc_connection,
        local_class=TcpV6Server,
        remote_class=TcpV6ServerRemote,
    )
    yield new_server
    await new_server.stop()


@pytest.fixture
async def tcp_ip6_raw_server(
    config: ConfigSettings, logging_level: int, rpc_connection: Optional[RpcClient]
) -> TcpServer:
    new_server = server_fabric(
        config=config,
        logging_level=logging_level,
        rpc_connection=rpc_connection,
        local_class=TcpIpV6RawServer,
        remote_class=TcpIpV6RawServerRemote,
    )
    yield new_server
    await new_server.stop()


@pytest.fixture
async def tcp_ip4_client(
    config: ConfigSettings,
    logging_level: int,
) -> TcpClient:
    new_client = client_fabric(
        config=config,
        logging_level=logging_level,
        local_class=TcpV4Client,
    )
    yield new_client
    await new_client.stop()


@pytest.fixture
async def tcp_ip4_raw_client(
    config: ConfigSettings,
    logging_level: int,
) -> TcpRawClient:
    new_client = client_fabric(
        config=config,
        logging_level=logging_level,
        local_class=TcpIpV4RawClient,
    )
    yield new_client
    await new_client.stop()


@pytest.fixture
async def tcp_ip6_client(
    config: ConfigSettings,
    logging_level: int,
) -> TcpClient:
    new_client = client_fabric(
        config=config,
        logging_level=logging_level,
        local_class=TcpV6Client,
    )
    yield new_client
    await new_client.stop()


@pytest.fixture
async def tcp_ip6_raw_client(
    config: ConfigSettings,
    logging_level: int,
) -> TcpRawClient:
    new_client = client_fabric(
        config=config,
        logging_level=logging_level,
        local_class=TcpIpV6RawClient,
    )
    yield new_client
    await new_client.stop()


@pytest.fixture
async def udp_ip4_server(
    config: ConfigSettings, logging_level: int, rpc_connection: Optional[RpcClient]
) -> UdpServer:
    new_server = server_fabric(
        config=config,
        logging_level=logging_level,
        rpc_connection=rpc_connection,
        local_class=UdpV4Server,
        remote_class=UdpV4ServerRemote,
    )
    yield new_server
    await new_server.stop()


@pytest.fixture
async def udp_ip6_server(
    config: ConfigSettings, logging_level: int, rpc_connection: Optional[RpcClient]
) -> UdpServer:
    new_server = server_fabric(
        config=config,
        logging_level=logging_level,
        rpc_connection=rpc_connection,
        local_class=UdpV6Server,
        remote_class=UdpV6ServerRemote,
    )
    yield new_server
    await new_server.stop()


@pytest.fixture
async def udp_ip4_client(
    config: ConfigSettings,
    logging_level: int,
) -> UdpClient:
    new_client = client_fabric(
        config=config,
        logging_level=logging_level,
        local_class=UdpV4Client,
    )
    yield new_client
    await new_client.stop()


@pytest.fixture
async def udp_ip4_raw_client(
    config: ConfigSettings,
    logging_level: int,
) -> UdpRawClient:
    new_client = client_fabric(
        config=config,
        logging_level=logging_level,
        local_class=UdpIpV4RawClient,
    )
    yield new_client
    await new_client.stop()


@pytest.fixture
async def udp_ip6_client(
    config: ConfigSettings,
    logging_level: int,
) -> UdpClient:
    new_client = client_fabric(
        config=config,
        logging_level=logging_level,
        local_class=UdpV6Client,
    )
    yield new_client
    await new_client.stop()


@pytest.fixture
async def udp_ip6_raw_client(
    config: ConfigSettings,
    logging_level: int,
) -> UdpRawClient:
    new_client = client_fabric(
        config=config,
        logging_level=logging_level,
        local_class=UdpIpV6RawClient,
    )
    yield new_client
    await new_client.stop()


@pytest.fixture
async def icmp_ip4_raw_client(
    config: ConfigSettings,
    logging_level: int,
) -> IcmpRawClient:
    new_client = client_fabric(
        config=config,
        logging_level=logging_level,
        local_class=IcmpRawV4Client,
    )
    yield new_client
    await new_client.stop()


@pytest.fixture
async def icmp_ip6_raw_client(
    config: ConfigSettings,
    logging_level: int,
) -> IcmpRawClient:
    new_client = client_fabric(
        config=config,
        logging_level=logging_level,
        local_class=IcmpRawV6Client,
    )
    yield new_client
    await new_client.stop()


@pytest.fixture
async def gre_ip4_raw_client(
    config: ConfigSettings,
    logging_level: int,
) -> GreRawClient:
    new_client = client_fabric(
        config=config,
        logging_level=logging_level,
        local_class=GreRawV4Client,
    )
    yield new_client
    await new_client.stop()


@pytest.fixture
async def gre_ip6_raw_client(
    config: ConfigSettings,
    logging_level: int,
) -> GreRawClient:
    new_client = client_fabric(
        config=config,
        logging_level=logging_level,
        local_class=GreRawV6Client,
    )
    yield new_client
    await new_client.stop()


@pytest.fixture(params=["udp", "tcp"])
def protocol(request) -> Literal["udp", "tcp"]:
    return request.param


@pytest.fixture(params=["ip4", "ip6"])
def ip_version(request) -> Literal["ip4", "ip6"]:
    return request.param


@pytest.fixture(scope="function")
async def client_cloner(server_cloner) -> ClonerCallable:
    """
    server_cloner: The server cloner fixture. Required to enforce the correct teardown sequence in pytest.

    Note on Lifecycle & Teardown Order:
        Pytest executes fixture teardown blocks (the code after `yield`) in
        reverse order of their initialization (LIFO - Last In, First Out).

        By making `client_cloner` explicitly depend on `server_cloner`, we
        guarantee the following graceful shutdown sequence after each test:

        1. Client Cleanup First: The teardown block in this fixture runs first,
           stopping and cleaning up all active client clones.
        2. Server Cleanup Second: Pytest then proceeds to `server_cloner`'s
           teardown block, shutting down the servers.

        This specific order prevents active clients from attempting to send
        traffic to already closed server sockets, avoiding intermittent
        'ConnectionResetError' exceptions or hung test processes.
    """
    _clones: list[RegularKernelSocketNetworkStateful] = []

    def wrapper(
        cloner: RegularKernelSocketNetworkStateful, amount: int, fabric: Optional[typing.Any] = None
    ) -> list[RegularKernelSocketNetworkStateful]:
        nonlocal _clones

        ports = cloner.generate_new_ports(amount)
        addresses = cloner.generate_new_addresses(amount)

        class_to_create = fabric if fabric else cloner.__class__

        for port, address in zip(ports, addresses):
            _clones.append(
                class_to_create(
                    network_interface=cloner.network_interface,
                    ipv4=address if cloner.ipv4 else None,
                    ipv4_mask=cloner.ipv4_mask if cloner.ipv4 else None,
                    ipv6=address if cloner.ipv6 else None,
                    ipv6_mask=cloner.ipv6_mask if cloner.ipv6 else None,
                    port=port,
                    remote_ip=cloner.remote_ip,
                    remote_port=cloner.remote_port,
                    logger=cloner.logger,
                    namespace=cloner.namespace,
                    testing_model=cloner.testing_model,
                    timeout=cloner.timeout,
                )
            )
        return _clones

    yield wrapper

    await asyncio.gather(*[clone.stop() for clone in _clones], return_exceptions=True)
    _clones.clear()


@pytest.fixture(scope="function")
async def server_cloner() -> ClonerCallable:
    _clones: list[RegularKernelSocketNetworkStateful] = []

    def wrapper(
        cloner: RegularKernelSocketNetworkStateful, amount: int, fabric: Optional[typing.Any] = None
    ) -> list[RegularKernelSocketNetworkStateful]:
        nonlocal _clones

        ports = cloner.generate_new_ports(amount)
        addresses = cloner.generate_new_addresses(amount)

        class_to_create = fabric if fabric else cloner.__class__

        for port, address in zip(ports, addresses):
            _clones.append(
                class_to_create(
                    network_interface=cloner.network_interface,
                    ipv4=address if cloner.ipv4 else None,
                    ipv4_mask=cloner.ipv4_mask if cloner.ipv4 else None,
                    ipv6=address if cloner.ipv6 else None,
                    ipv6_mask=cloner.ipv6_mask if cloner.ipv6 else None,
                    port=port,
                    logger=cloner.logger,
                    testing_model=cloner.testing_model,
                    rpc_connection=cloner.rpc_connection,
                    timeout=cloner.timeout,
                    namespace=cloner.namespace,
                )
            )
        return _clones

    yield wrapper

    await asyncio.gather(*[clone.stop() for clone in _clones], return_exceptions=True)
    _clones.clear()


@pytest.fixture
def server(
    config: ConfigSettings, request: FixtureRequest, protocol: str, ip_version: str
) -> RegularKernelSocketNetworkStateful:
    return request.getfixturevalue(f"{protocol}_{ip_version}_server")


@pytest.fixture
def client(request: FixtureRequest, protocol, ip_version) -> RegularKernelSocketNetworkStateful:
    return request.getfixturevalue(f"{protocol}_{ip_version}_client")


@pytest.fixture
def tcp_server(config: ConfigSettings, request: FixtureRequest, ip_version: str) -> TcpServer:
    return request.getfixturevalue(f"tcp_{ip_version}_server")


@pytest.fixture
def tcp_raw_server(request: FixtureRequest, ip_version) -> TcpServer:
    return request.getfixturevalue(f"tcp_{ip_version}_raw_server")


@pytest.fixture
def tcp_client(request: FixtureRequest, ip_version) -> TcpClient:
    return request.getfixturevalue(f"tcp_{ip_version}_client")


@pytest.fixture
def tcp_raw_client(request: FixtureRequest, ip_version) -> TcpRawClient:
    return request.getfixturevalue(f"tcp_{ip_version}_raw_client")


@pytest.fixture
def udp_server(config: ConfigSettings, request: FixtureRequest, ip_version: str) -> UdpServer:
    return request.getfixturevalue(f"udp_{ip_version}_server")


@pytest.fixture
def udp_client(request: FixtureRequest, ip_version) -> UdpClient:
    return request.getfixturevalue(f"udp_{ip_version}_client")


@pytest.fixture
def udp_raw_client(request: FixtureRequest, ip_version) -> UdpRawClient:
    return request.getfixturevalue(f"udp_{ip_version}_raw_client")


@pytest.fixture
def icmp_raw_client(request: FixtureRequest, ip_version) -> IcmpRawClient:
    return request.getfixturevalue(f"icmp_{ip_version}_raw_client")


@pytest.fixture
def gre_raw_client(request: FixtureRequest, ip_version) -> GreRawClient:
    return request.getfixturevalue(f"gre_{ip_version}_raw_client")


@pytest.fixture
async def establish_connection(client, server):
    await server.start()
    await client.start()
    yield


@pytest.fixture
async def start_tcp_server_and_clients(tcp_server, tcp_client):
    await tcp_server.start()
    await tcp_client.start()
    yield


@pytest.fixture
async def start_tcp_server_and_raw_clients(tcp_server, tcp_raw_client):
    await tcp_server.start()
    await tcp_raw_client.start()
    yield


@pytest.fixture
async def start_tcp_raw_server_and_raw_clients(tcp_raw_server, tcp_raw_client):
    await tcp_raw_server.start()
    await tcp_raw_client.start()
    yield


@pytest.fixture
async def start_udp_server_and_clients(udp_server, udp_client):
    await udp_server.start()
    await udp_client.start()
    yield


@pytest.fixture
async def start_udp_server_and_raw_clients(udp_server, udp_raw_client):
    await udp_server.start()
    await udp_raw_client.start()
    yield


@pytest.fixture
async def start_udp_server_and_icmp_clients(udp_server, icmp_raw_client):
    await udp_server.start()
    await icmp_raw_client.start()
    yield


@pytest.fixture
async def start_udp_server_and_gre_clients(udp_server, gre_raw_client):
    await udp_server.start()
    await gre_raw_client.start()
    yield


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


@pytest.fixture
def remaining_client_server_group(
    client: RegularKernelSocketNetworkStateful,
    server: RegularKernelSocketNetworkStateful,
    udp_ip4_client: RegularKernelSocketNetworkStateful,
    udp_ip4_server: RegularKernelSocketNetworkStateful,
    udp_ip6_client: RegularKernelSocketNetworkStateful,
    udp_ip6_server: RegularKernelSocketNetworkStateful,
    tcp_ip4_client: RegularKernelSocketNetworkStateful,
    tcp_ip4_server: RegularKernelSocketNetworkStateful,
    tcp_ip6_client: RegularKernelSocketNetworkStateful,
    tcp_ip6_server: RegularKernelSocketNetworkStateful,
) -> dict[RegularKernelSocketNetworkStateful, RegularKernelSocketNetworkStateful]:
    group = {
        udp_ip4_client: udp_ip4_server,
        udp_ip6_client: udp_ip6_server,
        tcp_ip4_client: tcp_ip4_server,
        tcp_ip6_client: tcp_ip6_server,
    }
    group.pop(client)
    yield group


@pytest.fixture
async def dns_udp_ip4_server(
    config: ConfigSettings,
    logging_level: int,
    rpc_connection: Optional[RpcClient],
) -> UdpServer:
    # mark: HARDCODED_53_PORT
    # XFW currently hardcoded to 53 port
    # port=config.backend_port,

    new_server = server_fabric(
        config=config,
        logging_level=logging_level,
        rpc_connection=rpc_connection,
        local_class=DnsUdpV4Server,
        remote_class=DnsUdpV4ServerRemote,
        port=53,
    )
    yield new_server
    await new_server.stop()


@pytest.fixture
async def dns_udp_ip6_server(
    config: ConfigSettings,
    logging_level: int,
    rpc_connection: Optional[RpcClient],
) -> UdpServer:
    # mark: HARDCODED_53_PORT
    # XFW currently hardcoded to 53 port
    # port=config.backend_port,

    new_server = server_fabric(
        config=config,
        logging_level=logging_level,
        rpc_connection=rpc_connection,
        local_class=DnsUdpV6Server,
        remote_class=DnsUdpV6ServerRemote,
        port=53,
    )
    yield new_server
    await new_server.stop()


@pytest.fixture
async def dns_udp_ip4_client(
    config: ConfigSettings,
    logging_level: int,
) -> DnsUdpClient:
    # mark: HARDCODED_53_PORT
    # XFW currently hardcoded to 53 port
    # remote_port=config.backend_port,
    new_client = client_fabric(
        config=config, logging_level=logging_level, local_class=DnsUdpV4Client, remote_port=53
    )
    yield new_client
    await new_client.stop()


@pytest.fixture
async def dns_udp_ip6_client(
    config: ConfigSettings,
    logging_level: int,
) -> DnsUdpClient:
    # mark: HARDCODED_53_PORT
    # XFW currently hardcoded to 53 port
    # remote_port=config.backend_port,
    new_client = client_fabric(
        config=config, logging_level=logging_level, local_class=DnsUdpV6Client, remote_port=53
    )
    yield new_client
    await new_client.stop()


@pytest.fixture
def dns_udp_server(
    config: ConfigSettings, request: FixtureRequest, ip_version: str
) -> DnsUdpServer:
    return request.getfixturevalue(f"dns_udp_{ip_version}_server")


@pytest.fixture
def dns_udp_client(
    config: ConfigSettings, request: FixtureRequest, ip_version: str
) -> DnsUdpClient:
    return request.getfixturevalue(f"dns_udp_{ip_version}_client")


@pytest.fixture
async def start_dns_udp_server_and_clients(dns_udp_server, dns_udp_client):
    await dns_udp_server.start()
    await dns_udp_client.start()
    yield


@pytest.fixture
async def traffic_replay_client(
    config: ConfigSettings,
    logging_level: int,
) -> TrafficReplayClient:
    new_client = client_fabric(
        config=config,
        logging_level=logging_level,
        local_class=TrafficReplayClient,
        force_ip4=True,
        tcpreplay_exec_file=config.tcpreplay_exec_file,
        tcprewrite_exec_file=config.tcprewrite_exec_file,
    )
    yield new_client
    await new_client.stop()


@pytest.fixture
async def ether_raw_client(
    config: ConfigSettings,
    logging_level: int,
):
    new_client = client_fabric(
        config=config,
        logging_level=logging_level,
        local_class=EtherRawClient,
        force_ip4=True,
    )
    yield new_client
    await new_client.stop()


@pytest.fixture
async def ether_raw_server(
    config: ConfigSettings,
    logging_level: int,
    rpc_connection: Optional[RpcClient],
):
    new_client = server_fabric(
        config=config,
        logging_level=logging_level,
        rpc_connection=rpc_connection,
        local_class=EtherRawServer,
        remote_class=EtherRawServerRemote,
        force_ip4=True,
    )
    yield new_client
    await new_client.stop()
