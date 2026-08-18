# SPDX-FileCopyrightText: (c) 2026 Tempesta Technologies, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later

import enum
from typing import Optional

from pydantic_settings import BaseSettings, SettingsConfigDict


class NetworkType(enum.IntEnum):
    veth = 0
    veth_gate = 1
    nic = 2
    veth_nat = 3


class TestingModel(enum.IntEnum):
    # Use namespaces to run tests on same machine
    same_host = 0

    # Clients and server on separated machines.
    # Mode define the client's machine.
    machine_local = 1


class ConfigSettings(BaseSettings):
    log_level: Optional[int] = None
    server_workdir: str = "/tmp/server"
    tests_log_dir: str = "/tmp/xfw_tests_log/"

    network_type: NetworkType = NetworkType.veth
    testing_model: TestingModel = TestingModel.same_host

    rpc_host: str = ""
    rpc_port: int = 6666
    rpc_log_file: str = "/tmp/server.log"
    rpc_daemonize: bool = False
    rpc_cmd_timeout: float = 1
    rpc_stop_if_not_connections_sec: int = 10

    tfw_logger_clickhouse_host: str = "localhost"
    tfw_logger_clickhouse_binary_port: int = 9000
    tfw_logger_clickhouse_http_port: int = 8123
    tfw_logger_clickhouse_user: str = "default"
    tfw_logger_clickhouse_password: str = ""
    tfw_logger_clickhouse_db: str = "default"
    tfw_logger_clickhouse_table: str = "incident_log"
    tfw_logger_clickhouse_max_events: int = 1000
    tfw_logger_clickhouse_max_wait_ms: int = 100

    xfw_interface: str = "xfwb1"
    xfw_devices_mode: str = "skb"
    xfw_server_iface: str = "xfwb1"
    xfw_build_dir: str = "/opt/tempesta"
    xfw_grpc_ip: str = "20.0.0.1"
    xfw_grpc_port: int = 4444
    xfw_http_port: int = 9090
    xfw_config_path: str = "/tmp/xfw.json"
    xfw_logger_config_path: str = "/tmp/tfw_logger.json"
    xfw_logger_log_file: str = "/tmp/tfw_logger.log"
    xfw_manager_log_file: str = "/tmp/xfw_manager.log"
    xfw_geolite2_country_db_url: str = (
        "https://tempesta-tech.com:8081/repository"
        "/maven-releases/files/geolite2-country"
        "/20251021/geolite2-country-20251021.tar.gz"
    )
    xfw_ddos_examples_url: str = (
        "https://tempesta-tech.com:8081/repository"
        "/maven-releases/files/ddos/examples/ddos-examples.zip"
    )
    xfw_ddos_examples_temp_dir: str = "/tmp/ddos_examples"
    xfw_geolite2_country_db_path: str = "/tmp/geolite2-country.mmdb"

    backend_interface_host: str = "xfwb0"
    backend_ipv4_host: str = "20.0.0.1"
    backend_ipv6_host: str = "fd00:20::1"
    backend_interface: str = "xfwb1"
    backend_namespace: str = "xfw-nb"
    backend_ipv4: str = "20.0.0.2"
    backend_ipv6: str = "fd00:20::2"
    backend_ipv4_mask: int = 24
    backend_ipv6_mask: int = 64
    backend_port: int = 10000

    gateway_nft_table_name: str = "xfw"
    gateway_nft_table_name_path: str = "/tmp/xfw.nft"
    gateway_ip4_backend: str = "30.0.0.1"
    gateway_ip6_backend: str = "fe00:20::1"
    gateway_ip4_xfw: str = "30.0.0.3"
    gateway_ip6_xfw: str = "fe00:20::3"

    client_interface_host: str = "xfwc0"
    client_ipv4_host: str = "109.245.0.1"
    client_ipv6_host: str = "2001:8c8::1"
    client_interface: str = "xfwc1"
    client_namespace: str = "xfw-nc"
    client_ipv4: str = "109.245.0.2"
    client_ipv6: str = "2001:8c8::2"
    client_ipv4_mask: int = 24
    client_ipv6_mask: int = 64
    client_port: int = 50000

    timeout_sec: float = 0.1
    load_duration: float = 5.0  # seconds
    ratelimit_tolerance_factor: float = 1.2  # 20%

    tcpreplay_exec_file: str = "tcpreplay"
    tcprewrite_exec_file: str = "tcprewrite"

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")


settings = ConfigSettings()
