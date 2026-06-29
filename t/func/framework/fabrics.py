# SPDX-FileCopyrightText: (c) 2026 Tempesta Technologies, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later

import socket

from typing import Type, TypeVar, Union

from config import ConfigSettings, TestingModel, NetworkType
from framework.logger import get_logger


TClient = TypeVar('TClient')
TLocalServer = TypeVar('TLocalServer')
TRemoteServer = TypeVar('TRemoteServer')


def client_fabric(
        config: ConfigSettings,
        logging_level: int,
        local_class: Type[TClient],
        remote_port: int = None,
        force_ip4: bool = False,
        **extra_params,
) -> TClient:
    """
    Creates the client instance based on the configuration
    """
    bind_ip4 = force_ip4 or (local_class.socket_family == socket.AF_INET)

    if bind_ip4:
        ip_v4 = config.client_ipv4
        ip_v4_mask = config.client_ipv4_mask
        ip_v6 = None
        ip_v6_mask = None
        backend_ip = config.backend_ipv4
    else:
        ip_v4 = None
        ip_v4_mask = None
        ip_v6 = config.client_ipv6
        ip_v6_mask = config.client_ipv6_mask
        backend_ip = config.backend_ipv6

    params = dict(
        network_interface=config.client_interface,
        ipv4=ip_v4,
        ipv4_mask=ip_v4_mask,
        ipv6=ip_v6,
        ipv6_mask=ip_v6_mask,
        port=config.client_port,
        remote_ip=backend_ip,
        remote_port=remote_port or config.backend_port,
        logger=get_logger(local_class.name(), level=logging_level),
        namespace=config.client_namespace,
        testing_model=config.testing_model,
        timeout=config.timeout_sec,
    )
    params.update(extra_params)

    if config.network_type == NetworkType.veth_nat:
        if bind_ip4:
            params['remote_ip'] = config.backend_ipv4_host
        else:
            params['remote_ip'] = config.backend_ipv6_host

    return local_class(**params)


def server_fabric(
        config: ConfigSettings,
        logging_level: int,
        rpc_connection,
        local_class: Type[TLocalServer],
        remote_class: Type[TRemoteServer],
        port: int = None,
        force_ip4: bool = False,
        **extra_params
) -> Union[TLocalServer, TRemoteServer]:
    """
    Creates the server instance based on the configuration
    and local/server class
    """
    cls = local_class

    if config.testing_model != TestingModel.same_host:
        cls = remote_class

    bind_ip4 = force_ip4 or (local_class.socket_family == socket.AF_INET)

    if bind_ip4:
        ip_v4 = config.backend_ipv4
        ip_v4_mask = config.backend_ipv4_mask
        ip_v6 = None
        ip_v6_mask = None
        client_ip = config.client_ipv4
    else:
        ip_v4 = None
        ip_v4_mask = None
        ip_v6 = config.backend_ipv6
        ip_v6_mask = config.backend_ipv6_mask
        client_ip = config.client_ipv6

    params = dict(
        network_interface=config.backend_interface,
        ipv4=ip_v4,
        ipv4_mask=ip_v4_mask,
        ipv6=ip_v6,
        ipv6_mask=ip_v6_mask,
        port=port or config.backend_port,
        logger=get_logger(local_class.name(), level=logging_level),
        testing_model=config.testing_model,
        rpc_connection=rpc_connection,
        timeout=config.timeout_sec,
        remote_ip=client_ip,
        remote_port=config.client_port,
    )
    params.update(extra_params)

    if config.network_type in {NetworkType.veth_gate, NetworkType.veth_nat}:
        params['namespace'] = config.backend_namespace

    if config.network_type == NetworkType.veth_nat:
        if bind_ip4:
            params['ipv4_testing'] = config.backend_ipv4_host
        else:
            params['ipv6_testing'] = config.backend_ipv6_host

    return cls(**params)


def xfw_fabric(
        config: ConfigSettings,
        logging_level: int,
        rpc_connection,
        clickhouse_client,
        local_class: Type[TLocalServer],
        remote_class: Type[TRemoteServer],
        geo: bool = False,
        **extra_params,
) -> Union[TLocalServer, TRemoteServer]:
    """
    Creates the XFW instance based on the configuration,
    local/server class and the geoip feature
    """
    cls = local_class

    if config.testing_model != TestingModel.same_host:
        cls = remote_class

    params = dict(
        build_dir=config.xfw_build_dir,
        network_interface=config.xfw_interface,
        ipv4=config.xfw_grpc_ip,
        port=config.xfw_grpc_port,
        http_port=config.xfw_http_port,
        logger=get_logger(local_class.name(), level=logging_level),
        path_to_config=config.xfw_config_path,
        rpc_connection=rpc_connection,
        testing_model=config.testing_model,
        timeout=config.timeout_sec,
        server_iface=config.xfw_server_iface,
        tfw_logger_config_file=config.xfw_logger_config_path,
        xfw_logger_log_file=config.xfw_logger_log_file,
        xfw_manager_log_file=config.xfw_manager_log_file,
        tfw_logger_max_events=config.tfw_logger_clickhouse_max_events,
        tfw_logger_max_wait_ms=config.tfw_logger_clickhouse_max_wait_ms,
        clickhouse_client=clickhouse_client,
        devices_mode=config.xfw_devices_mode,
    )
    params.update(extra_params)

    if geo:
        params['geolite2_db_path'] = config.xfw_geolite2_country_db_path

    return cls(**params)
