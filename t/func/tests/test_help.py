# SPDX-FileCopyrightText: (c) 2026 Tempesta Technologies, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later

import logging

import pytest

from config import ConfigSettings
from framework.xfw import XFW


def print_cmd(cmd: str, description: str, logger):
    logger.info(f"# {description:30}")
    logger.info(f" {cmd}")


@pytest.mark.prepare_network
async def test_prepare_local_veth_network(
    xfw: XFW,
    tcp_ip4_client,
    tcp_ip6_client,
    tcp_ip4_server,
    tcp_ip6_server,
    conf_logger: logging.Logger,
    config: ConfigSettings,
):
    # this part is required to add
    # ip addresses to the link
    server_and_clients = [tcp_ip4_server, tcp_ip4_client, tcp_ip6_server, tcp_ip6_client]
    for item in server_and_clients:
        await item.start()

    for item in server_and_clients:
        await item.stop()

    conf_logger.log_level = logging.DEBUG

    conf_logger.info("---------------------------------------")
    conf_logger.info("          Network prepared             ")
    conf_logger.info("---------------------------------------")
    conf_logger.info(f"Logger config: {xfw.tfw_logger_config_file}")
    conf_logger.info(f"Logger file  : {xfw.tfw_logger_log_file}")
    conf_logger.info(f"XFW config   : {xfw.path_to_config}")
    conf_logger.info(f"XFW Iface    : {tcp_ip4_server.network_interface}")
    conf_logger.info(f"XFW IPv4     : {xfw.ipv4}")
    conf_logger.info(f"Backend Iface: {tcp_ip4_server.network_interface}")
    conf_logger.info(f"Backend IPv4 : {tcp_ip4_server.ip}")
    conf_logger.info(f"Backend IPv6 : {tcp_ip6_server.ip}")
    conf_logger.info(f"Client NetNS : {tcp_ip6_client.namespace}")
    conf_logger.info(f"Client Iface : {tcp_ip4_client.network_interface}")
    conf_logger.info(f"Client IPv4  : {tcp_ip4_client.ip}")
    conf_logger.info(f"Client IPv6  : {tcp_ip6_client.ip}")
    conf_logger.info("---------------------------------------")
    conf_logger.info("          Userful commands             ")
    conf_logger.info("---------------------------------------")
    print_cmd(
        cmd=f"{xfw.path_to_executable} --status", description="XFW status", logger=conf_logger
    )
    print_cmd(
        cmd=f"ip -n {tcp_ip4_client.namespace} a",
        description="Show the namespace configuration",
        logger=conf_logger,
    )
    print_cmd(
        cmd=f"nc -l -s {tcp_ip4_server.ip} -p {tcp_ip4_server.port}",
        description="Start the TCP server",
        logger=conf_logger,
    )
    print_cmd(
        cmd=f"ip netns exec {tcp_ip4_client.namespace} nc {tcp_ip4_server.ip} {tcp_ip4_server.port}",
        description="Start the TCP client",
        logger=conf_logger,
    )
    print_cmd(
        cmd=f"nc -u -l -s {tcp_ip4_server.ip} -p {tcp_ip4_server.port}",
        description="Start the UDP server",
        logger=conf_logger,
    )
    print_cmd(
        cmd=f"ip netns exec {tcp_ip4_client.namespace} nc -u {tcp_ip4_server.ip} {tcp_ip4_server.port}",
        description="Start the UDP client",
        logger=conf_logger,
    )
    conf_logger.info("---------------------------------------")
    conf_logger.info("             Commands                  ")
    conf_logger.info("---------------------------------------")
    conf_logger.info("e, exit - Close the Interpreter and destroy the network.")
    conf_logger.info("---------------------------------------")

    while True:
        conf_logger.info("Enter command: ")
        data = input()

        if data in {"exit", "e"}:
            break
