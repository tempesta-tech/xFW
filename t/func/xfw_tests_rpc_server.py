# SPDX-FileCopyrightText: (c) 2026 Tempesta Technologies, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later

import asyncio
import os
import signal
import sys

from config import ConfigSettings
from framework.clickhouse import ClickhouseClient
from framework.logger import get_logger
from framework.rpc.server import RpcServer


def daemonize(log_path: str):
    """
    Turns the process into the daemon
    """
    if os.fork():
        sys.exit(0)

    os.setsid()
    os.umask(0)

    if os.fork():
        sys.exit(0)

    with open("/dev/null", "r") as f:
        os.dup2(f.fileno(), sys.stdin.fileno())

    log_file = open(log_path, "a", buffering=1)
    os.dup2(log_file.fileno(), sys.stdout.fileno())
    os.dup2(log_file.fileno(), sys.stderr.fileno())


if __name__ == "__main__":
    """
    Start the RPC-Server
    """

    config = ConfigSettings()

    if config.rpc_daemonize:
        print("Starting RPC Daemon")
        daemonize(config.rpc_log_file)

    logger = get_logger("server")
    logger.info("RPC Server")
    run_server = True
    loop = asyncio.new_event_loop()
    loop.set_debug(True)
    asyncio.set_event_loop(loop)

    logger.info(f"Listening on {config.rpc_host}:{config.rpc_port}")

    clickhouse_client = ClickhouseClient(
        host=config.tfw_logger_clickhouse_host,
        binary_port=config.tfw_logger_clickhouse_binary_port,
        http_port=config.tfw_logger_clickhouse_http_port,
        user=config.tfw_logger_clickhouse_user,
        password=config.tfw_logger_clickhouse_password,
        database=config.tfw_logger_clickhouse_db,
        table=ClickhouseClient.gen_new_table_name(),
        logger=get_logger("clickhouse"),
    )
    rpc_server = RpcServer(
        host=config.rpc_host,
        port=config.rpc_port,
        cmd_timeout=config.rpc_cmd_timeout,
        stop_if_not_connections_sec=config.rpc_stop_if_not_connections_sec,
        clickhouse_client=clickhouse_client,
    )
    task = loop.create_task(rpc_server.run())

    logger.info(f"Waiting for a new connection...")

    loop.add_signal_handler(signal.SIGTERM, task.cancel)
    loop.add_signal_handler(signal.SIGINT, task.cancel)

    try:
        loop.run_until_complete(task)

    except asyncio.CancelledError:
        pass

    finally:
        loop.run_until_complete(loop.shutdown_asyncgens())
        loop.close()
        logger.info("Server stopped")
