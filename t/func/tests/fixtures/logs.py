# SPDX-FileCopyrightText: (c) 2026 Tempesta Technologies, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later
import asyncio
import os.path
import shutil
import subprocess
from pathlib import Path

import pytest
from pytest import FixtureRequest, TestReport

from config import ConfigSettings
from framework.sniffer import TcpdumpSniffer


@pytest.fixture(autouse=True, scope="session")
def _clean_log_dir(config):
    if os.path.exists(config.tests_log_dir):
        shutil.rmtree(config.tests_log_dir)
    os.makedirs(config.tests_log_dir, exist_ok=True)


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


@pytest.fixture(autouse=True, scope="function")
async def __tcpdump_test_lifecycle(request: FixtureRequest, tmp_path: Path, config, conf_logger):
    if "disable_tcpdump" in request.keywords:
        yield
        return

    client_temp = tmp_path / "client_capture.pcap"
    server_temp = tmp_path / "server_capture.pcap"

    async with (
        TcpdumpSniffer(path=client_temp, namespace=config.client_namespace, logger=conf_logger),
        TcpdumpSniffer(path=server_temp, namespace=config.client_namespace, logger=conf_logger),
    ):
        yield

    report_call: TestReport = getattr(request.node, "rep_call", None)

    if report_call is None or report_call.failed:
        target_dir = Path(config.tests_log_dir)
        target_dir.mkdir(parents=True, exist_ok=True)

        loop = asyncio.get_running_loop()

        if client_temp.exists():
            await loop.run_in_executor(
                None,
                lambda: shutil.move(
                    str(client_temp), str(target_dir / f"{request.node.name}_client.pcap")
                ),
            )
        if server_temp.exists():
            await loop.run_in_executor(
                None,
                lambda: shutil.move(
                    str(server_temp), str(target_dir / f"{request.node.name}_server.pcap")
                ),
            )
