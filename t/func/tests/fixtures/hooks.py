# SPDX-FileCopyrightText: (c) 2026 Tempesta Technologies, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later

import os.path
import subprocess
from pathlib import Path

import pytest
from pluggy import Result
from pytest import CallInfo, FixtureRequest, Item, TestReport

from config import ConfigSettings


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
