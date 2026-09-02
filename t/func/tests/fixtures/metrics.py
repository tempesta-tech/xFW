# SPDX-FileCopyrightText: (c) 2026 Tempesta Technologies, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later
import pytest

from framework.metrics import KernelMetrics, MetricsAnalyzer, PrometheusMetrics


@pytest.fixture
def prometheus_metrics() -> PrometheusMetrics:
    return PrometheusMetrics()


@pytest.fixture
def kernel_metrics() -> KernelMetrics:
    return KernelMetrics()


@pytest.fixture
def metric_analyzer() -> MetricsAnalyzer:
    return MetricsAnalyzer()
