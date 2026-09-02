# SPDX-FileCopyrightText: (c) 2026 Tempesta Technologies, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later
from abc import ABC, abstractmethod
from contextlib import asynccontextmanager
from dataclasses import dataclass, field, fields
from typing import AsyncGenerator, Generic, Optional, Self, Union

from typing_extensions import TypeVar

from framework.utils import run_cmd
from framework.xfw import XFW


@dataclass
class BaseSingleMetric(ABC):
    name: str
    value: int = 0

    def __repr__(self) -> str:
        return f"{self.name}: {self.value}"

    def __sub__(self, other: Self) -> Self:
        self.__check_other(other)
        return self.__class__(name=self.name, value=self.value - other.value)

    def __check_other(self, other: Self) -> None:
        if not isinstance(other, BaseSingleMetric):
            raise TypeError(
                f"Incorrect metric type to action {type(other)} with {type(BaseSingleMetric)}"
            )

        if self.name != other.name:
            raise ValueError(f"Incorrect metric name to action {other.name} with {self.name}")


@dataclass
class PacketSinglePrometheusMetric(BaseSingleMetric):
    """Prometheus metric with '_packet' suffix."""

    def __repr__(self) -> str:
        return f"{super().__repr__()} packets."


@dataclass
class ByteSinglePrometheusMetric(BaseSingleMetric):
    """Prometheus metric with '_bytes' suffix."""

    def __repr__(self) -> str:
        return f"{super().__repr__()} bytes."


@dataclass
class KernelSingleMetric(BaseSingleMetric):
    """Metrics from /proc/net/netstat like SyncookieSent, etc."""


@dataclass
class BaseSingleDiffMetric(BaseSingleMetric, ABC):
    """
    This class overrides field types during comparison to improve type hinting,
    autocompletion, and static analysis within the IDE.
    """

    name: str
    value: Optional[int | list[int]] = 0


# --- ORIGINAL METRIC VALUE TYPES ---
# These type aliases are used during dataclass initialization.
# When creating an object, the user passes a raw integer (int), but after
# __post_init__ runs, the field is automatically wrapped into a metric object.
# Union allows the IDE to recognize both states without raising type-check warnings.
PacketMetricType = Union[int, PacketSinglePrometheusMetric]
ByteMetricType = Union[int, ByteSinglePrometheusMetric]
KernelMetricType = Union[int, KernelSingleMetric]

# --- METRIC DIFFERENCE TYPES (DIFF TYPES) ---
# Used in subclass variants (DiffMetrics) generated during subtraction.
# When subtracting metrics (via the __sub__ method), we get a difference.
# We override the field types for the IDE to indicate that the field no longer
# holds a full metric object, but rather a raw comparison result:
# an integer, a list of changes, or None.
PacketMetricDiffType = Union[int, list[int], None]
ByteMetricDiffType = Union[int, list[int], None]
KernelMetricDiffType = Union[int, list[int], None]

# --- GENERIC TYPE VARIABLES ---
# TypeVars with default values allow the base metric classes to behave as Generics.
# By default, they resolve to standard metric types (e.g., PacketMetricType),
# but when inheriting for Diff-classes, we can easily "swap" these parameters
# with *MetricDiffType. This prevents code duplication and ensures flawless IDE autocompletion.
T_Packets = TypeVar("T_Packets", default=PacketMetricType)
T_Bytes = TypeVar("T_Bytes", default=ByteMetricType)
T_Kernel = TypeVar("T_Kernel", default=KernelSingleMetric)


@dataclass
class InvalidMetric:
    name: str
    value: int
    expected: int | list[int]


@dataclass
class BaseMetrics(ABC):
    @property
    def default_metric_value(self) -> Optional[int]:
        return 0

    def __post_init__(self):
        """Automatically converts raw field values into metric objects."""
        for f in fields(self):
            current_value = getattr(self, f.name)

            if current_value is None:
                current_value = self.default_metric_value

            if f.name.endswith("_packets"):
                metric_class = PacketSinglePrometheusMetric
            elif f.name.endswith("_bytes"):
                metric_class = ByteSinglePrometheusMetric
            elif f.name.startswith("syncookie_"):
                metric_class = KernelSingleMetric
            else:
                continue

            setattr(self, f.name, metric_class(name=f.name, value=current_value))

    def __sub__(self, other: Self) -> Self:
        """
        Calculates the difference between the current set of metrics and another set.
        Returns a new instance of the class containing the difference in values of all fields.
        """
        if type(self) is not type(other):
            raise TypeError(f"Cannot subtract {type(other)} from {type(self)}")

        diff_metrics = self.__class__()
        for f in fields(self):
            self_metric = getattr(self, f.name)
            other_metric = getattr(other, f.name)
            setattr(diff_metrics, f.name, self_metric - other_metric)

        return diff_metrics

    @abstractmethod
    async def update(self, xfw: XFW) -> None: ...


@dataclass
class PrometheusMetrics(BaseMetrics, Generic[T_Packets, T_Bytes]):
    xfw_ip4_total_ingress_packets: T_Packets = None
    xfw_ip4_total_ingress_bytes: T_Bytes = None
    xfw_ip6_total_ingress_packets: T_Packets = None
    xfw_ip6_total_ingress_bytes: T_Bytes = None
    xfw_tcp_total_ingress_packets: T_Packets = None
    xfw_tcp_total_ingress_bytes: T_Bytes = None
    xfw_udp_total_ingress_packets: T_Packets = None
    xfw_udp_total_ingress_bytes: T_Bytes = None
    xfw_total_downstream_ingress_packets: T_Packets = None
    xfw_total_downstream_ingress_bytes: T_Bytes = None
    xfw_passed_downstream_ingress_packets: T_Packets = None
    xfw_passed_downstream_ingress_bytes: T_Bytes = None
    xfw_gre_ingress_packets: T_Packets = None
    xfw_gre_ingress_bytes: T_Bytes = None
    xfw_icmp_total_ingress_packets: T_Packets = None
    xfw_icmp_total_ingress_bytes: T_Bytes = None
    xfw_arp_ingress_packets: T_Packets = None
    xfw_arp_ingress_bytes: T_Bytes = None
    xfw_preload_ingress_packets: T_Packets = None
    xfw_preload_ingress_bytes: T_Bytes = None
    xfw_l2_unknown_egress_packets: T_Packets = None
    xfw_l2_unknown_egress_bytes: T_Bytes = None
    xfw_eth_badhdr_egress_packets: T_Packets = None
    xfw_eth_badhdr_egress_bytes: T_Bytes = None
    xfw_ip4_badhdr_egress_packets: T_Packets = None
    xfw_ip4_badhdr_egress_bytes: T_Bytes = None
    xfw_ip6_badhdr_egress_packets: T_Packets = None
    xfw_ip6_badhdr_egress_bytes: T_Bytes = None
    xfw_tcp_badhdr_egress_packets: T_Packets = None
    xfw_tcp_badhdr_egress_bytes: T_Bytes = None
    xfw_udp_badhdr_egress_packets: T_Packets = None
    xfw_udp_badhdr_egress_bytes: T_Bytes = None
    xfw_l4_unsupported_egress_packets: T_Packets = None
    xfw_l4_unsupported_egress_bytes: T_Bytes = None
    xfw_total_upstream_egress_packets: T_Packets = None
    xfw_total_upstream_egress_bytes: T_Bytes = None
    xfw_passed_upstream_egress_packets: T_Packets = None
    xfw_passed_upstream_egress_bytes: T_Bytes = None
    xfw_syn_packets: T_Packets = None
    xfw_syn_bytes: T_Bytes = None
    xfw_ack_packets: T_Packets = None
    xfw_ack_bytes: T_Bytes = None
    xfw_synack_packets: T_Packets = None
    xfw_synack_bytes: T_Bytes = None
    xfw_fin_packets: T_Packets = None
    xfw_fin_bytes: T_Bytes = None
    xfw_rst_packets: T_Packets = None
    xfw_rst_bytes: T_Bytes = None
    xfw_src_port_allowed_packets: T_Packets = None
    xfw_src_port_allowed_bytes: T_Bytes = None
    xfw_src_ip_allowed_packets: T_Packets = None
    xfw_src_ip_allowed_bytes: T_Bytes = None
    xfw_syncookie_generated_packets: T_Packets = None
    xfw_syncookie_generated_bytes: T_Bytes = None
    xfw_syncookie_received_packets: T_Packets = None
    xfw_syncookie_received_bytes: T_Bytes = None
    xfw_syncookie_failed_packets: T_Packets = None
    xfw_syncookie_failed_bytes: T_Bytes = None
    xfw_supported_protocol_ingress_packets: T_Packets = None
    xfw_supported_protocol_ingress_bytes: T_Bytes = None
    xfw_preload_egress_packets: T_Packets = None
    xfw_preload_egress_bytes: T_Bytes = None
    xfw_metadata_creation_failed_packets: T_Packets = None
    xfw_metadata_creation_failed_bytes: T_Bytes = None
    xfw_assert_failed_packets: T_Packets = None
    xfw_assert_failed_bytes: T_Bytes = None
    xfw_ip4_total_egress_packets: T_Packets = None
    xfw_ip4_total_egress_bytes: T_Bytes = None
    xfw_ip6_total_egress_packets: T_Packets = None
    xfw_ip6_total_egress_bytes: T_Bytes = None
    xfw_tcp_total_egress_packets: T_Packets = None
    xfw_tcp_total_egress_bytes: T_Bytes = None
    xfw_udp_total_egress_packets: T_Packets = None
    xfw_udp_total_egress_bytes: T_Bytes = None
    xfw_total_downstream_egress_packets: T_Packets = None
    xfw_total_downstream_egress_bytes: T_Bytes = None
    xfw_passed_downstream_egress_packets: T_Packets = None
    xfw_passed_downstream_egress_bytes: T_Bytes = None

    async def update(self, xfw: XFW) -> None:
        """
        Updates the values of existing class fields and verifies
        that all expected metrics have been received.
        """
        client = xfw.http_client()
        response = await client.get("/metrics")

        if response.status_code != 200:
            raise ValueError("Failed to get metrics from prometheus.")

        metric_names = list()
        for metric in response.text.split("\n"):
            if metric.startswith("#"):
                continue

            pair = metric.split(" ")

            if len(pair) != 2:
                continue

            key, value = pair
            metric_names.append(key)

            metric: BaseSingleMetric = getattr(self, key)
            metric.value = int(value)

        removed_metric_names = []
        for f in fields(self):
            if f.name not in metric_names:
                removed_metric_names.append(f.name)

        if removed_metric_names:
            raise AttributeError(f"Removed metric - {removed_metric_names}")


@dataclass
class KernelMetrics(BaseMetrics, Generic[T_Kernel]):
    syncookie_sent: T_Kernel = None
    syncookie_recv: T_Kernel = None
    syncookie_failed: T_Kernel = None

    async def update(self, xfw: XFW) -> None:
        """
        Updates the values of existing class fields and verifies
        that all expected metrics have been received.
        """
        code, stats, _ = await run_cmd(
            cmd="grep -A1 Syncookie /proc/net/netstat | tail -n 1 | awk '{print $2, $3, $4}'",
            logger=xfw.logger,
        )
        assert code == 0, "Can not read netstat"
        sent, received, failed = tuple((int(stat.strip()) for stat in stats.split(" ")))

        self.syncookie_sent.value = int(sent)
        self.syncookie_recv.value = int(received)
        self.syncookie_failed.value = int(failed)


@dataclass
class BaseDiffMetrics(BaseMetrics, ABC):
    """
    Abstract base class for validation and verification of captured metrics.

    This class compares expected reference metric values (or target ranges)
    against the actual metrics received (`diff_metrics`). Any discrepancies
    found during validation are recorded in the `invalid_metrics` list.
    """

    invalid_metrics: list[InvalidMetric] = field(default_factory=list, init=False)
    diff_metrics: BaseMetrics = field(default=None, init=False, repr=False)

    @property
    @abstractmethod
    def metric_cls(self) -> type[KernelMetrics | PrometheusMetrics]: ...

    @property
    def default_metric_value(self) -> Union[int, None]:
        """
        Returns the default value for target reference metrics.

        Overrides the parent class default to `None`. This allows the validation
        process to skip fields that were not explicitly specified.
        """
        return None

    def compare(self, diff_metrics: BaseMetrics) -> None:
        """
        Compares the expected target metrics against the actual metrics.

        Iterates through the dataclass fields. If the expected metric value
        is `None` (or left unspecified, falling back to the default `None`),
        the validation for that specific field is **skipped**.
        """
        for f in fields(self):
            expected_metric = getattr(self, f.name)
            if not isinstance(expected_metric, BaseSingleMetric):
                continue

            expected_metric: BaseSingleDiffMetric
            if expected_metric.value is None:
                continue

            diff: BaseSingleMetric = getattr(diff_metrics, f.name)
            expected_value = expected_metric.value
            if isinstance(expected_value, list):
                is_valid = expected_value[0] <= diff.value <= expected_value[1]
            else:
                is_valid = diff.value == expected_value

            if not is_valid:
                self.invalid_metrics.append(
                    InvalidMetric(
                        name=expected_metric.name, value=diff.value, expected=expected_value
                    )
                )


@dataclass
class PrometheusMetricsDiff(
    BaseDiffMetrics, PrometheusMetrics[PacketMetricDiffType, ByteMetricDiffType]
):
    """
    Class for validating Prometheus metric differences.

    Inherits validation logic from `BaseDiffMetrics` and the field structure from
    `PrometheusMetrics`. It overrides packet and byte field types with difference
    types (`PacketMetricDiffType`, `ByteMetricDiffType`) to provide accurate
    IDE type hinting (integer, range list, or None) during validation.
    """

    @property
    def metric_cls(self) -> type[PrometheusMetrics]:
        return PrometheusMetrics

    async def update(self, xfw: XFW) -> None: ...


@dataclass
class KernelMetricsDiff(BaseDiffMetrics, KernelMetrics[KernelMetricDiffType]):
    """
    Class for validating Kernel metric differences.

    Inherits validation logic from `BaseDiffMetrics` and the field structure from
    `KernelMetrics`. It overrides packet and byte field types with difference
    types (`KernelMetricDiffType`) to provide accurate IDE type hinting
    (integer, range list, or None) during validation.
    """

    @property
    def metric_cls(self) -> type[KernelMetrics]:
        return KernelMetrics

    async def update(self, xfw: XFW) -> None: ...


class MetricsAnalyzer:
    @asynccontextmanager
    async def expected_metrics_diff(
        self,
        xfw: XFW,
        expected_metrics: BaseDiffMetrics,
        strict: bool = True,
        wait_softirq: bool = False,
    ) -> AsyncGenerator[BaseDiffMetrics, None]:
        """
        It calculates the difference between the metrics, records it in
        `expected_metrics.diff_metrics`, and starts the validation process.
        """
        metrics_before = expected_metrics.metric_cls()
        await metrics_before.update(xfw)

        yield expected_metrics

        if wait_softirq:
            await xfw.wait_softirq()

        metrics_after = expected_metrics.metric_cls()
        await metrics_after.update(xfw)

        expected_metrics.diff_metrics = metrics_after - metrics_before
        expected_metrics.compare(expected_metrics.diff_metrics)

        invalid_metrics = expected_metrics.invalid_metrics
        if strict:
            assert len(invalid_metrics) == 0, f"Some metrics are different: {invalid_metrics}"
