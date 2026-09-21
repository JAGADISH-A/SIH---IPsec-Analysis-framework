"""Prometheus-compatible operational metrics (stdlib only).

A small registry with counters, gauges and histograms that renders the
Prometheus text exposition format directly:

    # TYPE sih_events_received counter
    sih_events_received 42

Metrics are observational only; they never feed security decisions. Timing is
recorded from an injected monotonic clock so tests stay deterministic.
"""

import time
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional

PROMETHEUS_MIME = "text/plain; version=0.0.4; charset=utf-8"


def monotonic_clock() -> float:
    return time.monotonic()


class Counter:
    def __init__(self, name: str, help_text: str, labels: List[str] | None = None) -> None:
        self.name = name
        self.help_text = help_text
        self.labels = labels or []
        self._values: Dict[tuple, float] = {}

    def inc(self, value: float = 1.0, **label_values: object) -> None:
        key = tuple(label_values.get(k, "") for k in self.labels) if self.labels else ()
        self._values[key] = self._values.get(key, 0.0) + value

    def render(self) -> str:
        lines = [f"# HELP {self.name} {self.help_text}", f"# TYPE {self.name} counter"]
        for key, value in sorted(self._values.items()):
            labels = self._label_suffix(key)
            lines.append(f"{self.name}{labels} {value:g}")
        return "\n".join(lines)

    def _label_suffix(self, key: tuple) -> str:
        if not self.labels:
            return ""
        pairs = ",".join(f'{n}="{v}"' for n, v in zip(self.labels, key))
        return "{" + pairs + "}"


class Gauge:
    def __init__(self, name: str, help_text: str, labels: List[str] | None = None) -> None:
        self.name = name
        self.help_text = help_text
        self.labels = labels or []
        self._values: Dict[tuple, float] = {}

    def set(self, value: float, **label_values: object) -> None:
        key = tuple(label_values.get(k, "") for k in self.labels) if self.labels else ()
        self._values[key] = float(value)

    def render(self) -> str:
        lines = [f"# HELP {self.name} {self.help_text}", f"# TYPE {self.name} gauge"]
        for key, value in sorted(self._values.items()):
            labels = self._label_suffix(key)
            lines.append(f"{self.name}{labels} {value:g}")
        return "\n".join(lines)

    def _label_suffix(self, key: tuple) -> str:
        if not self.labels:
            return ""
        pairs = ",".join(f'{n}="{v}"' for n, v in zip(self.labels, key))
        return "{" + pairs + "}"


class Histogram:
    """Simple histogram (count/sum + fixed buckets)."""

    BUCKETS = (0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0)

    def __init__(self, name: str, help_text: str, buckets: List[float] | None = None) -> None:
        self.name = name
        self.help_text = help_text
        self.buckets = sorted(buckets or list(self.BUCKETS))
        self._count = 0.0
        self._sum = 0.0
        self._buckets = {b: 0.0 for b in self.buckets}

    def observe(self, value: float) -> None:
        self._count += 1
        self._sum += value
        for bound in self.buckets:
            if value <= bound:
                self._buckets[bound] += 1

    def render(self) -> str:
        out = [f"# HELP {self.name} {self.help_text}", f"# TYPE {self.name} histogram"]
        inf = float("inf")
        for bound in self.buckets:
            out.append(f'{self.name}_bucket{{le="{bound:g}"}} {self._buckets[bound]:g}')
        out.append(f'{self.name}_bucket{{le="+Inf"}} {self._count:g}')
        out.append(f"{self.name}_sum {self._sum:g}")
        out.append(f"{self.name}_count {self._count:g}")
        return "\n".join(out)


class MetricsRegistry:
    """Named registry rendering the Prometheus exposition format."""

    def __init__(self) -> None:
        self._metrics: Dict[str, object] = {}

    def register(self, metric: object) -> object:
        self._metrics[getattr(metric, "name")] = metric
        return metric

    def counter(self, name: str, help_text: str = "") -> Counter:
        return self.register(Counter(name, help_text or name))

    def gauge(self, name: str, help_text: str = "") -> Gauge:
        return self.register(Gauge(name, help_text or name))

    def histogram(self, name: str, help_text: str = "") -> Histogram:
        return self.register(Histogram(name, help_text or name))

    def render(self) -> str:
        blocks = []
        for name in sorted(self._metrics):
            blocks.append(self._metrics[name].render())
        return "\n".join(blocks) + "\n"


class Phase10Metrics:
    """The concrete Phase-10 metric set (all required observables)."""

    def __init__(self, clock: Callable[[], float] | None = None) -> None:
        self.clock = clock or monotonic_clock
        self.registry = MetricsRegistry()
        self.events_received = self.registry.counter("sih_events_received", "Events received")
        self.events_processed = self.registry.counter("sih_events_processed", "Events processed")
        self.events_failed = self.registry.counter("sih_events_failed", "Events failed")
        self.events_dropped = self.registry.counter("sih_events_dropped", "Events dropped")
        self.kafka_lag = self.registry.gauge("sih_kafka_lag", "Kafka consumer lag")
        self.consumer_retries = self.registry.counter("sih_consumer_retries", "Consumer retries")
        self.dlq_count = self.registry.gauge("sih_dlq_count", "Dead-letter queue length")
        self.window_count = self.registry.counter("sih_window_count", "Completed windows")
        self.late_events = self.registry.counter("sih_late_events", "Late events")
        self.duplicate_events = self.registry.counter("sih_duplicate_events", "Duplicates")
        self.ml_latency = self.registry.histogram("sih_ml_latency_seconds", "ML inference latency")
        self.correlation_latency = self.registry.histogram(
            "sih_correlation_latency_seconds", "Correlation latency"
        )
        self.risk_latency = self.registry.histogram("sih_risk_latency_seconds", "Risk latency")
        self.response_latency = self.registry.histogram(
            "sih_response_latency_seconds", "Response planning latency"
        )
        self.execution_success = self.registry.counter(
            "sih_execution_success", "Successful controlled executions"
        )
        self.execution_failure = self.registry.counter(
            "sih_execution_failure", "Failed controlled executions"
        )
        self.pcap_downloads = self.registry.counter("sih_pcap_downloads", "PCAP downloads")

    def render(self) -> str:
        return self.registry.render()

    def collect_all(self) -> List[object]:
        return [self.registry._metrics[name] for name in sorted(self.registry._metrics)]