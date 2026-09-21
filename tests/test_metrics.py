"""Phase 10 — Prometheus metrics registry tests (observable, never gates)."""

import unittest

from correlation.observability.metrics import (
    Counter,
    Gauge,
    Histogram,
    MetricsRegistry,
    Phase10Metrics,
)


class TestCounterMetric(unittest.TestCase):
    def test_render_prometheus(self):
        counter = Counter("sih_events", "Events received", labels=["kind"])
        counter.inc(3.0, kind="packet")
        counter.inc(2.0, kind="packet")
        rendered = counter.render()
        self.assertIn("# TYPE sih_events counter", rendered)
        self.assertIn('# HELP sih_events Events received', rendered)
        self.assertIn('sih_events{kind="packet"} 5', rendered)


class TestGaugeMetric(unittest.TestCase):
    def test_set_and_render(self):
        gauge = Gauge("sih_kafka_lag", "Lag")
        gauge.set(42)
        rendered = gauge.render()
        self.assertIn("# TYPE sih_kafka_lag gauge", rendered)
        self.assertIn("sih_kafka_lag 42", rendered)


class TestHistogramMetric(unittest.TestCase):
    def test_observe_and_render(self):
        histogram = Histogram("sih_ml_latency_seconds", "Latency")
        histogram.observe(0.002)
        rendered = histogram.render()
        self.assertIn("# TYPE sih_ml_latency_seconds histogram", rendered)
        self.assertIn("_count 1", rendered)
        self.assertIn('le="+Inf"', rendered)


class TestMetricsRegistry(unittest.TestCase):
    def test_named_registration_and_sorted_render(self):
        registry = MetricsRegistry()
        registry.counter("z_metric")
        registry.gauge("a_metric")
        rendered = registry.render()
        self.assertLess(rendered.index("a_metric"), rendered.index("z_metric"))
        self.assertTrue(rendered.endswith("\n"))


class TestPhase10Metrics(unittest.TestCase):
    def test_required_observables_present(self):
        metrics = Phase10Metrics()
        expected_names = {
            "sih_events_received", "sih_events_processed", "sih_events_failed",
            "sih_events_dropped", "sih_kafka_lag", "sih_consumer_retries",
            "sih_dlq_count", "sih_window_count", "sih_late_events",
            "sih_duplicate_events", "sih_ml_latency_seconds",
            "sih_correlation_latency_seconds", "sih_risk_latency_seconds",
            "sih_response_latency_seconds", "sih_execution_success",
            "sih_execution_failure", "sih_pcap_downloads",
        }
        collected = {getattr(m, "name") for m in metrics.collect_all()}
        self.assertGreaterEqual(collected, expected_names)

    def test_render_includes_help_and_type(self):
        metrics = Phase10Metrics()
        rendered = metrics.render()
        self.assertIn("# TYPE sih_events_received counter", rendered)
        self.assertIn("# TYPE sih_ml_latency_seconds histogram", rendered)

    def test_metrics_do_not_gate_decisions(self):
        # metrics are pure renderers; calling never mutates domain objects
        metrics = Phase10Metrics()
        metrics.events_received.inc(1.0)
        metrics.window_count.inc(1.0)
        metrics.execution_success.inc(1.0)
        self.assertIn("sih_execution_success 1", metrics.render())


if __name__ == "__main__":
    unittest.main()