"""Phase 10 — /api/v1 handlers + live context tests (read-only surface)."""

import tempfile
import unittest

from correlation.api import app, live, v1
from correlation.api.pcap import PcapRegistry, PcapService
from correlation.api.routes import ApiError
from correlation.execution import ExecutionSettings
from correlation.observability.health import healthy


class TestPhase10Context(unittest.TestCase):
    def test_defaults_built(self):
        ctx = live.Phase10Context()
        self.assertIsNotNone(ctx.execution)
        self.assertIsNotNone(ctx.pcap)
        self.assertFalse(ctx.execution.settings.enable_production_execution)
        self.assertEqual(ctx.execution.settings.mode, "DRY_RUN")

    def test_from_settings(self):
        settings = ExecutionSettings(mode="AUTHORIZED_TESTBED",
                                     allowed_testbed_targets=("127.0.0.1/32",))
        with tempfile.TemporaryDirectory() as root:
            ctx = live.Phase10Context.from_settings(settings, root=root)
            self.assertEqual(ctx.summary()["execution_mode"],
                             "AUTHORIZED_TESTBED")
            self.assertIsInstance(ctx.pcap.registry, PcapRegistry)

    def test_summary_shape(self):
        ctx = live.Phase10Context()
        summary = ctx.summary()
        for key in ("execution_mode", "health", "metrics_points",
                    "registered_evidence", "pcap_downloads",
                    "traffic_generator"):
            self.assertIn(key, summary)

    def test_health_seeded_components(self):
        ctx = live.Phase10Context()
        names = {c.component for c in ctx.health.all()}
        self.assertIn("kafka", names)
        self.assertIn("executor", names)

    def test_health_can_be_injected(self):
        from correlation.observability import HealthRegistry
        registry = HealthRegistry()
        registry.set(healthy("probe", "ok"))
        ctx = live.Phase10Context(health=registry)
        self.assertEqual(ctx.health.get("probe").status, "healthy")


class TestV1Handlers(unittest.TestCase):
    def setUp(self):
        self.ctx = live.Phase10Context()

    def test_health(self):
        body, content_type = v1.handle_v1_get(self.ctx, "/api/v1/health")
        self.assertEqual(content_type, "application/json")
        self.assertIn("status", body)

    def test_metrics_text(self):
        body, content_type = v1.handle_v1_get(self.ctx, "/api/v1/metrics")
        self.assertEqual(content_type, "text/plain; version=0.0.4; charset=utf-8")
        self.assertIn("# TYPE sih_events_received counter", body)

    def test_traffic_generator_status(self):
        body, _ = v1.handle_v1_get(self.ctx, "/api/v1/traffic-generator")
        self.assertEqual(body["api"], "traffic-generator")
        self.assertFalse(body["status"]["monitored"])

    def test_monitored_traffic_generator(self):
        monitor = live.TrafficGeneratorMonitor(
            status_fn=lambda: {"running": True, "pps": 1200}
        )
        ctx = live.Phase10Context(traffic_generator=monitor)
        body, _ = v1.handle_v1_get(ctx, "/api/v1/traffic-generator")
        self.assertTrue(body["status"]["running"])
        self.assertEqual(body["status"]["pps"], 1200)

    def test_unknown_route_404(self):
        with self.assertRaises(ApiError) as raised:
            v1.handle_v1_get(self.ctx, "/api/v1/nope")
        self.assertEqual(raised.exception.status, 404)

    def test_is_v1_path(self):
        self.assertTrue(v1.is_v1_path("/api/v1/health"))
        self.assertFalse(v1.is_v1_path("/api/assessments"))
        self.assertTrue(v1.is_v1_path("/api/v1"))

    def test_combined_dispatches_v1_and_phase8(self):
        from correlation.api.store import build_store
        store = build_store()
        body, content_type = app.handle_combined(store, self.ctx, "/api/v1/health")
        self.assertIn("status", body)
        self.assertEqual(content_type, "application/json")
        # phase-8 route unchanged
        body8 = app.handle_combined(store, None, "/api/health")
        self.assertIsInstance(body8, dict)

    def test_combined_v1_requires_context(self):
        from correlation.api.store import build_store
        with self.assertRaises(ApiError) as raised:
            app.handle_combined(build_store(), None, "/api/v1/health")
        self.assertEqual(raised.exception.status, 503)


if __name__ == "__main__":
    unittest.main()