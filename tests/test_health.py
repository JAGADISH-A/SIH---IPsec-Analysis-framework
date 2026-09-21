"""Phase 10 — production health system tests (statuses never gate decisions)."""

import unittest

from correlation.observability.health import (
    STATUS_DEGRADED,
    STATUS_DISABLED,
    STATUS_HEALTHY,
    STATUS_UNAVAILABLE,
    ComponentHealth,
    HealthRegistry,
    degraded,
    disabled,
    healthy,
    unavailable,
    validate_status,
)


class TestComponentHealth(unittest.TestCase):
    def test_validation(self):
        self.assertEqual(validate_status("healthy"), "healthy")
        with self.assertRaises(ValueError):
            validate_status("on-fire")
        with self.assertRaises(ValueError):
            ComponentHealth(component="", status="healthy")
        with self.assertRaises(ValueError):
            ComponentHealth(component="x", status="bogus")

    def test_disabled_is_not_an_error(self):
        self.assertTrue(disabled("executor", "off by config").is_ok())
        self.assertFalse(unavailable("kafka", "down").is_ok())

    def test_factories(self):
        self.assertEqual(healthy("a", "ok").status, STATUS_HEALTHY)
        self.assertEqual(unavailable("b", "down").status, STATUS_UNAVAILABLE)
        self.assertEqual(degraded("c", "slow", latency_ms=99).metrics["latency_ms"], 99)
        self.assertEqual(disabled("d", "why").status, STATUS_DISABLED)


class TestHealthRegistry(unittest.TestCase):
    def test_set_get_all(self):
        registry = HealthRegistry()
        registry.set(healthy("a"))
        registry.set(disabled("b", "why"))
        self.assertEqual(registry.get("a").status, STATUS_HEALTHY)
        self.assertEqual([c.component for c in registry.all()], ["a", "b"])

    def test_overall_worst(self):
        registry = HealthRegistry()
        registry.set(healthy("a"))
        registry.set(disabled("b", "why"))
        self.assertEqual(registry.overall.status, STATUS_DISABLED)
        registry.set(unavailable("c", "down"))
        self.assertEqual(registry.overall.status, STATUS_UNAVAILABLE)

    def test_to_dict(self):
        registry = HealthRegistry()
        registry.set(healthy("kafka"))
        data = registry.to_dict()
        self.assertEqual(data["status"], "healthy")
        self.assertEqual(data["components"]["kafka"]["status"], "healthy")


if __name__ == "__main__":
    unittest.main()