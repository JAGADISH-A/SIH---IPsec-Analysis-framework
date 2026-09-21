"""Phase 10 — execution idempotency registry tests."""

import unittest

from correlation.execution.idempotency import (
    IdempotencyRegistry,
    idempotency_key,
)
from correlation.execution.targets import ExecutionTarget


def target():
    return ExecutionTarget(destination="192.0.2.5", protocol=50)


class TestIdempotencyKey(unittest.TestCase):
    def test_key_shape(self):
        key = idempotency_key("exec-1", "BLOCK_FLOW", target())
        self.assertEqual(key, "exec-1|BLOCK_FLOW|192.0.2.5|50|0")

    def test_requires_parts(self):
        with self.assertRaises(ValueError):
            idempotency_key("", "BLOCK_FLOW", target())
        with self.assertRaises(ValueError):
            idempotency_key("exec-1", "", target())


class TestRegistry(unittest.TestCase):
    def test_mark_then_already_applied(self):
        registry = IdempotencyRegistry()
        key = idempotency_key("exec-1", "BLOCK_FLOW", target())
        self.assertIsNone(registry.already_applied(key))
        registry.mark_applied(key, at_ns=100, outcome_status="SUCCEEDED")
        entry = registry.already_applied(key)
        self.assertIsNotNone(entry)
        self.assertEqual(entry["status"], "SUCCEEDED")

    def test_mark_only_once_and_different_target_distinct(self):
        registry = IdempotencyRegistry()
        key = idempotency_key("exec-1", "BLOCK_FLOW", target())
        other = idempotency_key("exec-1", "BLOCK_FLOW",
                                ExecutionTarget(destination="192.0.2.6", protocol=50))
        registry.mark_applied(key, at_ns=1, outcome_status="SUCCEEDED")
        registry.mark_applied(key, at_ns=2, outcome_status="SUCCEEDED")
        self.assertEqual(len(registry), 1)
        self.assertIsNone(registry.already_applied(other))

    def test_window_eviction(self):
        registry = IdempotencyRegistry(window_ns=50)
        key = idempotency_key("exec-1", "BLOCK_FLOW", target())
        registry.mark_applied(key, at_ns=0, outcome_status="SUCCEEDED")
        self.assertIsNotNone(registry.already_applied(key, now_ns=0))
        self.assertIsNone(registry.already_applied(key, now_ns=51))

    def test_bound_evicts_oldest(self):
        registry = IdempotencyRegistry(max_entries=2)
        k1 = idempotency_key("e1", "BLOCK_FLOW", target())
        k2 = idempotency_key("e2", "BLOCK_FLOW", target())
        k3 = idempotency_key("e3", "BLOCK_FLOW", target())
        registry.mark_applied(k1, at_ns=1, outcome_status="SUCCEEDED")
        registry.mark_applied(k2, at_ns=2, outcome_status="SUCCEEDED")
        registry.mark_applied(k3, at_ns=3, outcome_status="SUCCEEDED")
        self.assertEqual(len(registry), 2)
        self.assertIsNone(registry.already_applied(k1))
        self.assertIsNotNone(registry.already_applied(k3))

    def test_to_dict(self):
        registry = IdempotencyRegistry()
        registry.mark_applied(idempotency_key("e1", "BLOCK_FLOW", target()),
                              at_ns=1, outcome_status="SUCCEEDED")
        info = registry.to_dict()
        self.assertEqual(info["max_entries"], 4096)
        self.assertEqual(len(info["applied"]), 1)


if __name__ == "__main__":
    unittest.main()