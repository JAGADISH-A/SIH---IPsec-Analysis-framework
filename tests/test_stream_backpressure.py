"""Phase 10 — streaming backpressure policy tests (no silent loss)."""

import unittest

from correlation.streaming.backpressure import (
    BLOCK,
    DLQ,
    DROP,
    BackpressureState,
    OverflowAction,
    default_overflow_for,
)
from correlation.streaming.models import EVENT_TYPE_PACKET, StreamEvent


def event(**overrides) -> StreamEvent:
    base = dict(
        dataset_run_id="dataset-20260916-231246",
        sequence=1,
        experiment_id="exp-bp",
        attempt_number=1,
        event_type=EVENT_TYPE_PACKET,
        payload={"proto": 17},
    )
    base.update(overrides)
    return StreamEvent(**base)


class TestBackpressureState(unittest.TestCase):
    def test_accept_until_capacity(self):
        state = BackpressureState(max_queue=2, overflow=BLOCK)
        self.assertEqual(state.accept(event()), OverflowAction.ACCEPT)
        self.assertEqual(state.accept(event()), OverflowAction.ACCEPT)
        self.assertEqual(state.queue_size, 2)
        self.assertTrue(state.saturated)

    def test_block_never_silently_drops(self):
        state = BackpressureState(max_queue=1, overflow=BLOCK)
        state.accept(event())
        action = state.accept(event())
        self.assertEqual(action, OverflowAction.BLOCK)
        self.assertEqual(state.blocked, 1)
        self.assertEqual(state.dropped, 0)

    def test_drop_policy_is_explicit(self):
        state = BackpressureState(max_queue=1, overflow=DROP)
        state.accept(event())
        self.assertEqual(state.accept(event()), OverflowAction.DROP)
        self.assertEqual(state.dropped, 1)

    def test_dlq_policy(self):
        state = BackpressureState(max_queue=1, overflow=DLQ)
        state.accept(event())
        self.assertEqual(state.accept(event()), OverflowAction.DLQ)

    def test_drain_fifo_and_limit(self):
        state = BackpressureState(max_queue=10, overflow=BLOCK)
        for i in range(5):
            state.accept(event(sequence=i + 1))
        drained, count = state.drain(limit=2)
        self.assertEqual(count, 2)
        self.assertEqual([e.sequence for e in drained], [1, 2])
        rest, n = state.drain()
        self.assertEqual(n, 3)
        self.assertEqual(state.queue_size, 0)

    def test_validation(self):
        with self.assertRaises(ValueError):
            BackpressureState(max_queue=0)
        with self.assertRaises(ValueError):
            BackpressureState(overflow="SHRED")

    def test_default_overflow_is_block_for_security_relevant(self):
        self.assertEqual(default_overflow_for("ipsec.packet"), BLOCK)

    def test_to_dict_consistent(self):
        state = BackpressureState(max_queue=2, overflow=BLOCK)
        state.accept(event())
        info = state.to_dict()
        self.assertEqual(info["max_queue"], 2)
        self.assertEqual(info["overflow_policy"], BLOCK)
        self.assertEqual(info["queue_size"], 1)


if __name__ == "__main__":
    unittest.main()