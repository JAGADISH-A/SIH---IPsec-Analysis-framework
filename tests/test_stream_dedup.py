"""Phase 10 — streaming duplicate detection tests."""

import unittest

from correlation.streaming.dedup import Deduplicator, make_dedup_key
from correlation.streaming.models import EVENT_TYPE_PACKET, StreamEvent


def event(attempt_number=1, payload=None) -> StreamEvent:
    return StreamEvent(
        dataset_run_id="dataset-20260916-231246",
        sequence=1,
        experiment_id="exp-dedup",
        attempt_number=attempt_number,
        event_type=EVENT_TYPE_PACKET,
        payload=payload or {"proto": 17, "length": 74},
    )


class TestDeduplicator(unittest.TestCase):
    def test_first_observe_admits(self):
        d = Deduplicator(size=10)
        self.assertFalse(d.observe(event()))
        self.assertEqual(d.admitted_count, 1)
        self.assertEqual(d.duplicate_count, 0)

    def test_identical_copy_is_duplicate(self):
        d = Deduplicator(size=10)
        e = event()
        d.observe(e)
        self.assertTrue(d.observe(e))  # exact same object bytes
        self.assertTrue(d.is_duplicate(event()))
        self.assertEqual(d.duplicate_count, 1)
        self.assertEqual(d.admitted_count, 1)

    def test_different_attempt_never_collapses(self):
        d = Deduplicator(size=10)
        d.observe(event(attempt_number=1))
        self.assertFalse(d.observe(event(attempt_number=2)))
        self.assertNotEqual(make_dedup_key(event(attempt_number=1)),
                            make_dedup_key(event(attempt_number=2)))

    def test_different_payload_distinct(self):
        d = Deduplicator(size=10)
        d.observe(event(payload={"p": 1}))
        self.assertFalse(d.observe(event(payload={"p": 2})))

    def test_bounded_lru_eviction(self):
        d = Deduplicator(size=3)
        for i in range(4):
            d.observe(event(payload={"i": i}))
        self.assertLessEqual(len(d._seen), 3)
        # the first event was evicted -> re-observing it is no longer a dup
        self.assertFalse(d.observe(event(payload={"i": 0})))

    def test_reset(self):
        d = Deduplicator(size=10)
        d.observe(event())
        d.reset()
        self.assertEqual(d.admitted_count, 0)
        self.assertEqual(d.duplicate_count, 0)
        self.assertFalse(d.is_duplicate(event()))

    def test_to_dict(self):
        d = Deduplicator(size=10)
        d.observe(event())
        info = d.to_dict()
        self.assertEqual(info["seen_unique"], 1)
        self.assertEqual(info["admitted_count"], 1)
        self.assertEqual(info["duplicate_count"], 0)


if __name__ == "__main__":
    unittest.main()