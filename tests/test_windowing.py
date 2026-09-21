"""Phase 10 — 100 ms windowing engine tests (deterministic binning)."""

import unittest

from correlation.streaming.windowing import (
    CLASS_AH,
    CLASS_ESP,
    CLASS_IKE,
    CLASS_OTHER,
    EmissionPolicy,
    WINDOW_LOOKBACK_DEFAULT,
    WINDOW_SIZE_MS_DEFAULT,
    WindowEngine,
)

WINDOW_NS = 100_000_000  # 100 ms


def engine(window_ms=100, lookback=0, **policy) -> WindowEngine:
    return WindowEngine(
        window_ms=window_ms,
        lookback=lookback,
        policy=EmissionPolicy(**policy),
    )


class TestAlignment(unittest.TestCase):
    def test_window_index_alignment(self):
        w = engine()
        self.assertEqual(w._index_of(99_999_999, WINDOW_NS), 0)
        self.assertEqual(w._index_of(100_000_000, WINDOW_NS), 1)
        self.assertEqual(w._index_of(199_999_999, WINDOW_NS), 1)
        self.assertEqual(w._index_of(200_000_000, WINDOW_NS), 2)

    def test_default_constants(self):
        self.assertEqual(WINDOW_SIZE_MS_DEFAULT, 100)
        self.assertEqual(WINDOW_LOOKBACK_DEFAULT, 2)

    def test_accept_requires_non_negative_int(self):
        w = engine()
        with self.assertRaises(ValueError):
            w.accept(ts_ns=-1, event_type=CLASS_ESP)
        with self.assertRaises(ValueError):
            w.accept(ts_ns=1.5, event_type=CLASS_ESP)


class TestFolding(unittest.TestCase):
    def test_esp_spi_and_sequence_delta(self):
        w = engine()
        self.assertTrue(w.accept(ts_ns=0, event_type=CLASS_ESP, spi=0xAA,
                                 seq=0xFFFFFFF0, length=100))
        self.assertTrue(w.accept(ts_ns=1, event_type=CLASS_ESP, spi=0xAA,
                                 seq=0x00000010, length=120))
        records = w.flush()
        self.assertEqual(len(records), 1)
        rec = records[0]
        self.assertEqual(rec.total_packets, 2)
        self.assertEqual(rec.esp_packets, 2)
        self.assertEqual(rec.unique_esp_spi_count, 1)
        self.assertEqual(rec.bytes_seen, 220)
        self.assertEqual(rec.esp_sequence_delta, (0x00000010 - 0xFFFFFFF0) % (1 << 32))
        self.assertEqual(rec.esp_sequence_delta, 0x20)

    def test_unique_spi_counting(self):
        w = engine()
        w.accept(ts_ns=0, event_type=CLASS_ESP, spi=1)
        w.accept(ts_ns=1, event_type=CLASS_ESP, spi=2)
        rec = w.flush()[0]
        self.assertEqual(rec.unique_esp_spi_count, 2)

    def test_direction_counts_and_bytes(self):
        w = engine()
        w.accept(ts_ns=0, event_type=CLASS_ESP, direction="A_TO_B", length=50)
        w.accept(ts_ns=1, event_type=CLASS_ESP, direction="B_TO_A", length=25)
        rec = w.flush()[0]
        self.assertEqual(rec.packets_a_to_b, 1)
        self.assertEqual(rec.bytes_a_to_b, 50)
        self.assertEqual(rec.packets_b_to_a, 1)
        self.assertEqual(rec.bytes_b_to_a, 25)

    def test_type_buckets(self):
        w = engine()
        w.accept(ts_ns=0, event_type=CLASS_IKE, length=10)
        w.accept(ts_ns=1, event_type=CLASS_OTHER, length=10)
        w.accept(ts_ns=2, event_type=CLASS_AH, length=10)
        rec = w.flush()[0]
        self.assertEqual(rec.total_packets, 3)
        self.assertEqual(rec.ike_packets, 1)
        self.assertEqual(rec.ah_packets, 1)
        self.assertEqual(rec.other_packets, 1)


class TestLateEvents(unittest.TestCase):
    def test_late_event_counted_not_misbinned(self):
        w = engine(lookback=0)
        w.accept(ts_ns=0, event_type=CLASS_ESP)            # window 0
        self.assertTrue(w.accept(ts_ns=200_000_000, event_type=CLASS_ESP))  # window 2
        self.assertEqual(w.late_events, 0)
        self.assertFalse(w.accept(ts_ns=100_000_000, event_type=CLASS_ESP))  # window 1 late
        self.assertEqual(w.late_events, 1)
        records = w.flush()
        by_index = {r.window_index: r for r in records}
        self.assertIn(0, by_index)
        self.assertIn(2, by_index)
        # window 1 is emitted as EMPTY gap-fill; the late packet never entered it
        empty_win = by_index[1]
        self.assertTrue(empty_win.empty)
        self.assertEqual(empty_win.total_packets, 0)

    def test_lookback_keeps_window_open(self):
        w = engine(lookback=2)
        w.accept(ts_ns=300_000_000, event_type=CLASS_ESP)   # window 3
        self.assertTrue(w.accept(ts_ns=200_000_000, event_type=CLASS_ESP))  # +window 2
        self.assertTrue(w.accept(ts_ns=100_000_000, event_type=CLASS_ESP))  # +window 1
        self.assertEqual(w.late_events, 0)

    def test_frontier_advances_with_max(self):
        w = engine()
        w.accept(ts_ns=0, event_type=CLASS_ESP)
        w.accept(ts_ns=500_000_000, event_type=CLASS_ESP)   # window 5
        w.accept(ts_ns=300_000_000, event_type=CLASS_ESP)   # out-of-order but < 5-lookback(0)
        self.assertEqual(w.late_events, 1)
        self.assertEqual(w._frontier, 5)


class TestFlush(unittest.TestCase):
    def test_flush_emits_index_ordered_with_gap_fill(self):
        w = engine(lookback=0, emit_empty=True, flush_on_shutdown=True)
        w.accept(ts_ns=0, event_type=CLASS_ESP)              # window 0
        w.accept(ts_ns=300_000_000, event_type=CLASS_ESP)    # window 3
        records = w.flush()
        indices = [r.window_index for r in records]
        self.assertEqual(indices, [0, 1, 2, 3])
        self.assertTrue(records[1].empty)
        self.assertTrue(records[2].empty)

    def test_flush_without_empty_gap_fill(self):
        w = engine(lookback=0, emit_empty=False)
        w.accept(ts_ns=0, event_type=CLASS_ESP)
        w.accept(ts_ns=300_000_000, event_type=CLASS_ESP)
        records = [r for r in w.flush() if not r.empty]
        self.assertEqual([r.window_index for r in records], [0, 3])

    def test_flush_clears_engine(self):
        w = engine()
        w.accept(ts_ns=0, event_type=CLASS_ESP)
        w.flush()
        self.assertEqual(len(w.pending_flush), 0)
        self.assertEqual(w._open, {})
        self.assertGreaterEqual(w.windows_emitted, 1)

    def test_emit_policy_every_n_windows(self):
        w = engine(lookback=2, emit_empty=False,
                   emit_every_windows=1, flush_on_shutdown=True)
        w.accept(ts_ns=0, event_type=CLASS_ESP)
        w.accept(ts_ns=100_000_000, event_type=CLASS_ESP)
        w.accept(ts_ns=200_000_000, event_type=CLASS_ESP)
        records = w.flush()
        self.assertEqual(len(records), 3)

    def test_empty_window_is_real_observation(self):
        w = engine(lookback=0, emit_empty=True)
        w.accept(ts_ns=0, event_type=CLASS_ESP)
        w.accept(ts_ns=200_000_000, event_type=CLASS_ESP)
        records = w.flush()
        empty = [r for r in records if r.empty]
        self.assertEqual(len(empty), 1)
        self.assertEqual(empty[0].window_index, 1)

    def test_to_dict(self):
        w = engine()
        w.accept(ts_ns=0, event_type=CLASS_ESP)
        info = w.to_dict()
        self.assertEqual(info["window_ms"], 100)
        self.assertEqual(info["frontier"], 0)
        self.assertEqual(info["open_windows"], [0])


class TestWindowRecord(unittest.TestCase):
    def test_to_dict_serializable(self):
        w = engine()
        w.accept(ts_ns=0, event_type=CLASS_ESP, spi=1, seq=2, length=88)
        rec = w.flush()[0]
        d = rec.to_dict()
        self.assertEqual(d["window_start_ns"], 0)
        self.assertEqual(d["window_end_ns"], 100_000_000)
        self.assertIsInstance(d["events"], list)


if __name__ == "__main__":
    unittest.main()