"""Unit tests for the 100 ms userspace window aggregator.

These tests are fully synthetic: they feed :class:`PacketEvent` records (the
same shape the XDP ring buffer produces) into the aggregator and assert on the
emitted window feature records.  No live XDP or network is required.
"""

import json
import unittest

from ebpf.xdp_window_aggregator import (
    A_TO_B,
    B_TO_A,
    DEFAULT_ENDPOINTS,
    PacketEvent,
    WINDOW_SIZE_MS,
    WindowAggregator,
    aggregate,
    iter_jsonl_events,
)

GW_A = "192.168.100.1"
GW_B = "192.168.100.2"

NS_PER_MS = 1_000_000
WINDOW_NS = WINDOW_SIZE_MS * NS_PER_MS
# Start at a clean window boundary; BASE // WINDOW_NS == 10.
BASE = 10 * WINDOW_NS
# Exactly one full window after BASE.
NEXT = BASE + WINDOW_NS


def esp(ts, src=GW_A, dst=GW_B, spi=0x1111, seq=1, length=154):
    return PacketEvent(ts=ts, type="ESP", src=src, dst=dst, proto=50,
                       length=length, spi=spi, seq=seq)


def ike_nat_t(ts, src=GW_A, dst=GW_B, length=126):
    return PacketEvent(ts=ts, type="IKE-NAT-T", src=src, dst=dst, proto=17,
                       length=length, sport=4500, dport=4500)


def other(ts, src="0.0.0.0", dst="0.0.0.0", length=42):
    return PacketEvent(ts=ts, type="OTHER", src=src, dst=dst, proto=0,
                       length=length)


def ike(ts, src=GW_A, dst=GW_B, length=126):
    return PacketEvent(ts=ts, type="IKE", src=src, dst=dst, proto=17,
                       length=length, sport=500, dport=500)


class TestSingleWindow(unittest.TestCase):
    def test_a_to_b_esp(self):
        records = aggregate([esp(BASE + i * NS_PER_MS, seq=34 + i)
                             for i in range(4)])
        self.assertEqual(len(records), 1)
        r = records[0]
        self.assertEqual(r["window_start_ns"], BASE)
        self.assertEqual(r["window_end_ns"], BASE + WINDOW_NS)
        self.assertEqual(r["window_duration_ms"], 100)
        self.assertEqual(r["total_packets"], 4)
        self.assertEqual(r["esp_packets"], 4)
        self.assertEqual(r["total_bytes"], 616)
        self.assertEqual(r["min_packet_size"], 154)
        self.assertEqual(r["max_packet_size"], 154)
        self.assertEqual(r["average_packet_size"], 154.0)
        self.assertEqual(r["packets_a_to_b"], 4)
        self.assertEqual(r["bytes_a_to_b"], 616)
        self.assertEqual(r["packets_b_to_a"], 0)
        self.assertEqual(r["bytes_b_to_a"], 0)
        self.assertEqual(r["unique_esp_spi_count"], 1)
        self.assertEqual(r["first_esp_sequence"], 34)
        self.assertEqual(r["last_esp_sequence"], 37)
        self.assertEqual(r["esp_sequence_delta"], 3)
        self.assertEqual(r["packets_per_second"], 40.0)
        self.assertEqual(r["bytes_per_second"], 6160.0)

    def test_b_to_a_esp(self):
        records = aggregate([
            esp(BASE, src=GW_B, dst=GW_A, spi=0x2222, seq=7, length=150),
            esp(BASE + NS_PER_MS, src=GW_B, dst=GW_A, spi=0x2222, seq=8, length=150),
        ])
        r = records[0]
        self.assertEqual(r["packets_a_to_b"], 0)
        self.assertEqual(r["bytes_a_to_b"], 0)
        self.assertEqual(r["packets_b_to_a"], 2)
        self.assertEqual(r["bytes_b_to_a"], 300)
        self.assertEqual(r["esp_sequence_delta"], 1)

    def test_ike_nat_t_classification(self):
        records = aggregate([ike_nat_t(BASE), ike_nat_t(BASE + NS_PER_MS)])
        r = records[0]
        self.assertEqual(r["total_packets"], 2)
        self.assertEqual(r["ike_nat_t_packets"], 2)
        self.assertEqual(r["ike_packets"], 0)
        self.assertEqual(r["esp_packets"], 0)
        self.assertEqual(r["ah_packets"], 0)
        self.assertEqual(r["other_packets"], 0)
        # No ESP -> ESP statistics are all zero, never negative/invalid.
        self.assertEqual(r["unique_esp_spi_count"], 0)
        self.assertEqual(r["first_esp_sequence"], 0)
        self.assertEqual(r["last_esp_sequence"], 0)
        self.assertEqual(r["esp_sequence_delta"], 0)

    def test_mixed_esp_and_ike(self):
        records = aggregate([
            esp(BASE, seq=1),
            ike_nat_t(BASE + NS_PER_MS),
            ike(BASE + 2 * NS_PER_MS),
        ])
        r = records[0]
        self.assertEqual(r["total_packets"], 3)
        self.assertEqual(r["esp_packets"], 1)
        self.assertEqual(r["ike_nat_t_packets"], 1)
        self.assertEqual(r["ike_packets"], 1)
        self.assertEqual(r["packets_a_to_b"], 3)

    def test_multiple_spis(self):
        records = aggregate([
            esp(BASE, spi=0xaaaa, seq=1),
            esp(BASE + NS_PER_MS, spi=0xbbbb, seq=5),
        ])
        r = records[0]
        self.assertEqual(r["unique_esp_spi_count"], 2)
        self.assertEqual(r["first_esp_sequence"], 1)
        self.assertEqual(r["last_esp_sequence"], 5)
        self.assertEqual(r["esp_sequence_delta"], 4)

    def test_esp_sequence_progression(self):
        records = aggregate([esp(BASE + i * NS_PER_MS, seq=10 + i)
                             for i in range(3)])
        r = records[0]
        self.assertEqual(r["first_esp_sequence"], 10)
        self.assertEqual(r["last_esp_sequence"], 12)
        self.assertEqual(r["esp_sequence_delta"], 2)

    def test_sequence_wraparound(self):
        seqs = [0xFFFFFFFE, 0xFFFFFFFF, 0x00000000, 0x00000001]
        records = aggregate([esp(BASE + i * NS_PER_MS, seq=s)
                             for i, s in enumerate(seqs)])
        r = records[0]
        self.assertEqual(r["first_esp_sequence"], 0xFFFFFFFE)
        self.assertEqual(r["last_esp_sequence"], 1)
        # 3 forward steps, not a ~4e9 negative jump.
        self.assertEqual(r["esp_sequence_delta"], 3)

    def test_packets_outside_tunnel_endpoints(self):
        records = aggregate([
            esp(BASE, src="203.0.113.9", dst="203.0.113.10", seq=1),
            other(BASE + NS_PER_MS),
        ])
        r = records[0]
        self.assertEqual(r["total_packets"], 2)
        self.assertEqual(r["esp_packets"], 1)
        self.assertEqual(r["other_packets"], 1)
        # Not attributable to either tunnel direction.
        self.assertEqual(r["packets_a_to_b"], 0)
        self.assertEqual(r["packets_b_to_a"], 0)
        self.assertEqual(r["bytes_a_to_b"], 0)
        self.assertEqual(r["bytes_b_to_a"], 0)


class TestMultipleWindows(unittest.TestCase):
    def test_empty_window_between_activity(self):
        records = aggregate([
            esp(BASE, seq=1),
            esp(NEXT + WINDOW_NS, seq=2),   # skip one whole window
        ])
        self.assertEqual(len(records), 3)
        self.assertEqual(records[0]["total_packets"], 1)
        empty = records[1]
        self.assertEqual(empty["window_start_ns"], BASE + WINDOW_NS)
        self.assertEqual(empty["total_packets"], 0)
        self.assertEqual(empty["total_bytes"], 0)
        self.assertEqual(empty["min_packet_size"], 0)
        self.assertEqual(empty["max_packet_size"], 0)
        self.assertEqual(empty["average_packet_size"], 0.0)
        self.assertEqual(empty["packets_per_second"], 0.0)
        self.assertEqual(empty["bytes_per_second"], 0.0)
        self.assertEqual(empty["unique_esp_spi_count"], 0)
        self.assertEqual(empty["first_esp_sequence"], 0)
        self.assertEqual(empty["last_esp_sequence"], 0)
        self.assertEqual(empty["esp_sequence_delta"], 0)
        self.assertEqual(records[2]["total_packets"], 1)

    def test_packets_spanning_two_windows(self):
        records = aggregate([
            esp(BASE + 10 * NS_PER_MS, seq=1),
            esp(BASE + 99 * NS_PER_MS, seq=2),
            esp(BASE + 100 * NS_PER_MS, seq=3),   # first of next window
            esp(BASE + 150 * NS_PER_MS, seq=4),
        ])
        self.assertEqual(len(records), 2)
        first, second = records
        self.assertEqual(first["total_packets"], 2)
        self.assertEqual(first["window_start_ns"], BASE)
        self.assertEqual(second["total_packets"], 2)
        self.assertEqual(second["window_start_ns"], BASE + WINDOW_NS)
        # Each packet belongs to exactly one window.
        self.assertEqual(first["total_packets"] + second["total_packets"], 4)

    def test_totals_match_consumed_events(self):
        events = [esp(BASE + i * NS_PER_MS, seq=1 + i) for i in range(5)]
        events += [ike_nat_t(NEXT + i * NS_PER_MS) for i in range(3)]
        events += [other(NEXT + WINDOW_NS)]
        records = aggregate(events)
        self.assertEqual(sum(r["total_packets"] for r in records), len(events))
        self.assertEqual(sum(r["esp_packets"] for r in records), 5)
        self.assertEqual(sum(r["ike_nat_t_packets"] for r in records), 3)
        self.assertEqual(sum(r["other_packets"] for r in records), 1)

    def test_finalize_flushes_open_window(self):
        # A single event must still produce its (partial) window on finalize.
        records = aggregate([esp(BASE, seq=1)])
        self.assertEqual(len(records), 1)

    def test_no_events_no_windows(self):
        self.assertEqual(aggregate([]), [])


class TestConfigurationAndOrdering(unittest.TestCase):
    def test_configurable_window_size(self):
        records = aggregate([esp(0, seq=1), esp(60 * NS_PER_MS, seq=2)],
                            window_ms=50)
        # 0-50ms and 50-100ms are different windows under 50 ms configuration.
        self.assertEqual(len(records), 2)
        self.assertEqual(records[0]["window_duration_ms"], 50)
        self.assertEqual(records[0]["packets_per_second"], 20.0)

    def test_minor_reordering_stays_in_window(self):
        # Slightly out-of-order packet for window 10 arriving after an event in
        # window 11 still lands in window 10 (lookback keeps it open).
        agg = WindowAggregator(window_ms=100)
        out = []
        agg._emit = out.append
        agg.accept(esp(BASE + 90 * NS_PER_MS, seq=1))          # window 10
        agg.accept(esp(NEXT + 5 * NS_PER_MS, seq=3))           # window 11
        agg.accept(esp(BASE + 95 * NS_PER_MS, seq=2))          # late window 10
        agg.finalize()
        self.assertEqual(agg.events_dropped_late, 0)
        w10 = [r for r in out if r["window_start_ns"] == BASE][0]
        self.assertEqual(w10["total_packets"], 2)

    def test_very_late_event_is_dropped_not_misbinned(self):
        agg = WindowAggregator(window_ms=100)
        out = []
        agg._emit = out.append
        agg.accept(esp(BASE + 10 * NS_PER_MS, seq=1))          # window 10
        # Advance far so window 10 is flushed and closed.
        for i in range(5):
            agg.accept(esp(NEXT * (i + 1) + 10 * NS_PER_MS, seq=2 + i))
        agg.accept(esp(BASE + 20 * NS_PER_MS, seq=99))         # too late
        agg.finalize()
        self.assertEqual(agg.events_dropped_late, 1)
        seen = [r for r in out if r["window_start_ns"] == BASE][0]
        self.assertEqual(seen["last_esp_sequence"], 1)

    def test_direction_mapping_is_configurable(self):
        custom = {"10.0.0.1": A_TO_B, "10.0.0.2": B_TO_A}
        records = aggregate([
            esp(BASE, src="10.0.0.1", dst="10.0.0.2", seq=1),
            esp(BASE + NS_PER_MS, src="10.0.0.2", dst="10.0.0.1", seq=1),
        ], endpoints=custom)
        r = records[0]
        self.assertEqual(r["packets_a_to_b"], 1)
        self.assertEqual(r["packets_b_to_a"], 1)


class TestParserShell(unittest.TestCase):
    def test_iter_jsonl_events(self):
        lines = [
            json.dumps({"ts": BASE, "type": "ESP", "src": GW_A, "dst": GW_B,
                        "proto": 50, "len": 154, "spi": 4097, "seq": 4}),
            "",
            "# comment",
            "{not json",
            json.dumps({"timestamp": NEXT, "type": 2, "src": GW_A,
                        "dst": GW_B, "ip_protocol": 17, "frame_length": 126,
                        "source_port": 4500, "destination_port": 4500}),
        ]
        events = list(iter_jsonl_events(lines))
        self.assertEqual(len(events), 2)
        self.assertEqual(events[0].type, "ESP")
        self.assertEqual(events[0].spi, 4097)
        self.assertEqual(events[1].type, "IKE-NAT-T")
        self.assertEqual(events[1].length, 126)

    def test_default_endpoints_do_not_mutate_global(self):
        agg = WindowAggregator(endpoints={GW_A: A_TO_B})
        agg.accept(esp(BASE, src=GW_B, dst=GW_A, seq=1))
        self.assertEqual(agg.endpoints, {GW_A: A_TO_B})
        self.assertEqual(DEFAULT_ENDPOINTS[GW_B], B_TO_A)


if __name__ == "__main__":
    unittest.main()
