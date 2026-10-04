"""Phase 10 — XDP/eBPF live adapter tests (NAT-T seam, no inference)."""

import time
import unittest

from correlation.streaming.live_adapter import (
    CLASS_ESP,
    CLASS_IKE,
    CLASS_IKE_NAT_T,
    CLASSIFICATION_AH,
    CLASSIFICATION_ESP,
    CLASSIFICATION_ESP_IN_UDP,
    CLASSIFICATION_IKE,
    CLASSIFICATION_UNKNOWN,
    NatTClassification,
    XdpEventAdapter,
    classify_udp_4500,
)
from correlation.streaming.models import EVENT_TYPE_IKE, EVENT_TYPE_PACKET
from correlation.models import CorrelationIdentity


def identity(**overrides) -> CorrelationIdentity:
    base = dict(
        dataset_run_id="dataset-20260916-231246",
        sequence=1,
        experiment_id="exp-live",
        attempt_number=1,
        window_index=0,
        window_start_ns=0,
        window_end_ns=100_000_000,
    )
    base.update(overrides)
    return CorrelationIdentity(**base)


class TestClassifyUdp4500(unittest.TestCase):
    def test_sensor_labels_are_evidence_not_heuristics(self):
        result = classify_udp_4500("IKE-NAT-T", 4500, 4500)
        self.assertEqual(result.classification, CLASSIFICATION_IKE)
        self.assertTrue(result.nat_t)

        result = classify_udp_4500("ESP", 4500, 4500)
        self.assertEqual(result.classification, CLASSIFICATION_ESP_IN_UDP)
        self.assertTrue(result.nat_t)

    def test_insufficient_evidence_is_unknown(self):
        result = classify_udp_4500("", 4500, 4500)
        self.assertEqual(result.classification, CLASSIFICATION_UNKNOWN)
        self.assertIn("never fabricated", result.reason)

    def test_udp_500_is_ike_negotiation(self):
        result = classify_udp_4500(None, 500, 4500)
        self.assertEqual(result.classification, CLASSIFICATION_IKE)
        self.assertFalse(result.nat_t)

    def test_neither_port_is_500_4500(self):
        result = classify_udp_4500(None, 53, 80)
        self.assertEqual(result.classification, CLASSIFICATION_UNKNOWN)

    def test_nat_t_classification_validation(self):
        with self.assertRaises(ValueError):
            NatTClassification("MADE_UP", "nope")
        NatTClassification(CLASSIFICATION_UNKNOWN, "ok", nat_t=True)

    def test_esp_nat_t_sensor_label_is_nat_t_data(self):
        """``ESP-NAT-T`` is a real ESP header seen inside UDP/4500."""
        result = classify_udp_4500("ESP-NAT-T", 4500, 4500)
        self.assertEqual(result.classification, CLASSIFICATION_ESP_IN_UDP)
        self.assertTrue(result.nat_t)
        self.assertIn("RFC 3948", result.reason)

    def test_ike_nat_t_stays_ike_and_is_never_esp_data(self):
        """IKE over NAT-T must never be promoted to ESP data."""
        result = classify_udp_4500("IKE-NAT-T", 4500, 4500)
        self.assertEqual(result.classification, CLASSIFICATION_IKE)
        self.assertNotEqual(result.classification, CLASSIFICATION_ESP_IN_UDP)


class TestXdpEventAdapter(unittest.TestCase):
    def setUp(self):
        # A pinned realtime offset keeps every timestamp assertion
        # deterministic; the auto-computed live offset is covered separately.
        self.adapter = XdpEventAdapter(capture_ip="198.51.100.10", realtime_offset_ns=0)

    def test_classify_protocols(self):
        self.assertEqual(self.adapter.classify({"proto": 50}), CLASSIFICATION_ESP)
        self.assertEqual(self.adapter.classify({"proto": 51}), CLASSIFICATION_AH)
        self.assertEqual(self.adapter.classify({"proto": 17, "sport": 500, "dport": 500}),
                         CLASSIFICATION_IKE)
        self.assertEqual(
            self.adapter.classify({"proto": 17, "type": "IKE-NAT-T", "sport": 4500, "dport": 4500}),
            CLASSIFICATION_IKE,
        )
        self.assertEqual(
            self.adapter.classify({"proto": 17, "type": "ESP", "sport": 4500, "dport": 4500}),
            CLASSIFICATION_ESP_IN_UDP,
        )
        self.assertEqual(
            self.adapter.classify({"proto": 17, "sport": 4500, "dport": 4500}),
            CLASSIFICATION_UNKNOWN,
        )
        self.assertIsNone(self.adapter.classify({"proto": 6}))

    def test_direction_inbound_outbound(self):
        self.assertEqual(
            self.adapter.direction({"src": "198.51.100.10", "dst": "192.0.2.8"}),
            "outbound",
        )
        self.assertEqual(
            self.adapter.direction({"src": "192.0.2.8", "dst": "198.51.100.10"}),
            "inbound",
        )

    def test_spi_of(self):
        self.assertEqual(self.adapter.spi_of({"spi": "0xAA"}), 170)
        self.assertEqual(self.adapter.spi_of({"spi": 42}), 42)
        self.assertIsNone(self.adapter.spi_of({"spi": ""}))
        self.assertIsNone(self.adapter.spi_of({"spi": 0}))

    def test_normalize_esp_nat_t_keeps_real_spi_and_seq(self):
        """A sensor-parsed ESP-in-UDP event keeps its real SPI/sequence.

        Values below are the ones actually observed on the wire from a genuine
        MASQUERADE between the peers (SPI 0xc6711f27, seq 1 and 2).
        """
        for seq in (1, 2):
            raw = {
                "ts_ns": 5000000000 + seq,
                "proto": 17,
                "type": "ESP-NAT-T",
                "src": "10.30.1.20",
                "dst": "10.20.1.10",
                "spi": 0xC6711F27,
                "seq": seq,
                "len": 162,
                "sport": 4500,
                "dport": 4500,
            }
            out = self.adapter.normalize(raw)
            self.assertEqual(out["classification"], CLASSIFICATION_ESP_IN_UDP)
            self.assertEqual(out["spi"], 0xC6711F27)
            self.assertEqual(out["sequence"], seq)
            self.assertEqual(out["source_port"], 4500)
            self.assertEqual(out["destination_port"], 4500)

    def test_normalize_ike_nat_t_carries_no_spi(self):
        """IKE over NAT-T must not report an SPI or sequence."""
        raw = {
            "ts_ns": 5000000000,
            "proto": 17,
            "type": "IKE-NAT-T",
            "src": "10.30.1.20",
            "dst": "10.20.1.10",
            "len": 254,
            "sport": 4500,
            "dport": 4500,
        }
        out = self.adapter.normalize(raw)
        self.assertEqual(out["classification"], CLASSIFICATION_IKE)
        self.assertIsNone(out["spi"])
        self.assertEqual(out["sequence"], 0)

    def test_normalize_shape(self):
        raw = {
            "ts_ns": 123456789,
            "interface": "eth0",
            "proto": 17,
            "type": "ESP",
            "src": "192.0.2.7",
            "dst": "198.51.100.10",
            "spi": "0x77",
            "seq": 9,
            "len": 420,
            "sport": 4500,
            "dport": 4500,
        }
        out = self.adapter.normalize(raw)
        self.assertEqual(out["timestamp"], 123456789)
        self.assertEqual(out["source"], "192.0.2.7")
        self.assertEqual(out["destination"], "198.51.100.10")
        self.assertEqual(out["classification"], CLASSIFICATION_ESP_IN_UDP)
        self.assertEqual(out["direction"], "inbound")
        self.assertNotIn("crypto_algorithm", out)

    def test_normalize_maps_monotonic_to_realtime_epoch(self):
        # The sensor writes CLOCK_MONOTONIC (ns since boot). The canonical
        # timestamp must be a realtime epoch; a pinned offset proves the math.
        adapter = XdpEventAdapter(realtime_offset_ns=1_700_000_000_123_456_789)
        out = adapter.normalize({"proto": 6, "ts": 42_000_000_000})
        self.assertEqual(out["timestamp"], 1_700_000_042_123_456_789)

    def test_default_realtime_offset_reaches_the_wall_clock(self):
        # With no explicit offset the adapter must map a monotonic value
        # captured just now to approximately the current realtime clock.
        adapter = XdpEventAdapter()
        now = time.time_ns()
        monotonic_now = time.clock_gettime_ns(time.CLOCK_MONOTONIC)
        wall = adapter.realtime_offset_ns + monotonic_now
        self.assertLess(abs(wall - now), 1_000_000_000)
        self.assertGreater(adapter.realtime_offset_ns, 1_000_000_000_000_000_000)

    def test_zero_timestamp_is_not_offset(self):
        out = self.adapter.normalize({"proto": 6, "ts": 0})
        self.assertEqual(out["timestamp"], 0)

    def test_to_stream_event_ike_type(self):
        raw = {"proto": 17, "type": "IKE-NAT-T", "sport": 4500, "dport": 4500,
               "src": "198.51.100.10", "dst": "192.0.2.8"}
        e = self.adapter.to_stream_event(raw, identity(), created_at=7)
        self.assertEqual(e.event_type, EVENT_TYPE_IKE)
        self.assertEqual(e.source, "live_xdp")
        self.assertEqual(e.payload["classification"], CLASSIFICATION_IKE)

    def test_to_stream_event_packet_type(self):
        raw = {"proto": 50, "spi": 1}
        e = self.adapter.to_stream_event(raw, identity(), created_at=7)
        self.assertEqual(e.event_type, EVENT_TYPE_PACKET)


if __name__ == "__main__":
    unittest.main()