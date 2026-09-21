"""Phase 10 — XDP/eBPF live adapter tests (NAT-T seam, no inference)."""

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


class TestXdpEventAdapter(unittest.TestCase):
    def setUp(self):
        self.adapter = XdpEventAdapter(capture_ip="198.51.100.10")

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