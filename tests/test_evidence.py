import os
import unittest

from correlation.models import EvidenceRef

FIXTURE_DIR = os.path.join(os.path.dirname(__file__), "fixtures")


class TestEvidenceRef(unittest.TestCase):
    def test_pcap_reference_does_not_require_file(self):
        ref = EvidenceRef(
            pcap_path="results/datasets/run-001/captures/1/exp-video.pcap",
            capture_sequence=1,
            source="training_pcap",
        )
        self.assertFalse(ref.exists_on_disk())
        self.assertIn("exp-video.pcap", ref.pcap_path)

    def test_pcrap_path_pattern(self):
        run_id = "quality-01"
        seq = 2
        experiment_id = "exp-aes256gcm16-video"
        ref = EvidenceRef(
            pcap_path=f"results/datasets/{run_id}/captures/{seq}/{experiment_id}.pcap",
            capture_sequence=seq,
        )
        self.assertEqual(
            ref.pcap_path,
            "results/datasets/quality-01/captures/2/exp-aes256gcm16-video.pcap",
        )

    def test_minimal_evidence_ref(self):
        ref = EvidenceRef()
        self.assertIsNone(ref.pcap_path)
        self.assertIsNone(ref.source)

    def test_bad_source_rejected(self):
        with self.assertRaises(ValueError):
            EvidenceRef(source="made-up-source")

    def test_zero_capture_sequence_rejected(self):
        with self.assertRaises(ValueError):
            EvidenceRef(capture_sequence=0)

    def test_round_trip(self):
        ref = EvidenceRef(
            pcap_path="results/datasets/run-001/captures/1/exp-video.pcap",
            capture_sequence=1,
            audit_event_reference="audit://tap-events.jsonl#24",
            source="audit_tap",
            timestamp="2026-09-20T00:00:00Z",
        )
        self.assertEqual(EvidenceRef.from_json(ref.to_json()), ref)

    def test_fixtures_marked_test_fixture(self):
        import json

        with open(os.path.join(FIXTURE_DIR, "observed_example.json"), encoding="utf-8") as fh:
            data = json.load(fh)
        self.assertIn("TEST FIXTURE", data["comment"])
        with open(os.path.join(FIXTURE_DIR, "correlation_input_example.json"), encoding="utf-8") as fh:
            data = json.load(fh)
        self.assertIn("NOT REAL EVIDENCE", data["comment"])


if __name__ == "__main__":
    unittest.main()