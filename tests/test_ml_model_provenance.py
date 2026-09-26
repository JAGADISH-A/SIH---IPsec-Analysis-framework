"""A live ML result must be traceable to one exact model artifact (finding #3b).

``results/ml/train_report.json`` already recorded the artifact digest, but no
inference result carried it: a result naming only ``model_version`` could not be
tied to a specific file, and nothing checked the recorded digest against the
bytes on disk.  These tests pin the minimal provenance that closes that gap:

* ``controller.ml_inference.model_provenance()`` reports the SHA-256 of the
  artifact actually loaded, and it equals both the file on disk and the digest
  recorded in ``train_report.json``.
* every controller result producer carries that provenance.
* the bridge passes it through verbatim into ``MLResult.extras`` and never
  invents it: a result without provenance still converts, carrying no digest.
"""

from __future__ import annotations

import hashlib
import json
import unittest
from pathlib import Path

from controller import dataset_loader, ml_inference
from correlation.ml.controller_bridge import controller_result_to_ml_result

REPO_ROOT = Path(__file__).resolve().parents[1]
MODEL_PATH = REPO_ROOT / "results" / "ml" / "model_traffic_rf_v1.joblib"
TRAIN_REPORT = REPO_ROOT / "results" / "ml" / "train_report.json"

WINDOW_ID = "1700000000000000000-1700000100000000000"
CONTROLLER_RESULT = {
    "model_version": "traffic_rf_v1",
    "feature_schema_version": "v2",
    "window_id": WINDOW_ID,
    "timestamp": "2026-09-24T00:00:00Z",
    "traffic_profile": "voip",
    "probabilities": {
        "voip": 0.8, "video": 0.05, "messaging": 0.05,
        "email": 0.05, "web": 0.03, "icmp": 0.02,
    },
}


class TestModelProvenanceRejectsGuessing(unittest.TestCase):
    def test_model_provenance_reports_the_digest_of_the_loaded_artifact(self):
        provenance = ml_inference.model_provenance()
        on_disk = hashlib.sha256(MODEL_PATH.read_bytes()).hexdigest()

        self.assertEqual(on_disk, provenance["model_artifact_sha256"])

    def test_provenance_matches_the_digest_recorded_at_training_time(self):
        recorded = json.loads(TRAIN_REPORT.read_text(encoding="utf-8"))
        provenance = ml_inference.model_provenance()

        self.assertEqual(
            recorded["model_artifact"]["sha256"],
            provenance["model_artifact_sha256"],
        )
        self.assertEqual(
            recorded["model_artifact"]["path"],
            str(MODEL_PATH.relative_to(REPO_ROOT)),
        )

    def test_provenance_is_deterministic_within_a_process(self):
        self.assertEqual(
            ml_inference.model_provenance(), ml_inference.model_provenance()
        )

    def test_provenance_names_the_training_commit_and_datasets(self):
        recorded = json.loads(TRAIN_REPORT.read_text(encoding="utf-8"))
        provenance = ml_inference.model_provenance()

        self.assertEqual(recorded["git_commit"], provenance["model_trained_git_commit"])
        self.assertEqual(
            recorded["dataset_run_ids"], provenance["model_training_datasets"]
        )
        self.assertEqual(recorded["created_at"], provenance["model_trained_at"])

    def test_the_artifact_itself_does_not_claim_a_digest(self):
        """Honest boundary: the file cannot hash itself, so the digest is read
        from the bytes at load time rather than trusted from metadata."""
        artifact = ml_inference.load_artifact(MODEL_PATH)
        metadata = dict(artifact.get("metadata") or {})

        self.assertNotIn("sha256", metadata)
        self.assertNotIn("artifact_sha256", metadata)
        self.assertIn("model_artifact_sha256", ml_inference.model_provenance())


class TestEveryResultProducerCarriesProvenance(unittest.TestCase):
    def test_predict_carries_the_artifact_digest(self):
        features = {
            name: float(index + 1)
            for index, name in enumerate(ml_inference.feature_order())
        }
        result = ml_inference.predict(features, timestamp="2026-09-24T00:00:00Z")

        self.assertEqual(
            ml_inference.model_provenance()["model_artifact_sha256"],
            result["model_artifact_sha256"],
        )
        self.assertIn(
            result["traffic_profile"],
            dataset_loader.TARGET_CLASSES,
        )
        self.assertAlmostEqual(1.0, sum(result["probabilities"].values()), places=6)

    def test_predict_many_carries_the_artifact_digest(self):
        features = {
            name: float(index + 1)
            for index, name in enumerate(ml_inference.feature_order())
        }
        results = ml_inference.predict_many(
            [features], timestamp="2026-09-24T00:00:00Z"
        )
        expected = ml_inference.model_provenance()["model_artifact_sha256"]

        self.assertEqual(1, len(results))
        for result in results:
            self.assertEqual(expected, result["model_artifact_sha256"])


class TestBridgePreservesProvenanceVerbatim(unittest.TestCase):
    def test_bridge_forwards_the_digest_into_extras(self):
        supplied = dict(
            CONTROLLER_RESULT,
            **ml_inference.model_provenance(),
        )
        result = controller_result_to_ml_result(supplied)
        expected = ml_inference.model_provenance()["model_artifact_sha256"]

        self.assertEqual(expected, result.extras["model_artifact_sha256"])
        self.assertEqual(
            ml_inference.model_provenance()["model_trained_git_commit"],
            result.extras["model_trained_git_commit"],
        )
        self.assertEqual(
            ml_inference.model_provenance()["model_training_datasets"],
            result.extras["model_training_datasets"],
        )
        self.assertEqual("ml", result.extras["source"])
        self.assertEqual("traffic_rf_v1", result.model_version)

    def test_bridge_invents_no_digest_when_the_result_has_none(self):
        """Results recorded before provenance existed must stay usable and must
        not be back-filled with a digest the producer never sent."""
        result = controller_result_to_ml_result(CONTROLLER_RESULT)

        self.assertEqual("voip", result.traffic_class)
        self.assertNotIn("model_artifact_sha256", result.extras)
        self.assertNotIn("model_trained_git_commit", result.extras)
        self.assertNotIn("model_training_datasets", result.extras)
        self.assertEqual("traffic_rf_v1", result.extras["model_version"])

    def test_committed_recorded_results_carry_no_invented_digest(self):
        recorded = (
            REPO_ROOT / "results" / "ml" / "live_bridge" / "window_path_100ms.jsonl"
        )
        self.assertTrue(recorded.is_file(), "committed recorded results are missing")
        batches = [
            json.loads(line) for line in recorded.read_text().splitlines() if line.strip()
        ]
        self.assertTrue(batches)

        windows = [window for batch in batches for window in batch["windows"]]
        self.assertTrue(windows)
        for window in windows:
            result = controller_result_to_ml_result(window)
            self.assertNotIn("model_artifact_sha256", result.extras)


if __name__ == "__main__":
    unittest.main()
