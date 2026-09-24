"""Tests for controller.train_random_forest and controller.evaluate_model."""

import json
import tempfile
import unittest
from pathlib import Path

import joblib
import numpy as np

from controller.dataset_loader import TARGET_CLASSES
from controller.evaluate_model import compute_metrics, load_artifact
from controller.grouped_split import SPLIT_SEED, load_split
from controller.train_random_forest import (
    configure_model,
    encode_target,
    partition_mask,
)


class PartitionAndEncodingTest(unittest.TestCase):
    def test_encode_target_roundtrip(self):
        y = np.array(["voip", "web", "icmp", "voip"])
        encoded = encode_target(y, TARGET_CLASSES)
        decoded = [TARGET_CLASSES[i] for i in encoded]
        self.assertEqual(list(y), decoded)

    def test_encode_target_missing_class_raises(self):
        with self.assertRaises(KeyError):
            encode_target(["voip", "unknown"], TARGET_CLASSES)

    def test_partition_mask_counts(self):
        document = {
            "samples": [
                {"experiment_id": "e1", "split": "train"},
                {"experiment_id": "e2", "split": "validation"},
                {"experiment_id": "e3", "split": "test"},
                {"experiment_id": "e4", "split": "train"},
            ]
        }
        ids = np.array(["e1", "e2", "e3", "e4"])
        mask = partition_mask(ids, document, "train")
        self.assertEqual(mask.tolist(), [True, False, False, True])
        for s in ("train", "validation", "test"):
            expected = sum(1 for x in document["samples"] if x["split"] == s)
            self.assertEqual(int(partition_mask(ids, document, s).sum()), expected)

    def test_partition_mask_unknown_split_is_false(self):
        document = {"samples": [{"experiment_id": "e1", "split": "train"}]}
        mask = partition_mask(np.array(["e1"]), document, "missing")
        self.assertEqual(mask.tolist(), [False])


class ConfigureModelTest(unittest.TestCase):
    def test_hyperparameters(self):
        model = configure_model(seed=SPLIT_SEED)
        params = model.get_params()
        self.assertEqual(params["n_estimators"], 500)
        self.assertEqual(params["max_features"], "sqrt")
        self.assertEqual(params["min_samples_leaf"], 2)
        self.assertIsNone(params["max_depth"])
        self.assertEqual(params["class_weight"], "balanced_subsample")
        self.assertTrue(params["oob_score"])
        self.assertEqual(params["random_state"], SPLIT_SEED)


class ArtifactContractTest(unittest.TestCase):
    def _tiny_artifact(self):
        from sklearn.ensemble import RandomForestClassifier

        rng = np.random.default_rng(0)
        x = rng.normal(size=(60, 8))
        y = np.repeat(np.arange(6), 10)
        model = RandomForestClassifier(n_estimators=10, random_state=SPLIT_SEED)
        model.fit(x, y)
        return {
            "estimator": model,
            "feature_names": [f"f{i}" for i in range(8)],
            "feature_schema_version": "v2",
            "target_classes": list(TARGET_CLASSES),
            "label_encoder": {c: i for i, c in enumerate(TARGET_CLASSES)},
            "split_artifact": "split_v1.json",
            "split_hash": "abc",
            "input_fingerprints": {"run-a": "deadbeef"},
            "metadata": {
                "git_commit": "test",
                "created_at": "2026-09-24T00:00:00+00:00",
                "seed": SPLIT_SEED,
                "library_versions": {},
                "dataset_run_ids": ["run-a"],
                "sample_counts": {"total": 60},
                "hyperparameters": model.get_params(),
                "oob_score": None,
                "cv": None,
                "cv_error": None,
                "class_mapping": {c: i for i, c in enumerate(TARGET_CLASSES)},
            },
        }

    def test_roundtrip_and_required_keys(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "model.joblib"
            artifact = self._tiny_artifact()
            joblib.dump(artifact, path)
            loaded = load_artifact(path)
            for key in (
                "estimator", "feature_names", "feature_schema_version",
                "target_classes", "label_encoder", "split_artifact",
                "split_hash", "input_fingerprints", "metadata",
            ):
                self.assertIn(key, loaded)
            preds = loaded["estimator"].predict(np.zeros((3, 8)))
            self.assertEqual(len(preds), 3)

    def test_missing_key_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "model.joblib"
            artifact = self._tiny_artifact()
            del artifact["split_hash"]
            joblib.dump(artifact, path)
            with self.assertRaises(ValueError):
                load_artifact(path)

    def test_real_artifact_contract(self):
        model_path = Path("results/ml/model_traffic_rf_v1.joblib")
        if not model_path.exists():
            self.skipTest("model artifact not trained")
        artifact = load_artifact(model_path)
        self.assertEqual(len(artifact["feature_names"]), 57)
        self.assertEqual(len(artifact["target_classes"]), 6)
        self.assertTrue(artifact["split_hash"])
        split_doc = load_split()
        self.assertEqual(split_doc["split_hash"], artifact["split_hash"])


class MetricsTest(unittest.TestCase):
    def test_perfect_predictions(self):
        y_true = np.array([0, 1, 2, 3, 4, 5])
        metrics = compute_metrics(y_true, y_true.copy(), list(TARGET_CLASSES))
        self.assertEqual(metrics["accuracy"], 1.0)
        self.assertEqual(metrics["macro_f1"], 1.0)
        for row in metrics["per_class"]:
            self.assertEqual(row["support"], 1)

    def test_imperfect_predictions(self):
        y_true = np.array([0, 1, 2, 3, 4, 5])
        y_pred = np.array([0, 1, 2, 3, 4, 4])
        metrics = compute_metrics(y_true, y_pred, list(TARGET_CLASSES))
        self.assertLess(metrics["accuracy"], 1.0)
        self.assertEqual(metrics["confusion_matrix"][5][5], 0)


if __name__ == "__main__":
    unittest.main()