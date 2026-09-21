"""Phase 5 ML adapter tests (brief items 9-16).

The adapter is the boundary that normalizes RAW model output into correlation
vocabulary: raw label -> canonical traffic profile, confidence only when the
model genuinely provides probabilities, anomaly seam (absent when the model
lacks the capability, never fabricated), and fail-fast missing-feature
handling before any prediction.
"""

import json
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "fixtures", "ml"))

from fixtures import build_demo_model, make_row, specifically_mutated_row, valid_window  # noqa: E402
from correlation.ml import (  # noqa: E402
    FEATURE_COLUMNS,
    MLInferenceError,
    ModelAdapter,
    ModelMetadata,
    class_label_mapping,
)
from correlation.ml import (  # noqa: E402
    FeatureContractError,
    feature_vector,
)
from correlation.models import ALLOWED_TRAFFIC_PROFILES, MLResult  # noqa: E402


class _ProbingModel:
    """A model that records what the adapter fed it and can return any label."""

    def __init__(self, *, labels, predict_label="voip"):
        self._predict_label = predict_label
        self.calls = []
        self.metadata = ModelMetadata.from_values(
            model_version="probe-1",
            class_labels=labels,
        )

    def predict(self, vector):
        self.calls.append(tuple(vector))
        return self._predict_label

    def supports_probability(self):
        return False

    def predict_proba(self, vector):
        return {}

    def supports_anomaly(self):
        return False

    def score_anomaly(self, vector):
        raise AssertionError("anomaly scoring must not be called")


class TestModelAvailabilityAndLabelMapping(unittest.TestCase):
    def test_adapter_requires_model(self):
        with self.assertRaises(MLInferenceError):
            ModelAdapter(None)

    def test_explicit_identity_mapping_for_canonical_labels(self):
        mapping = class_label_mapping(ALLOWED_TRAFFIC_PROFILES)
        self.assertEqual(mapping, {label: label for label in ALLOWED_TRAFFIC_PROFILES})

    def test_unmappable_label_excluded_from_mapping(self):
        mapping = class_label_mapping(("voip", "bogus_label", "video"))
        self.assertNotIn("bogus_label", mapping)
        self.assertEqual(mapping["voip"], "voip")


class TestClassificationNormalization(unittest.TestCase):
    def test_raw_label_mapped_to_canonical_profile(self):
        model = build_demo_model()
        adapter = ModelAdapter(model)
        result = adapter.classify(valid_window("voip"))
        self.assertEqual(result.label, "voip")
        self.assertEqual(result.canonical_profile, "voip")
        self.assertIn(result.canonical_profile, ALLOWED_TRAFFIC_PROFILES)

    def test_unmappable_label_yields_no_canonical_profile(self):
        model = _ProbingModel(labels=("mystery_label",), predict_label="mystery_label")
        adapter = ModelAdapter(model)
        result = adapter.classify(valid_window())
        self.assertIsNone(result.canonical_profile)
        self.assertEqual(result.label, "mystery_label")
        self.assertIn("unmapped_label", result.extras)

    def test_confidence_null_when_model_provides_no_probabilities(self):
        model = build_demo_model(estimate_confidence=False)
        adapter = ModelAdapter(model)
        result = adapter.classify(valid_window("voip"))
        self.assertIsNone(result.classification_confidence)

    def test_confidence_preserved_from_provided_probabilities(self):
        model = build_demo_model(estimate_confidence=True)
        adapter = ModelAdapter(model)
        result = adapter.classify(valid_window("voip"))
        self.assertEqual(result.classification_confidence, 1.0)
        self.assertIsInstance(result.classification_confidence, float)


class TestProbingAndFailFast(unittest.TestCase):
    def test_predict_receives_exact_canonical_vector(self):
        window = valid_window("voip")
        model = _ProbingModel(labels=("voip", "video"))
        adapter = ModelAdapter(model)
        adapter.classify(window)
        self.assertEqual(len(model.calls), 1)
        received = list(model.calls[0])
        self.assertEqual(received, feature_vector(window))
        self.assertEqual(received, [float(window.features[n]) for n in FEATURE_COLUMNS])

    def test_missing_feature_fails_before_predict(self):
        model = _ProbingModel(labels=("voip", "video"))
        adapter = ModelAdapter(model)
        bad = specifically_mutated_row()
        del bad["packet_count"]
        window = valid_window()
        window = window.__class__(
            feature_schema_version=window.feature_schema_version,
            window_start_ns=window.window_start_ns,
            window_end_ns=window.window_end_ns,
            features=bad,
        )
        with self.assertRaises(FeatureContractError):
            adapter.classify(window)
        self.assertEqual(model.calls, [])


class TestAnomalySeam(unittest.TestCase):
    def test_anomaly_absent_when_model_lacks_capability(self):
        model = build_demo_model(anomaly_threshold=None)
        adapter = ModelAdapter(model)
        self.assertFalse(adapter.supports_anomaly())
        anomaly, score = adapter.evaluate_anomaly(valid_window("voip"))
        self.assertIsNone(anomaly)
        self.assertIsNone(score)

    def test_anomaly_capable_model_records_flag_and_score(self):
        model = build_demo_model(anomaly_threshold=0.5)
        adapter = ModelAdapter(model)
        self.assertTrue(adapter.supports_anomaly())
        anomaly, score = adapter.evaluate_anomaly(valid_window("voip"))
        self.assertIsInstance(anomaly, bool)
        self.assertIsInstance(score, float)
        self.assertGreaterEqual(score, 0.0)
        # A clean in-class window should NOT raise the anomaly flag.
        self.assertFalse(anomaly)

    def test_anomaly_verdict_never_becomes_a_risk_conclusion(self):
        model = build_demo_model(anomaly_threshold=1e-9)
        adapter = ModelAdapter(model)
        anomaly, score = adapter.evaluate_anomaly(valid_window("voip"))
        # Seam stays at the verdict level; no risk/high/severity derivation.
        self.assertIn(anomaly, (True, False))
        self.assertIsInstance(score, float)

    def test_nonnegative_score_enforced(self):
        class _NegScore(_ProbingModel):
            def __init__(self):
                super().__init__(labels=("voip", "video"))

            def supports_anomaly(self):
                return True

            def score_anomaly(self, vector):
                return -1.0

        adapter = ModelAdapter(_NegScore())
        with self.assertRaises(MLInferenceError):
            adapter.evaluate_anomaly(valid_window("voip"))


class TestMLResultSerialization(unittest.TestCase):
    def test_mlresult_serialization_and_roundtrip(self):
        who = {"source": "ml", "model_version": "v0-demo"}
        ml = MLResult(
            model_version="v0-demo",
            traffic_class="voip",
            classification_confidence=0.5,
            anomaly=False,
            anomaly_score=0.1,
            extras=who,
        )
        payload = ml.to_dict()
        self.assertIsInstance(payload, dict)
        back = MLResult.from_dict(payload)
        self.assertEqual(back.to_dict(), payload)
        self.assertEqual(json.dumps(back.to_dict(), sort_keys=True),
                         json.dumps(payload, sort_keys=True))

    def test_mlresult_roundtrip_preserves_provenance(self):
        ml = MLResult(model_version="traffic-rf-v1", traffic_class="video")
        back = MLResult.from_dict(json.loads(json.dumps(ml.to_dict(), sort_keys=True)))
        self.assertEqual(back.model_version, "traffic-rf-v1")
        self.assertEqual(back.traffic_class, "video")
        self.assertIsNone(back.classification_confidence)
        self.assertIsNone(back.anomaly)


if __name__ == "__main__":
    unittest.main()