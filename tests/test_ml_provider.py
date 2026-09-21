"""Phase 10 — live ML provider tests (unavailable / real / test-double)."""

import unittest

from correlation.ml.feature_contract import canonical_feature_names
from correlation.ml.errors import MLIntegrationError
from correlation.models import ALLOWED_TRAFFIC_PROFILES, LiveFeatureWindow
from correlation.streaming.ml_provider import (
    MODE_REAL_MODEL,
    MODE_TEST_DOUBLE,
    MODE_UNAVAILABLE,
    STATUS_COMPLETED,
    STATUS_FAILED,
    STATUS_UNREQUESTED,
    MLInferenceProvider,
    MLProviderResult,
    TestDoubleClassifierModel,
    TestDoubleWindowBuilder,
)
from correlation.streaming.windowing import (
    CLASS_ESP,
    CLASS_IKE,
    EmissionPolicy,
    WindowEngine,
)


def record():
    w = WindowEngine(window_ms=100, lookback=0)
    w.accept(ts_ns=0, event_type=CLASS_ESP, spi=1, seq=1, length=120)
    w.accept(ts_ns=1, event_type=CLASS_ESP, spi=1, seq=2, length=240)
    w.accept(ts_ns=2, event_type=CLASS_IKE, length=88)
    return w.flush()[0]


class TestProviderModes(unittest.TestCase):
    def test_default_mode_unavailable(self):
        provider = MLInferenceProvider()
        self.assertEqual(provider.availability, MODE_UNAVAILABLE)

    def test_real_model_requires_model(self):
        with self.assertRaises(ValueError):
            MLInferenceProvider(mode=MODE_REAL_MODEL, model=None)

    def test_invalid_mode_rejected(self):
        with self.assertRaises(ValueError):
            MLInferenceProvider(mode="magic")

    def test_unavailable_infer_unrequested(self):
        result = MLInferenceProvider().infer(LiveFeatureWindow())
        self.assertEqual(result.status, STATUS_UNREQUESTED)
        self.assertIsNone(result.ml_result)
        self.assertEqual(result.extras["reason"], "model_unavailable")
        self.assertEqual(result.latency_ns, None)


class TestTestDoubleWindowBuilder(unittest.TestCase):
    def test_builds_exactly_59_features(self):
        win = TestDoubleWindowBuilder().build(record())
        self.assertIsInstance(win, LiveFeatureWindow)
        self.assertEqual(win.feature_schema_version, "v2")
        self.assertEqual(len(win.features), 59)
        self.assertEqual(set(win.features), set(canonical_feature_names()))
        for value in win.features.values():
            self.assertIsInstance(value, (int, float))
            self.assertNotEqual(value, float("nan"))
            self.assertNotEqual(value, float("inf"))

    def test_features_honest_counts(self):
        builder = TestDoubleWindowBuilder()
        self.assertEqual(builder.label, "TEST_DOUBLE")
        win = builder.build(record())
        self.assertEqual(win.features["packet_count"], 3)
        self.assertEqual(win.features["ike_packet_count"], 1)
        self.assertEqual(win.features["total_bytes"],
                         record().bytes_seen)

    def test_empty_record(self):
        w = WindowEngine(window_ms=100, lookback=0, policy=EmissionPolicy(emit_empty=True))
        w.accept(ts_ns=0, event_type=CLASS_ESP)
        w.accept(ts_ns=300_000_000, event_type=CLASS_ESP)
        empty = [r for r in w.flush() if r.empty][0]
        win = TestDoubleWindowBuilder().build(empty)
        self.assertEqual(win.features["packet_count"], 0)


class TestTestDoubleClassifierModel(unittest.TestCase):
    def test_metadata_labels(self):
        model = TestDoubleClassifierModel()
        self.assertEqual(model.metadata.model_version, "test-double-v0")
        self.assertEqual(model.metadata.class_labels, ALLOWED_TRAFFIC_PROFILES)
        self.assertFalse(model.supports_probability())
        self.assertFalse(model.supports_anomaly())

    def test_deterministic_predict(self):
        model = TestDoubleClassifierModel()
        vector = [1.0] * 4
        self.assertEqual(model.predict(vector), model.predict(vector))
        self.assertIn(model.predict(vector), ALLOWED_TRAFFIC_PROFILES)


class TestTestDoubleProvider(unittest.TestCase):
    def setUp(self):
        self.window = TestDoubleWindowBuilder().build(record())
        ticks = iter([100, 950])
        self.provider = MLInferenceProvider(
            model=TestDoubleClassifierModel(),
            mode=MODE_TEST_DOUBLE,
            clock=lambda: next(ticks),
        )

    def test_completed_with_provenance(self):
        result = self.provider.infer(self.window)
        self.assertEqual(result.status, STATUS_COMPLETED)
        self.assertIsNotNone(result.ml_result)
        self.assertIn(result.ml_result.traffic_class, ALLOWED_TRAFFIC_PROFILES)
        self.assertEqual(result.extras["test_double"], True)
        self.assertIn("no accuracy/precision", result.extras["disclaimer"])
        self.assertEqual(result.latency_ns, 850)

    def test_integration_error_maps_to_failed(self):
        class BrokenModel:
            metadata = type(
                "M",
                (),
                {
                    "model_version": "broken-v0",
                    "model_type": "broken",
                    "class_labels": ALLOWED_TRAFFIC_PROFILES,
                },
            )()

            def supports_probability(self):
                return False

            def supports_anomaly(self):
                return False

            def predict(self, vector):
                raise MLIntegrationError("model crashed")

            def predict_proba(self, vector):
                return {}

            def score_anomaly(self, vector):
                return 0.0

        provider = MLInferenceProvider(model=BrokenModel(), mode=MODE_REAL_MODEL)
        result = provider.infer(self.window)
        self.assertEqual(result.status, STATUS_FAILED)
        self.assertIn("model crashed", result.error)

    def test_to_stream_event(self):
        from correlation.models import CorrelationIdentity
        from correlation.streaming.models import EVENT_TYPE_ML_RESULT

        result = self.provider.infer(self.window)
        identity = CorrelationIdentity(
            dataset_run_id="dataset-20260916-231246",
            sequence=1, experiment_id="exp-ml", attempt_number=1,
        )
        e = self.provider.to_stream_event(self.window, result, identity=identity)
        self.assertEqual(e.source, "ml_provider")
        self.assertEqual(e.event_type, EVENT_TYPE_ML_RESULT)
        self.assertEqual(e.payload["status"], STATUS_COMPLETED)
        self.assertTrue(e.payload["extras"]["test_double"])
        self.assertEqual(e.payload["feature_schema_version"], "v2")


if __name__ == "__main__":
    unittest.main()