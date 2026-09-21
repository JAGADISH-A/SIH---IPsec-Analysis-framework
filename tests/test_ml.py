import unittest

from correlation.models import LiveFeatureWindow, MLResult


class TestLiveFeatureWindow(unittest.TestCase):
    def test_v2_window_survives_serialization(self):
        win = LiveFeatureWindow(
            feature_schema_version="v2",
            window_start_ns=123456789000,
            window_end_ns=123456789100,
            features={"ip_total": 480, "esp_packets": 120},
        )
        d = win.to_dict()
        self.assertEqual(d["feature_schema_version"], "v2")
        self.assertEqual(d["window_start_ns"], 123456789000)
        self.assertEqual(d["window_end_ns"], 123456789100)
        self.assertTrue(isinstance(d["features"], dict))
        restored = LiveFeatureWindow.from_json(win.to_json())
        self.assertEqual(restored, win)

    def test_non_v2_version_rejected(self):
        with self.assertRaises(ValueError):
            LiveFeatureWindow(
                feature_schema_version="v1",
                window_start_ns=0,
                window_end_ns=0,
                features={},
            )

    def test_features_must_be_dict(self):
        with self.assertRaises(ValueError):
            LiveFeatureWindow(features=["not", "a", "dict"])

    def test_window_end_before_start_rejected(self):
        with self.assertRaises(ValueError):
            LiveFeatureWindow(
                feature_schema_version="v2",
                window_start_ns=200,
                window_end_ns=100,
                features={},
            )


class TestMLResultContract(unittest.TestCase):
    def test_ml_result_accepts_none_fields(self):
        result = MLResult(model_version="v1")
        self.assertIsNone(result.traffic_class)
        self.assertIsNone(result.classification_confidence)
        self.assertIsNone(result.anomaly_score)

    def test_ml_result_full(self):
        result = MLResult(
            model_version="v1",
            traffic_class="video",
            classification_confidence=0.94,
            anomaly=False,
            anomaly_score=0.08,
            extras={"model_family": "placeholder-contract"},
        )
        d = result.to_dict()
        self.assertEqual(d["traffic_class"], "video")
        self.assertEqual(d["classification_confidence"], 0.94)
        restored = MLResult.from_json(result.to_json())
        self.assertEqual(restored, result)

    def test_ml_result_rejects_out_of_range_confidence(self):
        with self.assertRaises(ValueError):
            MLResult(model_version="v1", classification_confidence=1.5)

    def test_ml_result_rejects_negative_anomaly_score(self):
        with self.assertRaises(ValueError):
            MLResult(model_version="v1", anomaly_score=-0.1)


if __name__ == "__main__":
    unittest.main()