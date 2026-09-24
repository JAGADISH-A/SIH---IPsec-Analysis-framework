"""Tests for controller.shap_analysis (representation handling + non-interference)."""

import unittest

import numpy as np

from controller.grouped_split import SPLIT_SEED
from controller.shap_analysis import normalize_class_arrays


def tiny_model(x, y):
    from sklearn.ensemble import RandomForestClassifier

    model = RandomForestClassifier(n_estimators=20, random_state=SPLIT_SEED)
    model.fit(x, y)
    return model


class NormalizeClassArraysTest(unittest.TestCase):
    def test_ndarray_n_samples_n_features_n_classes(self):
        arrays, rep = normalize_class_arrays(
            np.zeros((10, 4, 3)), n_classes=3, n_samples=10, n_features=4
        )
        self.assertEqual(len(arrays), 3)
        self.assertTrue(all(a.shape == (10, 4) for a in arrays))
        self.assertEqual(rep["type"], "ndarray")
        self.assertIn("n_samples, n_features, n_classes", rep["note"])

    def test_list_of_arrays(self):
        arrays, rep = normalize_class_arrays(
            [np.zeros((10, 4)) for _ in range(3)],
            n_classes=3, n_samples=10, n_features=4,
        )
        self.assertEqual(len(arrays), 3)
        self.assertEqual(rep["type"], "list")

    def test_wrong_class_count_rejected(self):
        with self.assertRaises(ValueError):
            normalize_class_arrays(
                [np.zeros((10, 4)) for _ in range(2)],
                n_classes=3, n_samples=10, n_features=4,
            )

    def test_unrecognized_ndim_rejected(self):
        with self.assertRaises(ValueError):
            normalize_class_arrays(
                np.zeros((10, 3, 4, 2)), n_classes=3, n_samples=10, n_features=4
            )


class ShapNonInterferenceTest(unittest.TestCase):
    def test_shap_does_not_change_model_outputs(self):
        import shap

        rng = np.random.default_rng(42)
        x = rng.normal(size=(80, 6))
        y = np.repeat(np.arange(6), 14)[:80]
        model = tiny_model(x, y)
        probs_before = model.predict_proba(x).copy()
        preds_before = model.predict(x).copy()
        explainer = shap.TreeExplainer(model, feature_names=[f"f{i}" for i in range(6)])
        raw = explainer.shap_values(x)
        probs_after = model.predict_proba(x)
        preds_after = model.predict(x)
        self.assertTrue(np.array_equal(probs_before, probs_after))
        self.assertTrue(np.array_equal(preds_before, preds_after))
        self.assertIsNotNone(raw)

    def test_explainer_run_matches_representation_contract(self):
        import shap

        rng = np.random.default_rng(7)
        x = rng.normal(size=(30, 5))
        y = np.repeat(np.arange(5), 6)
        model = tiny_model(x, y)
        explainer = shap.TreeExplainer(model)
        raw = explainer.shap_values(x)
        arrays, rep = normalize_class_arrays(raw, n_classes=5, n_samples=30, n_features=5)
        self.assertEqual(len(arrays), 5)
        self.assertTrue(all(a.shape == (30, 5) for a in arrays))
        self.assertEqual({"type", "note", "shape"} <= set(rep), True)


if __name__ == "__main__":
    unittest.main()