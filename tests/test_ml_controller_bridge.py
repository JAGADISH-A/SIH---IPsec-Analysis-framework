"""Integration tests: controller RF -> correlation ML boundary bridge.

Covers the seam added in ``correlation/ml/controller_bridge.py`` following the
EXISTING Phase 5 semantics (expected-vs-ML comparison is source-labeled ML
metadata only; protocol comparison lists/status are never touched):

1. MATCH           expected traffic.profile = "voip", controller predicts
                   "voip" -> ML comparison MATCH, source "ml", class "voip"
2. MISMATCH        expected "voip", controller predicts "web" -> MISMATCH with
                   expected_profile "voip" / ml_traffic_class "web"
3. PROVENANCE      MLResult.extras preserves source, model_version,
                   feature_schema_version, window_id, timestamp, and the FULL
                   six-class probabilities vector
4. EXPECTED-STATE  expected state (ExpectedState and MaterializedExpectedState)
   INDEPENDENCE    is byte-identical before and after ML inference
5. PROTOCOL        matches / mismatches / unknowns / not_applicable / status
   NON-INTERFERENCE are untouched by ML MATCH/MISMATCH
6. ANOMALY SEAM    anomaly is None and anomaly_score is None (RF is a
                   traffic-profile classifier only; ML_ANOMALY = NOT_APPLICABLE)
7. PROBABILITY     classification_confidence equals the probability of the
                   predicted traffic_profile and stays in [0, 1]

The mapping-only tests never import the trained model. The real-RF tests drive
the ACTUAL artifact (``results/ml/model_traffic_rf_v1.joblib``) with real rows
from the protected datasets and skip cleanly when those artifacts are absent.
"""

import json
import unittest
from pathlib import Path

from correlation.adapters import MaterializedExpectedState
from correlation.comparison import ComparisonEngine
from correlation.ml.controller_bridge import (
    controller_result_to_ml_result,
    correlate_with_controller_ml,
    infer_controller_ml_result,
    live_window_to_controller_record,
)
from correlation.ml.integration import correlate_with_ml
from correlation.models import (
    ALLOWED_TRAFFIC_PROFILES,
    CORRELATION_STATUS_MATCH,
    CORRELATION_STATUS_MISMATCH,
    CORRELATION_STATUS_NOT_APPLICABLE,
    CorrelationIdentity,
    EspExpected,
    ExpectedState,
    IkeExpected,
    LiveFeatureWindow,
    MLResult,
    ObservedState,
    TrafficExpected,
)

WIN_START = 0
WIN_END = 100_000_000
WINDOW_ID = f"{WIN_START}-{WIN_END}"

EXPECTED_VOIP = ExpectedState(
    mode="tunnel",
    address_family="ipv4",
    ike=IkeExpected(version=2, encryption="aes256", integrity="sha256",
                    dh_group="modp2048"),
    esp=EspExpected(encryption="aes256gcm16", integrity=None,
                    dh_group="modp2048", pfs=True),
    traffic=TrafficExpected(profile="voip", duration=30, port=5060),
    capture_filter="udp port 500 or udp port 4500",
)

IDENTITY = CorrelationIdentity(
    dataset_run_id="run-bridge-1", sequence=1, experiment_id="exp-bridge-1",
    attempt_number=1,
)

PROFILES = tuple(ALLOWED_TRAFFIC_PROFILES)


def synthetic_result(profile: str, confidence: float = 1.0) -> dict:
    """Deterministic six-class controller result (no model required)."""
    probabilities = {p: 0.0 for p in PROFILES}
    probabilities[profile] = confidence
    others = sum(1 for p in PROFILES if p != profile)
    if others:
        remainder = (1.0 - confidence) / others
    for p in PROFILES:
        probabilities[p] += remainder if p != profile else 0.0
    return {
        "model_version": "traffic_rf_v1",
        "feature_schema_version": "v2",
        "window_id": WINDOW_ID,
        "timestamp": "2026-09-24T00:00:00Z",
        "traffic_profile": profile,
        "probabilities": probabilities,
    }


def observed_basic():
    return ObservedState(timestamp_ns=10)


def run_with_ml_result(engine, ml_result):
    return correlate_with_ml(
        engine,
        EXPECTED_VOIP,
        observed_basic(),
        identity=IDENTITY,
        observed_identity=IDENTITY,
        ml_result=ml_result,
        observed_values={},
    )


class TestControllerResultMapping(unittest.TestCase):
    def test_maps_all_fields_to_ml_result_contract(self):
        result = controller_result_to_ml_result(synthetic_result("voip"))
        self.assertIsInstance(result, MLResult)
        self.assertEqual(result.model_version, "traffic_rf_v1")
        self.assertEqual(result.traffic_class, "voip")
        self.assertEqual(result.classification_confidence, 1.0)
        self.assertIsNone(result.anomaly)
        self.assertIsNone(result.anomaly_score)

    def test_extras_preserve_full_provenance_and_probability_vector(self):
        source = synthetic_result("voip", confidence=0.8)
        result = controller_result_to_ml_result(source)
        extras = result.extras
        self.assertEqual(extras["source"], "ml")
        self.assertEqual(extras["model_version"], "traffic_rf_v1")
        self.assertEqual(extras["feature_schema_version"], "v2")
        self.assertEqual(extras["window_id"], WINDOW_ID)
        self.assertEqual(extras["timestamp"], "2026-09-24T00:00:00Z")
        self.assertEqual(extras["traffic_profile"], "voip")
        self.assertEqual(set(extras["probabilities"]), set(PROFILES))
        self.assertAlmostEqual(extras["probabilities"]["voip"], 0.8)
        # full vector preserved, never collapsed to a single confidence number
        self.assertEqual(len(extras["probabilities"]), 6)

    def test_confidence_matches_predicted_class_probability(self):
        result = controller_result_to_ml_result(synthetic_result("web", 0.6))
        self.assertEqual(result.classification_confidence, 0.6)
        self.assertTrue(0.0 <= result.classification_confidence <= 1.0)

    def test_traffic_profile_outside_canonical_six_rejected(self):
        bad = synthetic_result("voip")
        bad["traffic_profile"] = "http"
        with self.assertRaises(ValueError):
            controller_result_to_ml_result(bad)

    def test_missing_controller_field_rejected(self):
        bad = synthetic_result("voip")
        del bad["probabilities"]
        with self.assertRaises(ValueError):
            controller_result_to_ml_result(bad)

    def test_probability_vector_with_unknown_class_rejected(self):
        bad = synthetic_result("voip")
        bad["probabilities"]["http"] = 0.0
        with self.assertRaises(ValueError):
            controller_result_to_ml_result(bad)

    def test_probability_vector_missing_class_rejected(self):
        bad = synthetic_result("voip")
        del bad["probabilities"]["icmp"]
        with self.assertRaises(ValueError):
            controller_result_to_ml_result(bad)

    def test_probability_out_of_range_rejected(self):
        bad = synthetic_result("voip")
        bad["probabilities"]["voip"] = 1.5
        bad["probabilities"]["web"] = -0.5
        with self.assertRaises(ValueError):
            controller_result_to_ml_result(bad)

    def test_probabilities_not_summing_to_one_rejected(self):
        bad = synthetic_result("voip")
        bad["probabilities"]["voip"] = 1.0
        bad["probabilities"]["web"] = 1.0
        with self.assertRaises(ValueError):
            controller_result_to_ml_result(bad)

    def test_input_dict_not_mutated(self):
        source = synthetic_result("voip")
        before = json.dumps(source, sort_keys=True)
        controller_result_to_ml_result(source)
        self.assertEqual(json.dumps(source, sort_keys=True), before)


class TestExpectedVsControllerML(unittest.TestCase):
    def _comparison(self, ml_result, variable="ML_TRAFFIC_CLASSIFICATION"):
        result = run_with_ml_result(ComparisonEngine(), ml_result)
        return result, next(
            c for c in result.metadata["ml"]["comparisons"]
            if c["variable"] == variable
        )

    def test_match_when_expected_and_ml_agree(self):
        ml_result = controller_result_to_ml_result(synthetic_result("voip"))
        result, comparison = self._comparison(ml_result)
        self.assertEqual(result.metadata["ml"]["model_available"], True)
        self.assertEqual(comparison["status"], CORRELATION_STATUS_MATCH)
        self.assertEqual(comparison["source"], "ml")
        self.assertEqual(comparison["ml_traffic_class"], "voip")
        self.assertEqual(comparison["expected_profile"], "voip")
        self.assertIs(comparison["is_authoritative_observation"], False)

    def test_mismatch_when_expected_and_ml_disagree(self):
        ml_result = controller_result_to_ml_result(synthetic_result("web"))
        result, comparison = self._comparison(ml_result)
        self.assertEqual(comparison["status"], CORRELATION_STATUS_MISMATCH)
        self.assertEqual(comparison["expected_profile"], "voip")
        self.assertEqual(comparison["ml_traffic_class"], "web")
        self.assertIs(comparison["is_authoritative_observation"], False)

    def test_provenance_flows_into_result_metadata(self):
        ml_result = controller_result_to_ml_result(synthetic_result("voip"))
        result, _ = self._comparison(ml_result)
        attached = result.metadata["ml"]["ml_result"]
        self.assertEqual(attached["model_version"], "traffic_rf_v1")
        self.assertEqual(attached["traffic_class"], "voip")
        for key in ("source", "model_version", "feature_schema_version",
                    "window_id", "timestamp", "probabilities"):
            self.assertIn(key, attached["extras"])

    def test_anomaly_seam_never_fabricates_a_verdict(self):
        ml_result = controller_result_to_ml_result(synthetic_result("voip"))
        self.assertIsNone(ml_result.anomaly)
        self.assertIsNone(ml_result.anomaly_score)
        _, anomaly = self._comparison(ml_result, "ML_ANOMALY")
        self.assertEqual(anomaly["status"], CORRELATION_STATUS_NOT_APPLICABLE)
        self.assertEqual(anomaly["anomaly"], None)
        self.assertEqual(anomaly["anomaly_score"], None)


class TestProtocolNonInterference(unittest.TestCase):
    def _baseline(self):
        return ComparisonEngine().compare(
            EXPECTED_VOIP, observed_basic(),
            identity=IDENTITY, observed_identity=IDENTITY, observed_values={},
        )

    def test_ml_match_leaves_protocol_result_untouched(self):
        baseline = self._baseline()
        result = run_with_ml_result(
            ComparisonEngine(),
            controller_result_to_ml_result(synthetic_result("voip")),
        )
        self.assertEqual(result.status, baseline.status)
        self.assertEqual(result.matches, baseline.matches)
        self.assertEqual(result.mismatches, baseline.mismatches)
        self.assertEqual(result.unknowns, baseline.unknowns)
        self.assertEqual(result.not_applicable, baseline.not_applicable)

    def test_ml_mismatch_leaves_protocol_result_untouched(self):
        baseline = self._baseline()
        result = run_with_ml_result(
            ComparisonEngine(),
            controller_result_to_ml_result(synthetic_result("web")),
        )
        self.assertEqual(result.status, baseline.status)
        self.assertEqual(result.matches, baseline.matches)
        self.assertEqual(result.mismatches, baseline.mismatches)
        self.assertEqual(result.unknowns, baseline.unknowns)
        self.assertEqual(result.not_applicable, baseline.not_applicable)

    def test_ml_variables_never_enter_protocol_lists(self):
        ml_result = controller_result_to_ml_result(synthetic_result("web"))
        result = run_with_ml_result(ComparisonEngine(), ml_result)
        for list_name in ("matches", "mismatches", "unknowns", "not_applicable"):
            variables = {item.get("variable") for item in getattr(result, list_name)}
            self.assertNotIn("ML_TRAFFIC_CLASSIFICATION", variables)
            self.assertNotIn("ML_ANOMALY", variables)


class TestExpectedStateIndependence(unittest.TestCase):
    def _expected_snapshot(self):
        return json.dumps(EXPECTED_VOIP.to_dict(), sort_keys=True)

    def test_expected_state_identical_before_and_after_inference(self):
        before = self._expected_snapshot()
        ml_result = controller_result_to_ml_result(synthetic_result("voip"))
        run_with_ml_result(ComparisonEngine(), ml_result)
        self.assertEqual(self._expected_snapshot(), before)

    def test_materialized_expected_state_passed_through_unchanged(self):
        materialized = MaterializedExpectedState(
            expected=EXPECTED_VOIP, identity=IDENTITY, provenance={},
        )
        before = json.dumps(materialized.expected.to_dict(), sort_keys=True)
        result = correlate_with_ml(
            ComparisonEngine(), materialized, observed_basic(),
            identity=IDENTITY, observed_identity=IDENTITY,
            ml_result=controller_result_to_ml_result(synthetic_result("voip")),
        )
        self.assertIsNotNone(result.metadata["ml"]["ml_result"])
        self.assertEqual(
            json.dumps(materialized.expected.to_dict(), sort_keys=True), before
        )

    def test_expected_state_never_leaks_into_ml_result(self):
        ml_result = controller_result_to_ml_result(synthetic_result("voip"))
        self.assertNotIn("expected", ml_result.extras)
        # The mapping is a pure function of the controller result: it never
        # consults (or can be influenced by) any expected state.
        self.assertEqual(ml_result.traffic_class, "voip")


class TestLiveWindowConversion(unittest.TestCase):
    def _window(self, **features) -> LiveFeatureWindow:
        from tests.fixtures.ml.fixtures import make_row

        data = make_row(100.0)
        data.update(features)
        return LiveFeatureWindow(
            feature_schema_version="v2",
            window_start_ns=WIN_START,
            window_end_ns=WIN_END,
            features=data,
        )

    def test_live_window_to_controller_record_shape(self):
        window = self._window()
        record = live_window_to_controller_record(window)
        self.assertEqual(record["feature_schema_version"], "v2")
        self.assertEqual(record["window_start_ns"], WIN_START)
        self.assertEqual(record["window_end_ns"], WIN_END)
        self.assertEqual(set(record["features"]), set(window.features))

    def test_bad_window_features_rejected_before_controller(self):
        window = LiveFeatureWindow(
            feature_schema_version="v2",
            window_start_ns=WIN_START,
            window_end_ns=WIN_END,
            features={"packet_count": 1},  # not the 59-feature v2 schema
        )
        with self.assertRaises(Exception):
            live_window_to_controller_record(window)

    def test_non_v2_window_rejected(self):
        with self.assertRaises(Exception):
            live_window_to_controller_record(
                LiveFeatureWindow(
                    feature_schema_version="v1",
                    window_start_ns=WIN_START,
                    window_end_ns=WIN_END,
                    features={},
                )
            )


class _RealRfBase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._candidates = None

    @staticmethod
    def _datasets_present() -> bool:
        from controller.dataset_loader import (
            DEFAULT_DATASETS_DIR,
            PROTECTED_DATASET_RUN_IDS,
        )

        return all(
            (DEFAULT_DATASETS_DIR / run / "features.parquet").exists()
            for run in PROTECTED_DATASET_RUN_IDS
        )

    @classmethod
    def _real_windows(cls):
        """(profile, LiveFeatureWindow) for every protected sample, real RF pred."""
        if cls._candidates is not None:
            return cls._candidates
        if not cls._datasets_present():
            cls._candidates = None
            return None
        import pyarrow.parquet as pq

        from controller import ml_inference
        from controller.dataset_artifacts import (
            FEATURE_COLUMNS,
            INT_FEATURES,
        )
        from controller.dataset_loader import (
            DEFAULT_DATASETS_DIR,
            PROTECTED_DATASET_RUN_IDS,
        )

        records = []
        profiles = []
        for run in PROTECTED_DATASET_RUN_IDS:
            data = pq.read_table(
                str(DEFAULT_DATASETS_DIR / run / "features.parquet")
            ).to_pydict()
            profs = data["traffic_profile"]
            for i in range(len(profs)):
                features = {}
                for column in FEATURE_COLUMNS:
                    value = data[column][i]
                    features[column] = (
                        int(value) if column in INT_FEATURES else float(value)
                    )
                records.append({
                    "feature_schema_version": "v2",
                    "window_start_ns": WIN_START,
                    "window_end_ns": WIN_END,
                    "features": features,
                })
                profiles.append(profs[i])
        results = ml_inference.predict_many(
            records, timestamp="2026-09-24T00:00:00Z"
        )
        windows = {}
        for profile, record, result in zip(profiles, records, results):
            if profile not in ("voip", "web"):
                continue
            key = f"{profile}->{result['traffic_profile']}"
            if key not in windows:
                windows[key] = (
                    profile,
                    result,
                    LiveFeatureWindow(
                        feature_schema_version="v2",
                        window_start_ns=WIN_START,
                        window_end_ns=WIN_END,
                        features=dict(record["features"]),
                    ),
                )
        cls._candidates = windows
        return windows

    @classmethod
    def _window_for(cls, ground_truth: str, predicted: str):
        candidates = cls._real_windows()
        if candidates is None:
            raise unittest.SkipTest(
                "protected datasets absent; real RF path skipped"
            )
        key = f"{ground_truth}->{predicted}"
        if key not in candidates or candidates[key][2] is None:
            raise unittest.SkipTest(
                f"no protected {ground_truth} sample predicted {predicted!r} "
                "by the committed RF artifact"
            )
        return candidates[key]


class TestRealRfPath(_RealRfBase):
    def test_committed_rf_classifies_voip_as_voip(self):
        candidates = self._real_windows()
        if candidates is None:
            self.skipTest("protected datasets absent; real RF path skipped")
        if "voip->voip" not in candidates:
            self.fail(
                "committed RF artifact classifies no protected voip sample as "
                "voip; the MATCH test needs one"
            )
        _, result, _ = candidates["voip->voip"]
        self.assertEqual(result["traffic_profile"], "voip")

    def test_committed_rf_classifies_web_as_web(self):
        candidates = self._real_windows()
        if candidates is None:
            self.skipTest("protected datasets absent; real RF path skipped")
        if "web->web" not in candidates:
            self.fail(
                "committed RF artifact classifies no protected web sample as "
                "web; the MISMATCH test needs one"
            )
        _, result, _ = candidates["web->web"]
        self.assertEqual(result["traffic_profile"], "web")

    def test_match_with_real_rf_on_protected_voip_window(self):
        _, result, window = self._window_for("voip", "voip")
        correlation = correlate_with_controller_ml(
            ComparisonEngine(), EXPECTED_VOIP, observed_basic(),
            identity=IDENTITY, observed_identity=IDENTITY,
            window=window, timestamp="2026-09-24T00:00:00Z",
        )
        comparison = correlation.metadata["ml"]["comparisons"][0]
        self.assertEqual(comparison["variable"], "ML_TRAFFIC_CLASSIFICATION")
        self.assertEqual(comparison["status"], CORRELATION_STATUS_MATCH)
        self.assertEqual(comparison["source"], "ml")
        self.assertEqual(comparison["ml_traffic_class"], "voip")
        self.assertEqual(result["traffic_profile"], "voip")

    def test_mismatch_with_real_rf_on_protected_web_window(self):
        _, result, window = self._window_for("web", "web")
        correlation = correlate_with_controller_ml(
            ComparisonEngine(), EXPECTED_VOIP, observed_basic(),
            identity=IDENTITY, observed_identity=IDENTITY,
            window=window, timestamp="2026-09-24T00:00:00Z",
        )
        comparison = correlation.metadata["ml"]["comparisons"][0]
        self.assertEqual(comparison["status"], CORRELATION_STATUS_MISMATCH)
        self.assertEqual(comparison["expected_profile"], "voip")
        self.assertEqual(comparison["ml_traffic_class"], "web")
        self.assertEqual(result["traffic_profile"], "web")

    def test_real_ml_result_contract(self):
        _, _, window = self._window_for("voip", "voip")
        ml_result = infer_controller_ml_result(
            window, timestamp="2026-09-24T00:00:00Z"
        )
        self.assertEqual(ml_result.model_version, "traffic_rf_v1")
        self.assertEqual(ml_result.traffic_class, "voip")
        self.assertTrue(0.0 <= ml_result.classification_confidence <= 1.0)
        self.assertIsNone(ml_result.anomaly)
        self.assertIsNone(ml_result.anomaly_score)
        self.assertEqual(ml_result.extras["feature_schema_version"], "v2")
        self.assertEqual(ml_result.extras["window_id"], WINDOW_ID)
        self.assertEqual(ml_result.extras["source"], "ml")
        self.assertEqual(set(ml_result.extras["probabilities"]), set(PROFILES))

    def test_real_rf_match_does_not_change_protocol_status(self):
        baseline = ComparisonEngine().compare(
            EXPECTED_VOIP, observed_basic(),
            identity=IDENTITY, observed_identity=IDENTITY, observed_values={},
        )
        _, _, window = self._window_for("voip", "voip")
        result = correlate_with_controller_ml(
            ComparisonEngine(), EXPECTED_VOIP, observed_basic(),
            identity=IDENTITY, observed_identity=IDENTITY,
            window=window, timestamp="2026-09-24T00:00:00Z",
        )
        self.assertEqual(result.status, baseline.status)
        self.assertEqual(result.matches, baseline.matches)
        self.assertEqual(result.mismatches, baseline.mismatches)
        self.assertEqual(result.unknowns, baseline.unknowns)
        self.assertEqual(result.not_applicable, baseline.not_applicable)


if __name__ == "__main__":
    unittest.main()