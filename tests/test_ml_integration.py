"""Phase 5 ML integration tests (brief items 17-31).

End-to-end FEATURES -> ML -> MLResult -> CORRELATION: model availability,
provenance/determinism, artifact safety, Expected-vs-ML outcomes (never in
protocol mismatch lists, never a risk conclusion), correct ml_evaluated flag,
and the real-v2-path validation against the authoritative extractor when
``D:\\sihipsec`` is present.
"""

import importlib.util
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "fixtures", "ml"))

from fixtures import (  # noqa: E402
    CENTROID_ARTIFACT,
    VOIP_BASE,
    build_demo_model,
    feature_window,
    make_row,
    valid_window,
)
from correlation.adapters import ExpectedStateAdapter  # noqa: E402
from correlation.comparison import ComparisonEngine  # noqa: E402
from correlation.ml import (  # noqa: E402
    FEATURE_COLUMNS,
    FEATURE_SCHEMA_VERSION,
    FeatureContractError,
    ModelMetadataError,
    ModelArtifactError,
    ModelMetadata,
    load_artifact,
    normalize_feature_values,
    run_ml_inference,
    save_artifact,
    train_nearest_centroid,
    validate_feature_values,
    validate_feature_window,
    verify_authoritative_contract,
)
from correlation.ml.integration import (  # noqa: E402
    correlate_with_ml,
)
from correlation.models import (  # noqa: E402
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

SIHIPSEC_ROOT = r"D:\sihipsec"

EXPECTED_VOIP = ExpectedState(
    mode="tunnel",
    address_family="ipv4",
    ike=IkeExpected(version=2, encryption="aes256", integrity="sha256", dh_group="modp2048"),
    esp=EspExpected(encryption="aes256gcm16", integrity=None, dh_group="modp2048", pfs=True),
    traffic=TrafficExpected(profile="voip", duration=30, port=5060),
    capture_filter="udp port 500 or udp port 4500",
)

IDENTITY = CorrelationIdentity(
    dataset_run_id="run-ml-1", sequence=1, experiment_id="exp-ml-1", attempt_number=1
)


def observed_basic():
    return ObservedState(timestamp_ns=10)


def run_engine_without_ml(engine, *, window=None, ml_result=None):
    return engine.compare(
        EXPECTED_VOIP,
        observed_basic(),
        identity=IDENTITY,
        observed_identity=IDENTITY,
        ml_result=ml_result,
        observed_values={},
    )


def encode(value):
    return json.dumps(value, sort_keys=True)


class TestModelAvailability(unittest.TestCase):
    def test_no_model_is_recorded_absent_not_fabricated(self):
        engine = ComparisonEngine()
        baseline = run_engine_without_ml(engine)
        result = correlate_with_ml(
            engine,
            EXPECTED_VOIP,
            observed_basic(),
            identity=IDENTITY,
            observed_identity=IDENTITY,
        )
        ml = result.metadata["ml"]
        self.assertFalse(ml["model_available"])
        self.assertIsNone(ml["ml_result"])
        self.assertFalse(ml["ml_evaluated"])
        classification = ml["comparisons"][0]
        self.assertEqual(classification["variable"], "ML_TRAFFIC_CLASSIFICATION")
        self.assertEqual(classification["status"], "UNKNOWN")
        anomaly = ml["comparisons"][1]
        self.assertEqual(anomaly["variable"], "ML_ANOMALY")
        self.assertEqual(anomaly["status"], CORRELATION_STATUS_NOT_APPLICABLE)
        # protocol comparison still ran, unaffected by absent ML
        self.assertEqual(result.status, baseline.status)
        self.assertEqual(result.matches, baseline.matches)

    def test_protocol_still_evaluated_when_ml_absent(self):
        engine = ComparisonEngine()
        result = correlate_with_ml(
            engine, EXPECTED_VOIP, observed_basic(),
            identity=IDENTITY, observed_identity=IDENTITY,
        )
        self.assertTrue(result.metadata["rules_executed"])
        self.assertGreaterEqual(len(result.metadata["comparison_engine_version"]), 1)


class TestDeterminismAndProvenance(unittest.TestCase):
    def test_same_window_same_model_identical_output(self):
        model = build_demo_model()
        w = valid_window("voip")
        first = run_ml_inference(w, model)
        second = run_ml_inference(w, model)
        self.assertEqual(encode(first.to_dict()), encode(second.to_dict()))

    def test_model_version_recorded_in_ml_result(self):
        model = build_demo_model(model_version="v7-tag")
        result = run_ml_inference(valid_window("voip"), model)
        self.assertEqual(result.model_version, "v7-tag")
        self.assertEqual(result.extras["model_version"], "v7-tag")

    def test_extras_marked_source_ml(self):
        model = build_demo_model()
        result = run_ml_inference(valid_window("voip"), model)
        self.assertEqual(result.extras["source"], "ml")
        self.assertEqual(result.extras["feature_schema_version"], "v2")

    def test_model_version_change_reflected_but_predictions_stable(self):
        a = run_ml_inference(valid_window("voip"), build_demo_model(model_version="ver-a"))
        b = run_ml_inference(valid_window("voip"), build_demo_model(model_version="ver-b"))
        self.assertEqual(a.traffic_class, b.traffic_class)
        self.assertNotEqual(a.model_version, b.model_version)


class TestArtifactSafety(unittest.TestCase):
    def test_committed_artifact_loads_with_full_provenance(self):
        model = load_artifact(CENTROID_ARTIFACT)
        md = model.metadata
        self.assertEqual(md.model_version, "v0-demo")
        self.assertEqual(md.feature_schema_version, FEATURE_SCHEMA_VERSION)
        self.assertEqual(tuple(md.feature_names), tuple(FEATURE_COLUMNS))
        self.assertEqual(set(model.metadata.class_labels), {"voip", "video"})
        self.assertEqual(md.model_type, "nearest_centroid")
        self.assertIn("training_dataset", md.to_dict())
        self.assertIn("training_timestamp", md.to_dict())

    def test_training_is_reproducible_byte_identical(self):
        rows = [("voip", make_row(VOIP_BASE, i)) for i in range(4)]
        rows += [("video", make_row(1500, i)) for i in range(4)]
        m1 = train_nearest_centroid(rows, model_version="r", training_dataset="t")
        m2 = train_nearest_centroid(rows, model_version="r", training_dataset="t")
        with tempfile.TemporaryDirectory() as d:
            p1, p2 = os.path.join(d, "a.json"), os.path.join(d, "b.json")
            save_artifact(m1, p1)
            save_artifact(m2, p2)
            with open(p1, "rb") as a, open(p2, "rb") as b:
                self.assertEqual(a.read(), b.read())

    def test_artifact_json_not_pickle_and_path_safety(self):
        with tempfile.TemporaryDirectory() as d:
            missing = os.path.join(d, "nope.json")
            with self.assertRaises(ModelArtifactError):
                load_artifact(missing)
            pkl = os.path.join(d, "model.pkl")
            with open(pkl, "wb") as fh:
                fh.write(b"!fake-pickle!")
            with self.assertRaises(ModelArtifactError):
                save_artifact(build_demo_model(), pkl)
            with self.assertRaises(ModelArtifactError):
                load_artifact(pkl)
            bad = os.path.join(d, "bad.json")
            with open(bad, "w", encoding="utf-8") as fh:
                fh.write("{not json")
            with self.assertRaises(ModelArtifactError):
                load_artifact(bad)

    def test_artifact_with_wrong_feature_order_rejected(self):
        with open(CENTROID_ARTIFACT, encoding="utf-8") as fh:
            data = json.load(fh)
        data["metadata"]["feature_names"] = list(reversed(data["metadata"]["feature_names"]))
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "bad.json")
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(data, fh)
            with self.assertRaises(ModelArtifactError):
                load_artifact(path)

    def test_artifact_metadata_order_enforced_at_load(self):
        with open(CENTROID_ARTIFACT, encoding="utf-8") as fh:
            data = json.load(fh)
        md = data["metadata"].copy()
        md["feature_names"] = list(reversed(md["feature_names"]))
        with self.assertRaises(ModelMetadataError):
            ModelMetadata.from_dict(md)


class TestFeatureParityRejectsSilentAdaptation(unittest.TestCase):
    def test_window_missing_feature_rejected_before_predict(self):
        model = build_demo_model()
        bad = make_row(VOIP_BASE)
        del bad["ike_packet_count"]
        w = feature_window(bad)
        with self.assertRaises(FeatureContractError):
            run_ml_inference(w, model)

    def test_window_extra_feature_rejected(self):
        model = build_demo_model()
        bad = make_row(VOIP_BASE)
        bad["purple_feature"] = 3.0
        w = feature_window(bad)
        with self.assertRaises(FeatureContractError):
            run_ml_inference(w, model)


class TestExpectedVsMLNeverTouchesProtocol(unittest.TestCase):
    def _mismatching_ml_result(self):
        # Model that only ever says 'video' -> expected 'voip' is a MISMATCH.
        model = build_demo_model()
        model = train_nearest_centroid(
            [("video", make_row(1500, i)) for i in range(6)],
            model_version="video-only",
            training_dataset="video-only-demo",
            estimate_confidence=True,
        )
        return model

    def test_ml_mismatch_does_not_change_protocol_result(self):
        engine = ComparisonEngine()
        baseline = run_engine_without_ml(engine)
        model = self._mismatching_ml_result()
        result = correlate_with_ml(
            engine, EXPECTED_VOIP, observed_basic(),
            identity=IDENTITY, observed_identity=IDENTITY,
            model=model, window=valid_window("voip"),
        )
        self.assertEqual(result.status, baseline.status)
        self.assertEqual(result.matches, baseline.matches)
        self.assertEqual(result.mismatches, baseline.mismatches)
        self.assertEqual(result.unknowns, baseline.unknowns)
        self.assertEqual(result.not_applicable, baseline.not_applicable)

    def test_ml_mismatch_recorded_only_in_ml_comparisons(self):
        engine = ComparisonEngine()
        model = self._mismatching_ml_result()
        result = correlate_with_ml(
            engine, EXPECTED_VOIP, observed_basic(),
            identity=IDENTITY, observed_identity=IDENTITY,
            model=model, window=valid_window("voip"),
        )
        comparison = result.metadata["ml"]["comparisons"][0]
        self.assertEqual(comparison["variable"], "ML_TRAFFIC_CLASSIFICATION")
        self.assertEqual(comparison["status"], CORRELATION_STATUS_MISMATCH)
        self.assertIs(comparison["is_authoritative_observation"], False)
        # every result-level list is still free of ML variables
        for list_name in ("matches", "mismatches", "unknowns", "not_applicable"):
            variables = {item.get("variable") for item in getattr(result, list_name)}
            self.assertNotIn("ML_TRAFFIC_CLASSIFICATION", variables)
            self.assertNotIn("ML_ANOMALY", variables)

    def test_ml_output_never_becomes_a_risk_conclusion(self):
        model = self._mismatching_ml_result()
        engine = ComparisonEngine()
        result = correlate_with_ml(
            engine, EXPECTED_VOIP, observed_basic(),
            identity=IDENTITY, observed_identity=IDENTITY,
            model=model, window=valid_window("voip"),
        )
        blob = encode(result.to_dict()).lower()
        # "risk" may legitimately appear in DISCLAIMER prose; it must never be a
        # key or a severity label carrying a conclusion.
        self.assertNotIn('"risk":', blob)
        self.assertNotIn('"severity"', blob)
        self.assertNotIn('"high"', blob)

    def test_ml_match_recorded_as_match(self):
        engine = ComparisonEngine()
        model = build_demo_model()  # classifies voip window as voip
        result = correlate_with_ml(
            engine, EXPECTED_VOIP, observed_basic(),
            identity=IDENTITY, observed_identity=IDENTITY,
            model=model, window=valid_window("voip"),
        )
        comparison = result.metadata["ml"]["comparisons"][0]
        self.assertEqual(comparison["status"], CORRELATION_STATUS_MATCH)


class TestMLEvaluatedFlagAndPrecomputedResult(unittest.TestCase):
    def test_ml_evaluated_false_without_any_ml_input(self):
        engine = ComparisonEngine()
        result = correlate_with_ml(
            engine, EXPECTED_VOIP, observed_basic(),
            identity=IDENTITY, observed_identity=IDENTITY,
        )
        self.assertFalse(result.metadata["ml_evaluated"])

    def test_ml_evaluated_true_with_window_and_model(self):
        engine = ComparisonEngine()
        result = correlate_with_ml(
            engine, EXPECTED_VOIP, observed_basic(),
            identity=IDENTITY, observed_identity=IDENTITY,
            model=build_demo_model(), window=valid_window("voip"),
        )
        self.assertTrue(result.metadata["ml_evaluated"])

    def test_precomputed_ml_result_accepted(self):
        engine = ComparisonEngine()
        ml = MLResult(
            model_version="external-1",
            traffic_class="voip",
            classification_confidence=0.9,
        )
        result = correlate_with_ml(
            engine, EXPECTED_VOIP, observed_basic(),
            identity=IDENTITY, observed_identity=IDENTITY,
            ml_result=ml,
        )
        self.assertTrue(result.metadata["ml"]["model_available"])
        self.assertEqual(
            result.metadata["ml"]["ml_result"]["model_version"], "external-1"
        )

    def test_model_without_window_rejected(self):
        engine = ComparisonEngine()
        with self.assertRaises(Exception):
            correlate_with_ml(
                engine, EXPECTED_VOIP, observed_basic(),
                identity=IDENTITY, observed_identity=IDENTITY,
                model=build_demo_model(),
            )


class TestSerialization(unittest.TestCase):
    def test_result_with_ml_is_json_serializable(self):
        engine = ComparisonEngine()
        result = correlate_with_ml(
            engine, EXPECTED_VOIP, observed_basic(),
            identity=IDENTITY, observed_identity=IDENTITY,
            model=build_demo_model(), window=valid_window("voip"),
        )
        payload = encode(result.to_dict())
        self.assertIn('"ml"', payload)
        json.loads(payload)  # must not raise

    def test_deterministic_serialization_across_runs(self):
        engine = ComparisonEngine()
        a = correlate_with_ml(
            engine, EXPECTED_VOIP, observed_basic(),
            identity=IDENTITY, observed_identity=IDENTITY,
            model=build_demo_model(), window=valid_window("voip"),
        )
        b = correlate_with_ml(
            ComparisonEngine(), EXPECTED_VOIP, observed_basic(),
            identity=IDENTITY, observed_identity=IDENTITY,
            model=build_demo_model(), window=valid_window("voip"),
        )
        self.assertEqual(encode(a.to_dict()), encode(b.to_dict()))


class TestRealV2Path(unittest.TestCase):
    def test_authoritative_crosscheck_when_sihipsec_present(self):
        if not os.path.isdir(SIHIPSEC_ROOT):
            self.skipTest("D:\\sihipsec not present")
        report = verify_authoritative_contract(SIHIPSEC_ROOT)
        self.assertTrue(report["snapshot_matches_authoritative"])

    def test_all_zero_live_snapshot_shape_is_schema_complete(self):
        # LiveFeatureExtractor documents empty observations as an all-zero
        # schema-complete record; it MUST satisfy the contract.
        features = {
            name: (0 if name in set(
                "packet_count total_bytes min_packet_size max_packet_size "
                "unique_packet_size_count outbound_packet_count "
                "inbound_packet_count outbound_bytes inbound_bytes burst_count "
                "burst_count_10ms burst_count_50ms burst_count_200ms "
                "ike_packet_count ike_datagram_bytes ike_min_packet_size "
                "ike_max_packet_size".split()
            ) else 0.0)
            for name in FEATURE_COLUMNS
        }
        validate_feature_values(features)
        validate_feature_window(feature_window(features))

    def test_real_extractor_records_satisfy_contract_and_classify(self):
        features_module_path = os.path.join(SIHIPSEC_ROOT, "controller", "features.py")
        if not os.path.isfile(features_module_path):
            self.skipTest("D:\\sihipsec controller/features.py not present")
        spec = importlib.util.spec_from_file_location(
            "sihipsec_controller_features", features_module_path
        )
        module = importlib.util.module_from_spec(spec)
        try:
            spec.loader.exec_module(module)
        except Exception as exc:
            self.skipTest(f"authoritative extractor not importable: {exc}")

        empty = module.summarize_capture([], [], capture_ip=None, nominal_duration=None)
        self.assertEqual(len(empty), 59)
        normalized_empty = normalize_feature_values(empty)
        populate = module.summarize_capture(
            [
                (0.0, 40, 26, "192.168.100.1", "10.0.0.1"),
                (0.05, 40, 26, "10.0.0.1", "192.168.100.1"),
                (0.1, 40, 26, "192.168.100.1", "10.0.0.1"),
            ],
            [80, 92, 88],
            capture_ip="192.168.100.1",
            nominal_duration=30.0,
        )
        normalized = normalize_feature_values(populate)
        model = train_nearest_centroid(
            [("icmp", normalized_empty), ("web", normalized)],
            model_version="v0-real-path",
            training_dataset="D:/sihipsec controller/features.py (in-vivo)",
            estimate_confidence=False,
        )
        w = feature_window(normalized)
        result = run_ml_inference(w, model)
        self.assertIn(result.traffic_class, ALLOWED_TRAFFIC_PROFILES)
        self.assertIsNone(result.classification_confidence)


if __name__ == "__main__":
    unittest.main()