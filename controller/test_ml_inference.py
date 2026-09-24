"""Tests for the live 100-ms window -> ML inference adapter.

Covers: strict 57-feature schema validation (count/names/order/duplicates,
NaN/inf/type rejection), the ML result contract (model version, schema
version, window identity, timestamp, six-class probabilities), determinism,
offline==live parity at the ML-vector boundary, SHAP non-interference, and
the CLI (per-100-ms window path and record path).
"""

import json
import math
import tempfile
import unittest
from pathlib import Path

import numpy as np

from controller import (
    features as features_mod,
    ml_inference as ml_inf,
    dataset_loader,
)
from controller.dataset_artifacts import FEATURE_COLUMNS
from controller.live_features import (
    iterate_capture_as_live_events,
    extract_record,
)

ROOT = Path(__file__).resolve().parent.parent
TESTDATA = Path(__file__).resolve().parent / "testdata"
FIXTURE = TESTDATA / "wan_side_esp_ike_sample.pcap"
GATEWAY_A = "192.168.100.1"
RUN_DIR = ROOT / "results" / "datasets" / "dataset-20260923-221430"


def fixture_record(nominal_duration=None) -> dict:
    return extract_record(
        iterate_capture_as_live_events(str(FIXTURE)),
        capture_ip=GATEWAY_A,
        nominal_duration=nominal_duration,
    )


def shuffle_dict(pairs):
    keys = [k for k, _ in pairs]
    order = sorted(range(len(keys)), key=lambda i: (keys[i], i), reverse=True)
    return {keys[i]: pairs[i][1] for i in order}


class TestFeatureOrderContract(unittest.TestCase):
    def test_feature_order_is_57_no_duplicates(self):
        order = ml_inf.feature_order()
        self.assertEqual(len(order), 57)
        self.assertEqual(len(set(order)), 57)

    def test_feature_order_matches_loader_and_artifact(self):
        order = ml_inf.feature_order()
        self.assertEqual(list(order), dataset_loader.feature_names())
        artifact = ml_inf.load_artifact()
        self.assertEqual(list(order), list(artifact["feature_names"]))

    def test_constants_are_removed_not_trained(self):
        order = set(ml_inf.feature_order())
        self.assertNotIn("burst_packet_ratio", order)
        self.assertNotIn("ike_packet_count", order)


class TestSchemaValidation(unittest.TestCase):
    def setUp(self):
        self.record = fixture_record()
        self.fiftyseven = dict(self.record["features"])
        del self.fiftyseven["burst_packet_ratio"]
        del self.fiftyseven["ike_packet_count"]
        self.assertEqual(len(self.fiftyseven), 57)

    def test_live_record_accepted(self):
        canonical, window_id = ml_inf._extract_input(self.record)
        self.assertEqual(len(canonical), 57)
        self.assertEqual(list(canonical), list(ml_inf.feature_order()))
        self.assertEqual(
            window_id,
            f"{self.record['window_start_ns']}-{self.record['window_end_ns']}",
        )

    def test_missing_feature_rejected(self):
        broken = dict(self.fiftyseven)
        del broken[next(iter(broken))]
        with self.assertRaisesRegex(ValueError, "expected exactly 57"):
            ml_inf._extract_input(broken)

    def test_extra_feature_rejected(self):
        broken = dict(self.fiftyseven)
        broken["totally_unknown"] = 1.0
        with self.assertRaisesRegex(ValueError, "expected exactly 57"):
            ml_inf._extract_input(broken)

    def test_unknown_name_rejected(self):
        broken = dict(self.fiftyseven)
        renamed = {k: v for k, v in broken.items()}
        renamed["flow_duration_renamed"] = renamed.pop("flow_duration")
        self.assertEqual(len(renamed), 57)
        with self.assertRaisesRegex(ValueError, "feature set mismatch"):
            ml_inf._extract_input(renamed)

    def test_wrong_count_rejected(self):
        with self.assertRaisesRegex(ValueError, "expected exactly 57"):
            ml_inf.validate_features(list(self.fiftyseven.items())[:56])

    def test_duplicate_names_rejected(self):
        pairs = list(self.fiftyseven.items())
        dup = (pairs[0][0], pairs[0][1])
        pairs = [dup, dup] + pairs[2:]
        self.assertEqual(len(pairs), 57)
        with self.assertRaisesRegex(ValueError, "duplicate feature names"):
            ml_inf.validate_features(pairs)

    def test_nan_rejected(self):
        broken = dict(self.fiftyseven)
        broken["packet_count"] = float("nan")
        with self.assertRaisesRegex(ValueError, "not a finite number"):
            ml_inf._extract_input(broken)

    def test_inf_rejected(self):
        broken = dict(self.fiftyseven)
        broken["packet_count"] = float("inf")
        with self.assertRaisesRegex(ValueError, "not a finite number"):
            ml_inf._extract_input(broken)

    def test_string_value_rejected(self):
        broken = dict(self.fiftyseven)
        broken["packet_count"] = "1500"
        with self.assertRaisesRegex(ValueError, "not a finite number"):
            ml_inf._extract_input(broken)

    def test_bool_value_rejected(self):
        broken = dict(self.fiftyseven)
        broken["packet_count"] = True
        with self.assertRaisesRegex(ValueError, "not a finite number"):
            ml_inf._extract_input(broken)

    def test_none_value_rejected(self):
        broken = dict(self.fiftyseven)
        broken["packet_count"] = None
        with self.assertRaisesRegex(ValueError, "not a finite number"):
            ml_inf._extract_input(broken)

    def test_wrong_container_rejected(self):
        with self.assertRaisesRegex(ValueError, "record must be a mapping"):
            ml_inf._extract_input("not a record")

    def test_wrong_schema_version_rejected(self):
        bad = dict(self.record)
        bad["feature_schema_version"] = "v1"
        with self.assertRaisesRegex(ValueError, "feature_schema_version"):
            ml_inf._extract_input(bad)

    def test_missing_features_field_rejected(self):
        with self.assertRaisesRegex(ValueError, "expected exactly 57"):
            ml_inf._extract_input({"feature_schema_version": "v2"})

    def test_order_independent_vector(self):
        canonical = ml_inf.validate_features(self.fiftyseven)
        shuffled = {k: v for k, v in reversed(list(canonical.items()))}
        self.assertTrue(
            np.array_equal(
                ml_inf.vectorize(shuffled), ml_inf.vectorize(self.fiftyseven)
            )
        )

    def test_constants_dropped_from_live_record_only(self):
        vector = ml_inf.vectorize(
            {k: v for k, v in self.record["features"].items()
             if k in ml_inf.feature_order()}
        )
        self.assertEqual(vector.shape, (1, 57))


class TestInferenceContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.record = fixture_record()
        cls.res = ml_inf.predict(cls.record, timestamp="2026-09-24T00:00:00+00:00")

    def test_result_identifies_model_and_schema(self):
        self.assertEqual(self.res["model_version"], ml_inf.MODEL_VERSION)
        self.assertEqual(self.res["feature_schema_version"], "v2")

    def test_result_retains_window_identity(self):
        self.assertEqual(
            self.res["window_id"],
            f"{self.record['window_start_ns']}-{self.record['window_end_ns']}",
        )

    def test_result_has_timestamp(self):
        self.assertIn("T", self.res["timestamp"])
        self.assertIn("+", self.res["timestamp"])

    def test_result_has_valid_class(self):
        self.assertIn(self.res["traffic_profile"], dataset_loader.TARGET_CLASSES)

    def test_probabilities_contract(self):
        probs = self.res["probabilities"]
        self.assertEqual(list(probs), list(dataset_loader.TARGET_CLASSES))
        self.assertTrue(all(isinstance(p, float) for p in probs.values()))
        self.assertAlmostEqual(sum(probs.values()), 1.0, places=9)
        self.assertGreaterEqual(probs[self.res["traffic_profile"]], 0.0)

    def test_matches_direct_estimator_prediction(self):
        artifact = ml_inf.load_artifact()
        vector = ml_inf.vectorize(
            {k: v for k, v in self.record["features"].items()
             if k in ml_inf.feature_order()}
        )
        proba = artifact["estimator"].predict_proba(vector)[0]
        self.assertTrue(
            np.allclose(list(self.res["probabilities"].values()), proba)
        )

    def test_deterministic(self):
        again = ml_inf.predict(self.record, timestamp="2026-09-24T00:00:00+00:00")
        self.assertEqual(again, self.res)

    def test_predict_many_batch_equals_sequential(self):
        records = [fixture_record(), fixture_record(nominal_duration=30.0)]
        batch = ml_inf.predict_many(
            records, timestamp="2026-09-24T00:00:00+00:00"
        )
        sequential = [
            ml_inf.predict(record, artifact=ml_inf.load_artifact(),
                           timestamp="2026-09-24T00:00:00+00:00")
            for record in records
        ]
        self.assertEqual(batch, sequential)
        self.assertEqual(len(batch), 2)
        self.assertEqual(
            batch[0]["window_id"],
            f"{records[0]['window_start_ns']}-{records[0]['window_end_ns']}",
        )
        self.assertAlmostEqual(sum(batch[0]["probabilities"].values()), 1.0)

    def test_predict_many_empty(self):
        self.assertEqual(ml_inf.predict_many([]), [])

    def test_empty_epoch_record_valid(self):
        record = {
            "feature_schema_version": "v2",
            "window_start_ns": 0,
            "window_end_ns": 0,
            "features": {k: 0.0 for k in FEATURE_COLUMNS},
        }
        res = ml_inf.predict(record)
        self.assertEqual(res["window_id"], "0-0")
        self.assertAlmostEqual(sum(res["probabilities"].values()), 1.0)


class TestOfflineLiveParityAtMlBoundary(unittest.TestCase):
    def test_fixture_vectors_identical(self):
        offline = features_mod.extract_features(str(FIXTURE), capture_ip=GATEWAY_A)
        live = fixture_record()
        off_vec = ml_inf.vectorize(
            {k: offline[k] for k in ml_inf.feature_order()}
        )
        live_vec = ml_inf.vectorize(
            {k: live["features"][k] for k in ml_inf.feature_order()}
        )
        self.assertTrue(np.array_equal(off_vec, live_vec))

    def test_fixture_vectors_identical_with_nominal_duration(self):
        offline = features_mod.extract_features(
            str(FIXTURE), capture_ip=GATEWAY_A, nominal_duration=30.0
        )
        live = fixture_record(nominal_duration=30.0)
        off_vec = ml_inf.vectorize(
            {k: offline[k] for k in ml_inf.feature_order()}
        )
        live_vec = ml_inf.vectorize(
            {k: live["features"][k] for k in ml_inf.feature_order()}
        )
        self.assertTrue(np.array_equal(off_vec, live_vec))

    def test_fixture_predictions_identical(self):
        offline = features_mod.extract_features(str(FIXTURE), capture_ip=GATEWAY_A)
        off_res = ml_inf.predict(
            {k: offline[k] for k in ml_inf.feature_order()},
            timestamp="2026-09-24T00:00:00+00:00",
        )
        live_res = ml_inf.predict(
            fixture_record(), timestamp="2026-09-24T00:00:00+00:00"
        )
        self.assertEqual(off_res["traffic_profile"], live_res["traffic_profile"])
        self.assertEqual(off_res["probabilities"], live_res["probabilities"])


class TestShapNonInterferenceAndContract(unittest.TestCase):
    def test_explain_is_observational(self):
        record = fixture_record()
        before = ml_inf.predict(record, timestamp="2026-09-24T00:00:00+00:00")
        explanation = ml_inf.explain(record)
        after = ml_inf.predict(record, timestamp="2026-09-24T00:00:00+00:00")
        self.assertEqual(after, before)
        self.assertTrue(explanation["non_interference"]["predictions_equal"])
        self.assertTrue(explanation["non_interference"]["probabilities_equal"])
        self.assertEqual(explanation["traffic_profile"], before["traffic_profile"])
        self.assertEqual(explanation["window_id"], before["window_id"])
        self.assertEqual(explanation["n_features"], 57)
        self.assertEqual(len(explanation["top_features"]), 10)
        self.assertEqual(
            set(explanation["shap_representation"]), {"type", "shape", "note"}
        )


class TestLiveWindowPath(unittest.TestCase):
    def test_events_are_grouped_into_100ms_windows(self):
        events = list(iterate_capture_as_live_events(str(FIXTURE)))
        window_ns = 100 * 1_000_000
        slots = sorted({int(e["ts"]) // window_ns for e in events})

        windows = list(
            ml_inf.iter_window_records(events, capture_ip=GATEWAY_A, window_ms=100)
        )
        self.assertEqual(len(windows), len(slots))
        for record in windows:
            self.assertEqual(record["feature_schema_version"], "v2")
            self.assertTrue(record["window_end_ns"] > record["window_start_ns"])


class TestCli(unittest.TestCase):
    def test_records_mode(self):
        with tempfile.TemporaryDirectory() as tmp:
            rec_path = Path(tmp) / "records.jsonl"
            out_path = Path(tmp) / "results.jsonl"
            rec_path.write_text(
                json.dumps(fixture_record(nominal_duration=30.0)) + "\n"
            )
            rc = ml_inf.main(["--records", str(rec_path), "--output", str(out_path)])
            self.assertEqual(rc, 0)
            lines = out_path.read_text().strip().splitlines()
            self.assertEqual(len(lines), 1)
            result = json.loads(lines[0])
            self.assertEqual(result["model_version"], ml_inf.MODEL_VERSION)
            self.assertEqual(result["feature_schema_version"], "v2")
            self.assertIn("window_id", result)
            self.assertIn("timestamp", result)
            self.assertIn(result["traffic_profile"], dataset_loader.TARGET_CLASSES)
            self.assertEqual(
                set(result["probabilities"]),
                set(dataset_loader.TARGET_CLASSES),
            )

    def test_events_mode_produces_per_window_results(self):
        with tempfile.TemporaryDirectory() as tmp:
            ev_path = Path(tmp) / "events.jsonl"
            out_path = Path(tmp) / "results.jsonl"
            with open(ev_path, "w") as fh:
                for event in iterate_capture_as_live_events(str(FIXTURE)):
                    fh.write(json.dumps(event) + "\n")
            rc = ml_inf.main(
                ["--events", str(ev_path), "--capture-ip", GATEWAY_A,
                 "--output", str(out_path)]
            )
            self.assertEqual(rc, 0)
            lines = out_path.read_text().strip().splitlines()
            self.assertGreaterEqual(len(lines), 1)
            for line in lines:
                result = json.loads(line)
                self.assertEqual(result["feature_schema_version"], "v2")
                self.assertNotEqual(result["window_id"], "unknown")

    def test_explain_flag_attaches_explanation(self):
        with tempfile.TemporaryDirectory() as tmp:
            rec_path = Path(tmp) / "records.jsonl"
            out_path = Path(tmp) / "results.jsonl"
            rec_path.write_text(
                json.dumps(fixture_record(nominal_duration=30.0)) + "\n"
            )
            ml_inf.main(["--records", str(rec_path), "--output", str(out_path),
                         "--explain"])
            result = json.loads(out_path.read_text().strip().splitlines()[0])
            self.assertIn("explanation", result)
            self.assertTrue(
                result["explanation"]["non_interference"]["predictions_equal"]
            )


if __name__ == "__main__":
    unittest.main()