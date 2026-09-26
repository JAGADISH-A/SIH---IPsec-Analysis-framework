"""Production controller -> correlation integration seam tests.

Every test here drives :mod:`correlation.ml.live_correlation`, the production
entry point, and asserts the authority boundaries the architecture requires:

* the committed Random Forest is really exercised, across all six canonical
  traffic classes, with probabilities, model version, feature-schema version,
  window id and timestamp provenance intact;
* real observed IPsec state comes from the real state engine, and the
  ``IPsecStateBuilder`` -> ``ObservedState`` translation is lossless;
* expected state is materialized from the plan only, and neither ML nor risk nor
  XAI output mutates expected or observed state;
* protocol comparison outcomes are byte-identical with and without ML, with ML
  attached only as source-labelled metadata (``source="ml"``,
  ``is_authoritative_observation=false``);
* anomaly stays ``None`` / ``NOT_APPLICABLE``;
* SHAP stays observational (the seam never imports it and never changes a
  prediction because of it);
* the seam is reachable from a non-test production path (``python -m``), not
  only from this test module;
* the whole path stays passive: no enforcement, no execution plane.
"""

from __future__ import annotations

import copy
import json
import os
import subprocess
import sys
import unittest
from pathlib import Path

from correlation.adapters import ExpectedStateAdapter
from correlation.comparison import ComparisonEngine, ComparisonEngineOptions
from correlation.models import (
    CorrelationIdentity,
    LiveFeatureWindow,
    MLResult,
    ObservedState,
)
from correlation.ml import live_correlation as seam
from correlation.ml.controller_bridge import (
    CANONICAL_TRAFFIC_PROFILES,
    infer_controller_ml_result,
)
from correlation.ml.integration import correlate_with_ml
from correlation.risk import RiskEngine, RiskPolicy
from correlation.risk.models import SEVERITIES
from correlation.xai import ExplainabilityEngine

REPO_ROOT = Path(__file__).resolve().parents[1]

PLAN_PATH = "results/datasets/acc-eng-02/staging/plan.json"
RUN_ID = "acc-eng-02"
EXPERIMENT_ID = "acc-eng-02-exp-0001"
LIVE_EVENTS = "results/observed-state/live_events_full.jsonl"
MODEL_PATH = "results/ml/model_traffic_rf_v1.joblib"

WIN_START = 1_790_185_065_700_000_000
WIN_END = 1_790_185_065_800_000_000


def _artifact(name):
    path = REPO_ROOT / name
    if not path.exists():
        raise unittest.SkipTest(f"required artifact missing: {name}")
    return path


def _materialized():
    return ExpectedStateAdapter(
        materialized_at=seam.DEFAULT_MATERIALIZED_AT
    ).from_plan(
        _artifact(PLAN_PATH),
        sequence=1,
        experiment_id=EXPERIMENT_ID,
        attempt_number=1,
        run_id=RUN_ID,
    )


def _observed():
    return seam.observed_state_from_events(
        seam.read_event_jsonl(str(_artifact(LIVE_EVENTS))),
        endpoints={"a": "192.168.100.1", "b": "192.168.100.2"},
    )


def _busiest_window():
    events = seam.read_event_jsonl(str(_artifact(LIVE_EVENTS)))
    return max(
        seam.feature_windows_from_events(events),
        key=lambda w: w.features.get("total_bytes", 0),
    )


class TestObservedStateIsReal(unittest.TestCase):
    """Observed IPsec state must come from real observation, not from ML."""

    def test_state_is_built_from_real_observation_events(self):
        observed = _observed()

        self.assertTrue(observed.tunnel_seen)
        self.assertTrue(observed.esp_seen)
        self.assertEqual(93, observed.packets_seen)
        self.assertEqual(14098, observed.bytes_seen)
        self.assertEqual(4, len(observed.spis))

    def test_spi_state_is_observed_not_inferred(self):
        observed = _observed()

        for spi_state in observed.spis:
            self.assertTrue(spi_state.spi.startswith("0x"))
            self.assertIsInstance(spi_state.sequence_delta, int)
            self.assertGreaterEqual(spi_state.sequence_delta, 0)
            self.assertGreaterEqual(spi_state.packet_count, 1)

    def test_transition_translation_is_lossless(self):
        """The builder's ``type``/flat payload survives as name/``details``."""
        from ebpf.ipsec_state_builder import IPsecStateBuilder

        events = seam.read_event_jsonl(str(_artifact(LIVE_EVENTS)))
        builder = IPsecStateBuilder(
            endpoints={"a": "192.168.100.1", "b": "192.168.100.2"}
        )
        for event in events:
            builder.consume_event_dict(event)
        raw = builder.snapshot()

        observed = seam.observed_state_from_events(
            events, endpoints={"a": "192.168.100.1", "b": "192.168.100.2"}
        )

        self.assertEqual(len(raw["transitions"]), len(observed.transitions))
        for source, translated in zip(raw["transitions"], observed.transitions):
            self.assertEqual(source["type"], translated.name)
            self.assertEqual(source["timestamp_ns"], translated.timestamp_ns)
            for key, value in source.items():
                if key in ("type", "timestamp_ns"):
                    continue
                self.assertIn(key, translated.details)
                self.assertEqual(value, translated.details[key])

    def test_empty_event_stream_is_refused(self):
        with self.assertRaises(ValueError):
            seam.observed_state_from_events([])

    def test_crypto_parameters_are_never_fabricated(self):
        """A passive observer cannot evidence cipher/integrity/DH/PFS."""
        values = seam.observed_values_from_state(_observed())

        self.assertEqual({"mode"}, set(values))
        self.assertEqual("tunnel", values["mode"])
        for forbidden in (
            "ike.version", "ike.encryption", "ike.integrity", "ike.dh_group",
            "esp.encryption", "esp.integrity", "esp.dh_group", "esp.pfs",
        ):
            self.assertNotIn(forbidden, values)

    def test_transport_mode_is_derived_from_observation(self):
        """Cleartext-only traffic must report transport, not tunnel.

        ``IPsecStateBuilder`` sets ``tunnel_seen`` for *any* observed traffic,
        so the seam must key ``mode`` off the encapsulating protocols instead.
        """
        from ebpf.ipsec_state_builder import IPsecStateBuilder

        builder = IPsecStateBuilder(endpoints={"a": "10.0.0.1", "b": "10.0.0.2"})
        builder.consume_event_dict(
            {"ts": 1_000, "type": "OTHER", "src": "10.0.0.1",
             "dst": "10.0.0.2", "len": 100}
        )
        observed = ObservedState.from_dict(
            seam.state_snapshot_to_dict(builder.snapshot())
        )

        self.assertTrue(observed.tunnel_seen)
        self.assertFalse(observed.esp_seen)
        self.assertFalse(observed.ah_seen)
        self.assertEqual("transport", seam.observed_values_from_state(observed)["mode"])

    def test_tunnel_mode_requires_an_encapsulating_protocol(self):
        self.assertTrue(_observed().esp_seen)
        self.assertEqual("tunnel", seam.observed_values_from_state(_observed())["mode"])


class TestRealRandomForestIsExercised(unittest.TestCase):
    """The committed RF artifact must really run, on all six canonical classes."""

    @classmethod
    def setUpClass(cls):
        cls.artifact = seam.load_rf_artifact()
        cls.window = _busiest_window()
        cls.result = infer_controller_ml_result(
            cls.window,
            artifact=cls.artifact,
            timestamp=seam.window_timestamp(cls.window),
        )

    def test_committed_artifact_is_used(self):
        self.assertTrue((REPO_ROOT / MODEL_PATH).exists())
        self.assertIn("estimator", self.artifact)
        self.assertEqual("v2", self.artifact["feature_schema_version"])
        self.assertEqual(
            set(CANONICAL_TRAFFIC_PROFILES), set(self.artifact["target_classes"])
        )
        self.assertEqual(57, len(self.artifact["feature_names"]))
        for name in self.artifact["feature_names"]:
            self.assertIn(name, self.window.features)

    def test_model_and_schema_version_provenance(self):
        self.assertEqual("traffic_rf_v1", self.result.model_version)
        self.assertEqual(
            "traffic_rf_v1", self.result.extras["model_version"]
        )
        self.assertEqual("v2", self.result.extras["feature_schema_version"])
        self.assertEqual("v2", self.window.feature_schema_version)
        self.assertEqual("ml", self.result.extras["source"])

    def test_window_and_timestamp_provenance(self):
        self.assertEqual(
            f"{self.window.window_start_ns}-{self.window.window_end_ns}",
            self.result.extras["window_id"],
        )
        self.assertEqual(
            seam.window_timestamp(self.window), self.result.extras["timestamp"]
        )

    def test_all_six_probabilities_are_reported_and_normalized(self):
        probabilities = self.result.extras["probabilities"]

        self.assertEqual(
            set(CANONICAL_TRAFFIC_PROFILES), set(probabilities)
        )
        self.assertEqual(6, len(probabilities))
        for value in probabilities.values():
            self.assertGreaterEqual(value, 0.0)
            self.assertLessEqual(value, 1.0)
        self.assertAlmostEqual(1.0, sum(probabilities.values()), places=5)

    def test_traffic_class_is_canonical_and_matches_its_confidence(self):
        self.assertIn(self.result.traffic_class, CANONICAL_TRAFFIC_PROFILES)
        self.assertAlmostEqual(
            self.result.extras["probabilities"][self.result.traffic_class],
            self.result.classification_confidence,
            places=6,
        )
        self.assertEqual(
            self.result.traffic_class, self.result.extras["traffic_profile"]
        )


class TestAllSixClassesRemainCanonical(unittest.TestCase):
    """Every canonical class the RF can emit must still be one of the six."""

    @classmethod
    def setUpClass(cls):
        try:
            from controller.dataset_loader import (
                DEFAULT_DATASETS_DIR,
                PROTECTED_DATASET_RUN_IDS,
            )

            present = all(
                (DEFAULT_DATASETS_DIR / run / "features.parquet").exists()
                for run in PROTECTED_DATASET_RUN_IDS
            )
        except Exception:  # pragma: no cover - defensive
            present = False
        if not present:
            raise unittest.SkipTest("protected dataset features.parquet absent")
        import pyarrow.parquet as pq

        from controller.dataset_artifacts import FEATURE_COLUMNS, INT_FEATURES
        from controller.dataset_loader import (
            DEFAULT_DATASETS_DIR,
            PROTECTED_DATASET_RUN_IDS,
        )

        cls.windows = []
        for run in PROTECTED_DATASET_RUN_IDS:
            data = pq.read_table(
                str(DEFAULT_DATASETS_DIR / run / "features.parquet")
            ).to_pydict()
            for i in range(len(data["traffic_profile"])):
                features = {
                    column: (
                        int(data[column][i])
                        if column in INT_FEATURES
                        else float(data[column][i])
                    )
                    for column in FEATURE_COLUMNS
                }
                cls.windows.append(
                    LiveFeatureWindow(
                        feature_schema_version="v2",
                        window_start_ns=WIN_START,
                        window_end_ns=WIN_END,
                        features=features,
                    )
                )
        cls.artifact = seam.load_rf_artifact()
        cls.results = [
            infer_controller_ml_result(
                window, artifact=cls.artifact, timestamp="2026-09-24T00:00:00Z"
            )
            for window in cls.windows
        ]

    def test_every_prediction_is_one_of_the_six_classes(self):
        self.assertGreater(len(self.results), 0)
        for result in self.results:
            self.assertIn(result.traffic_class, CANONICAL_TRAFFIC_PROFILES)
            self.assertEqual(
                set(CANONICAL_TRAFFIC_PROFILES),
                set(result.extras["probabilities"]),
            )

    def test_the_six_classes_are_all_reachable(self):
        emitted = {result.traffic_class for result in self.results}

        self.assertEqual(set(CANONICAL_TRAFFIC_PROFILES), emitted)

    def test_predictions_are_deterministic(self):
        repeat = infer_controller_ml_result(
            self.windows[0], artifact=self.artifact, timestamp="2026-09-24T00:00:00Z"
        )

        self.assertEqual(self.results[0].traffic_class, repeat.traffic_class)
        self.assertEqual(
            self.results[0].extras["probabilities"],
            repeat.extras["probabilities"],
        )


class TestMlIsNeverAuthoritative(unittest.TestCase):
    """ML is evidence. It never becomes observed state or a security verdict."""

    @classmethod
    def setUpClass(cls):
        cls.materialized = _materialized()
        cls.expected = cls.materialized.expected
        cls.observed = _observed()
        cls.window = _busiest_window()
        cls.window_identity = CorrelationIdentity(
            dataset_run_id=RUN_ID,
            sequence=1,
            experiment_id=EXPERIMENT_ID,
            attempt_number=1,
            window_index=0,
            window_start_ns=cls.window.window_start_ns,
            window_end_ns=cls.window.window_end_ns,
        )

    def _seam_result(self):
        return seam.correlate_live_window(
            expected=self.materialized,
            observed=self.observed,
            window=self.window,
            identity=self.materialized.identity,
            observed_identity=self.window_identity,
            artifact=seam.load_rf_artifact(),
        )

    def test_expected_state_is_never_mutated(self):
        before = self.expected.to_dict()

        self._seam_result()

        self.assertEqual(before, self.expected.to_dict())

    def test_observed_state_is_never_mutated(self):
        before = self.observed.to_dict()

        self._seam_result()

        self.assertEqual(before, self.observed.to_dict())

    def test_ml_does_not_change_protocol_comparison(self):
        engine = ComparisonEngine(ComparisonEngineOptions())
        without = engine.compare(
            self.expected,
            self.observed,
            identity=self.materialized.identity,
            observed_identity=self.window_identity,
            observed_values=seam.observed_values_from_state(self.observed),
        )
        ml_result = infer_controller_ml_result(
            self.window, artifact=seam.load_rf_artifact()
        )
        with_ml = correlate_with_ml(
            engine,
            self.expected,
            self.observed,
            identity=self.materialized.identity,
            observed_identity=self.window_identity,
            ml_result=ml_result,
            observed_values=seam.observed_values_from_state(self.observed),
        )

        self.assertEqual(without.status, with_ml.status)
        self.assertEqual(without.matches, with_ml.matches)
        self.assertEqual(without.mismatches, with_ml.mismatches)
        self.assertEqual(without.unknowns, with_ml.unknowns)
        self.assertEqual(without.not_applicable, with_ml.not_applicable)
        self.assertEqual(without.metadata["rules_executed"], with_ml.metadata["rules_executed"])

    def test_ml_outcomes_are_attached_as_labelled_evidence(self):
        result = self._seam_result()
        comparisons = result.correlation.metadata["ml"]["comparisons"]

        self.assertTrue(result.correlation.metadata["ml_evaluated"])
        for comparison in comparisons:
            self.assertEqual("ml", comparison["source"])
        classification = next(
            c for c in comparisons if c["variable"] == "ML_TRAFFIC_CLASSIFICATION"
        )
        self.assertFalse(classification["is_authoritative_observation"])

    def test_anomaly_stays_deferred(self):
        result = self._seam_result()
        comparisons = result.correlation.metadata["ml"]["comparisons"]
        anomaly = next(c for c in comparisons if c["variable"] == "ML_ANOMALY")

        self.assertIsNone(result.ml_result.anomaly)
        self.assertIsNone(result.ml_result.anomaly_score)
        self.assertEqual("NOT_APPLICABLE", anomaly["status"])
        self.assertFalse(anomaly["observation_recorded"])
        self.assertIsNone(anomaly["anomaly"])

    def test_risk_semantics_come_from_the_existing_engine(self):
        result = self._seam_result()
        expected = RiskEngine(RiskPolicy.default()).assess(
            expected=self.materialized,
            observed=self.observed,
            correlation=result.correlation,
            ml_result=result.ml_result,
        )

        self.assertEqual(expected.to_dict(), result.assessment.to_dict())
        self.assertEqual(
            expected.risk_engine_version, result.assessment.risk_engine_version
        )
        self.assertEqual(
            expected.risk_policy_version, result.assessment.risk_policy_version
        )
        self.assertIn(result.assessment.severity, SEVERITIES)

    def test_explanation_comes_from_the_existing_xai_engine(self):
        result = self._seam_result()
        explanation = result.explanation

        self.assertEqual(
            "v1", explanation.metadata["explainability_engine_version"]
        )
        self.assertTrue(explanation.metadata["deterministic"])
        self.assertTrue(explanation.summary)
        self.assertEqual(
            1, len(explanation.ml_explanations)
        )

    def test_explanation_declares_everything_read_only(self):
        """XAI must not become a decision input or a recomputation of risk."""
        result = self._seam_result()
        authority = result.explanation.metadata["authority"]

        self.assertTrue(authority["ml_read_only"])
        self.assertTrue(authority["correlation_read_only"])
        self.assertTrue(authority["findings_read_only"])
        self.assertTrue(authority["score_unchanged"])
        self.assertTrue(authority["severity_unchanged"])

    def test_explanation_states_ml_is_not_an_authoritative_observation(self):
        result = self._seam_result()

        self.assertTrue(result.explanation.ml_explanations)
        for entry in result.explanation.ml_explanations:
            self.assertIn(
                "does not represent an authoritative", entry.explanation
            )
            self.assertEqual(result.ml_result.traffic_class, entry.traffic_class)
            self.assertEqual(
                result.ml_result.classification_confidence,
                entry.classification_confidence,
            )
            self.assertIsNone(entry.anomaly)
            self.assertIsNone(entry.anomaly_score)

    def test_explanation_never_proposes_enforcement(self):
        result = self._seam_result()
        blob = json.dumps(result.explanation.to_dict(), default=str).lower()

        for forbidden in ("enforce", "block", "drop", "terminate"):
            self.assertNotIn(forbidden, blob)


class TestShapStaysObservational(unittest.TestCase):
    """The seam never imports SHAP and never lets it change a prediction."""

    def test_seam_never_imports_or_calls_shap(self):
        """The controller SHAP path is never reached from the seam.

        ``ExplainabilityEngine.explain`` is a *different* function and is the
        required XAI step, so only the controller's SHAP entry point and the
        ``shap`` package itself are forbidden here.
        """
        import ast

        tree = ast.parse(
            (REPO_ROOT / "correlation/ml/live_correlation.py").read_text()
        )
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    self.assertNotEqual("shap", alias.name.split(".")[0])
            elif isinstance(node, ast.ImportFrom):
                module = node.module or ""
                root = module.split(".")[0]
                self.assertNotEqual("shap", root)
                imported = {alias.name for alias in node.names}
                if "controller.ml_inference" in module:
                    self.assertNotIn("explain", imported)
            elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                owner = node.func.value
                owner_name = getattr(owner, "attr", None)
                if owner_name in ("ml_inference", "controller"):
                    self.assertNotEqual("explain", node.func.attr)

    def test_importing_the_seam_does_not_pull_in_the_ml_stack(self):
        probe = (
            "import sys;"
            "import correlation.ml.live_correlation;"
            "leaked=[m for m in ('shap','sklearn','matplotlib') if m in sys.modules];"
            "print(leaked)"
        )
        completed = subprocess.run(
            [sys.executable, "-c", probe],
            cwd=REPO_ROOT, capture_output=True, text=True, check=True,
        )

        self.assertEqual("[]", completed.stdout.strip())

    def test_prediction_is_identical_with_and_without_explain(self):
        window = _busiest_window()
        artifact = seam.load_rf_artifact()
        plain = infer_controller_ml_result(
            window, artifact=artifact, timestamp="2026-09-24T00:00:00Z"
        )

        try:
            from controller import ml_inference

            record = {
                "feature_schema_version": "v2",
                "window_start_ns": window.window_start_ns,
                "window_end_ns": window.window_end_ns,
                "features": dict(window.features),
            }
            explained = ml_inference.explain(record, artifact=artifact)
        except Exception as exc:  # pragma: no cover - shap optional
            self.skipTest(f"SHAP explanation unavailable: {exc}")

        self.assertEqual(plain.traffic_class, explained["traffic_profile"])
        self.assertTrue(explained["non_interference"]["predictions_equal"])
        self.assertTrue(explained["non_interference"]["probabilities_equal"])
        self.assertEqual(
            f"{window.window_start_ns}-{window.window_end_ns}",
            explained["window_id"],
        )


class TestExpectedStateStaysIndependent(unittest.TestCase):
    """Expected state is sourced from the plan, never from ML or observed data."""

    def test_expected_state_is_materialized_from_the_plan(self):
        materialized = _materialized()

        self.assertEqual(RUN_ID, materialized.identity.dataset_run_id)
        self.assertEqual(EXPERIMENT_ID, materialized.identity.experiment_id)
        self.assertEqual("tunnel", materialized.expected.mode)

    def test_run_requires_an_expected_state_or_a_plan(self):
        with self.assertRaises(ValueError):
            seam.correlate_live_events(
                seam.read_event_jsonl(str(_artifact(LIVE_EVENTS)))
            )

    def test_run_exposes_the_plan_as_its_expected_source(self):
        run = seam.correlate_live_events(
            seam.read_event_jsonl(str(_artifact(LIVE_EVENTS))),
            plan_path=str(_artifact(PLAN_PATH)),
            sequence=1,
            experiment_id=EXPERIMENT_ID,
            attempt_number=1,
            run_id=RUN_ID,
            endpoints={"a": "192.168.100.1", "b": "192.168.100.2"},
        )

        self.assertEqual("materialized_plan", run.to_dict()["expected_source"])
        self.assertGreater(len(run.results), 0)
        self.assertEqual(93, run.observed.packets_seen)
        for result in run.results:
            self.assertEqual(run.observed.to_dict(), result.observed.to_dict())
            self.assertEqual(
                f"{result.window.window_start_ns}-{result.window.window_end_ns}",
                result.ml_result.extras["window_id"],
            )

    def test_window_identity_enables_per_window_identity_safety(self):
        """``observed_identity`` is verified against expected for every window.

        The engine does not store the observed identity; it consumes it in
        ``assert_identity_compatible`` before comparing anything.  Passing a
        window-stamped identity per window is therefore what makes each
        window's comparison identity-safe.
        """
        from correlation.comparison.engine import assert_identity_compatible

        run = seam.correlate_live_events(
            seam.read_event_jsonl(str(_artifact(LIVE_EVENTS))),
            plan_path=str(_artifact(PLAN_PATH)),
            sequence=1,
            experiment_id=EXPERIMENT_ID,
            attempt_number=1,
            run_id=RUN_ID,
            endpoints={"a": "192.168.100.1", "b": "192.168.100.2"},
        )

        self.assertGreater(len(run.results), 1)
        for index, result in enumerate(run.results):
            window_identity = CorrelationIdentity(
                dataset_run_id=RUN_ID,
                sequence=1,
                experiment_id=EXPERIMENT_ID,
                attempt_number=1,
                window_index=index,
                window_start_ns=result.window.window_start_ns,
                window_end_ns=result.window.window_end_ns,
            )
            assert_identity_compatible(run.identity, window_identity)
            self.assertEqual(
                f"{result.window.window_start_ns}-{result.window.window_end_ns}",
                result.ml_result.extras["window_id"],
            )


class TestProductionPathIsReal(unittest.TestCase):
    """The seam must be reachable from a non-test production path."""

    def test_module_is_not_test_only(self):
        source = (REPO_ROOT / "correlation/ml/live_correlation.py").read_text()

        self.assertIn('if __name__ == "__main__":', source)
        self.assertIn("def main(", source)
        self.assertNotIn("test-only", source)
        self.assertNotIn("TEST ONLY", source)

    def test_cli_help_runs_as_a_module(self):
        completed = subprocess.run(
            [sys.executable, "-m", "correlation.ml.live_correlation", "--help"],
            cwd=REPO_ROOT, capture_output=True, text=True,
        )

        self.assertEqual(0, completed.returncode, completed.stderr)
        self.assertIn("--events", completed.stdout)
        self.assertIn("--plan", completed.stdout)

    def test_cli_produces_a_correlated_result(self):
        events = str(_artifact(LIVE_EVENTS))
        plan = str(_artifact(PLAN_PATH))
        with tempfile_output() as out:
            completed = subprocess.run(
                [
                    sys.executable, "-m", "correlation.ml.live_correlation",
                    "--events", events,
                    "--plan", plan,
                    "--sequence", "1",
                    "--run-id", RUN_ID,
                    "--experiment-id", EXPERIMENT_ID,
                    "--attempt-number", "1",
                    "--endpoints", "a=192.168.100.1,b=192.168.100.2",
                    "--output", out,
                ],
                cwd=REPO_ROOT, capture_output=True, text=True,
            )
            self.assertEqual(0, completed.returncode, completed.stderr)
            payload = json.loads(Path(out).read_text(encoding="utf-8"))

        self.assertTrue(payload["passive_only"])
        self.assertEqual("materialized_plan", payload["expected_source"])
        self.assertGreater(payload["window_count"], 0)
        first = payload["windows"][0]
        self.assertIn("ml_result", first)
        self.assertIn("correlation", first)
        self.assertIn("assessment", first)
        self.assertIn("explanation", first)
        self.assertIn(first["ml_result"]["traffic_class"], CANONICAL_TRAFFIC_PROFILES)
        self.assertIsNone(first["ml_result"]["anomaly"])


class TestPassiveArchitectureIsPreserved(unittest.TestCase):
    """The seam connects observation to reporting. It enforces nothing."""

    def _module(self):
        import ast

        return ast.parse(
            (REPO_ROOT / "correlation/ml/live_correlation.py").read_text()
        )

    def test_seam_imports_no_enforcement_or_execution_module(self):
        import ast

        imported = set()
        for node in ast.walk(self._module()):
            if isinstance(node, ast.Import):
                imported.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
                imported.add(node.module.split(".")[0])

        self.assertTrue(imported)
        for forbidden in (
            "nftables", "iptables", "shap", "kafka", "matplotlib", "ctypes",
        ):
            self.assertNotIn(forbidden, imported)

    def test_seam_imports_no_execution_plane(self):
        import ast

        names = {
            node.id
            for node in ast.walk(self._module())
            if isinstance(node, ast.Name)
        } | {
            node.attr
            for node in ast.walk(self._module())
            if isinstance(node, ast.Attribute)
        }

        self.assertNotIn("ExecutionControlPlane", names)
        self.assertNotIn("respond_to_threat", names)

    def test_seam_code_uses_no_xdp_action(self):
        """XDP action constants belong to the sensor, never to this seam."""
        import ast

        actions = set()
        for node in ast.walk(self._module()):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                actions.add(node.value)

        for action in ("XDP_DROP", "XDP_TX", "XDP_REDIRECT", "XDP_ABORTED"):
            self.assertNotIn(action, actions)

    def test_result_payload_is_marked_passive_only(self):
        run = seam.correlate_live_events(
            seam.read_event_jsonl(str(_artifact(LIVE_EVENTS))),
            plan_path=str(_artifact(PLAN_PATH)),
            sequence=1,
            experiment_id=EXPERIMENT_ID,
            attempt_number=1,
            run_id=RUN_ID,
        )

        self.assertTrue(run.to_dict()["passive_only"])


def tempfile_output():
    import contextlib
    import tempfile

    @contextlib.contextmanager
    def _cm():
        handle = tempfile.NamedTemporaryFile(suffix=".json", delete=False)
        handle.close()
        try:
            yield handle.name
        finally:
            os.unlink(handle.name)

    return _cm()


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
