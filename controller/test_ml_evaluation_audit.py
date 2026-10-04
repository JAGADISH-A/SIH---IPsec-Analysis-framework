"""Tests for the ML evaluation audit (:mod:`controller.ml_evaluation_audit`).

These tests are the reproducibility contract for the model's evaluation.  They
pin the data-integrity claims, the held-out metrics, the non-vacuity controls
and the robustness floor against the committed artifact and protected
datasets.

They are deliberately *non-vacuous*:

* every assertion is recomputed from the real artifact and the real 300-sample
  dataset, never read back out of a report the audit itself wrote;
* the metric-sensitivity tests assert a shuffled-label control lands near
  chance, so a metric that always returned 1.0 would fail;
* the integrity tests recompute group isolation and duplicate-row
  contamination from the split assignments, so a splitter that vouched for
  itself would not pass;
* metrics are recomputed from ``y_true``/``y_pred`` on known inputs, so a
  broken ``compute_metrics`` fails here.

Tests that need the trained artifact skip cleanly when it is absent, matching
``controller/test_ml_model.py``'s convention for a repo checked out without
``results/``.
"""

from __future__ import annotations

import json
import pathlib
import shutil
import tempfile
import unittest

import numpy as np

from controller import ml_evaluation_audit as audit_mod
from controller.dataset_loader import (
    PROTECTED_DATASET_RUN_IDS,
    TARGET_CLASSES,
    load_dataset,
)
from controller.evaluate_model import MODEL_PATH, compute_metrics

DATASETS_DIR = pathlib.Path("results") / "datasets"


def _has_artifact() -> bool:
    return (
        MODEL_PATH.is_file()
        and DATASETS_DIR.is_dir()
        and all(
            (DATASETS_DIR / run / "features.parquet").is_file()
            for run in PROTECTED_DATASET_RUN_IDS
        )
    )


#: ``build_audit`` fits the non-vacuity control forests, so it costs a few
#: seconds. Every audit test needs the identical result, so it is computed once
#: per process and shared. ``setUpClass`` only rebinds the class attributes,
#: so the work is never repeated per subclass.
_SHARED: dict = {}


def _shared_audit() -> tuple:
    if not _SHARED:
        ctx = audit_mod.EvaluationContext()
        _SHARED["ctx"] = ctx
        _SHARED["audit"] = audit_mod.build_audit(
            model_path=ctx.model_path, split_path=ctx.split_path
        )
    return _SHARED["ctx"], _SHARED["audit"]


@unittest.skipUnless(
    _has_artifact(),
    "trained artifact or protected datasets not present (results/ is untracked)",
)
class AuditFixture(unittest.TestCase):
    """Shared, computed-once audit context."""

    ctx: audit_mod.EvaluationContext
    audit: dict

    @classmethod
    def setUpClass(cls):
        cls.ctx, cls.audit = _shared_audit()


class SplitIntegrityTest(AuditFixture):
    """The split must actually be leak-free, not merely claim to be."""

    def test_no_configuration_spans_partitions(self):
        report = self.audit["split_integrity"]
        self.assertEqual(report["configs_spanning_partitions"], [])
        self.assertTrue(report["group_isolation_ok"])

    def test_splitters_self_report_is_cross_checked(self):
        # The audit must not simply echo the splitter's own verification block.
        recomputed = audit_mod.split_integrity_report(self.ctx)
        claimed = self.ctx.split.get("verification", {})
        self.assertEqual(
            recomputed["configs_spanning_partitions"], []
        )
        self.assertTrue(
            claimed.get("group_isolation_ok"),
            "splitter itself reports broken group isolation",
        )
        self.assertEqual(recomputed["verification_block_agrees"]["group_isolation_ok"], True)

    def test_no_duplicate_experiment_ids(self):
        self.assertEqual(
            self.audit["split_integrity"]["duplicate_experiment_ids"], []
        )

    def test_no_duplicate_feature_rows_across_partitions(self):
        pairs = self.audit["split_integrity"][
            "duplicate_feature_rows_between_partitions"
        ]
        self.assertEqual(set(pairs), {"train_x_test", "train_x_validation", "validation_x_test"})
        for name, count in pairs.items():
            self.assertEqual(count, 0, f"duplicate feature rows in {name}")

    def test_every_sample_assigned_exactly_once(self):
        ids = [s["experiment_id"] for s in self.ctx.samples]
        self.assertEqual(len(ids), self.ctx.x.shape[0])
        self.assertEqual(len(set(ids)), len(ids))

    def test_split_targets_match_feature_labels(self):
        self.assertTrue(
            self.audit["split_integrity"]["split_targets_match_feature_labels"]
        )

    def test_split_hash_and_fingerprints_agree_with_artifact(self):
        integrity = self.audit["split_integrity"]
        self.assertTrue(integrity["split_hash_matches_artifact"])
        self.assertTrue(integrity["dataset_fingerprints_match_split"])
        self.assertTrue(integrity["feature_names_match_loader"])

    def test_duplicate_row_detection_actually_detects_duplicates(self):
        # Non-vacuity: the hash-based duplicate detector must fire when a
        # duplicate is planted, otherwise "0 duplicates" proves nothing.
        ctx = self.ctx
        original = ctx.x
        try:
            injected = original.copy()
            test_index = int(np.flatnonzero(ctx.partition("test"))[0])
            injected[test_index] = injected[0]
            ctx.x = injected
            report = audit_mod.split_integrity_report(ctx)
            self.assertGreaterEqual(
                report["duplicate_feature_rows_between_partitions"]["train_x_test"],
                1,
            )
        finally:
            ctx.x = original


class ClassBalanceTest(AuditFixture):
    def test_all_six_classes_present_in_every_partition(self):
        balance = self.audit["class_balance"]
        self.assertEqual(sorted(balance["classes"]), sorted(TARGET_CLASSES))
        self.assertEqual(len(balance["classes"]), 6)
        self.assertTrue(balance["every_class_present_in_test"])
        for partition, counts in balance["per_partition"].items():
            self.assertEqual(
                sorted(counts), sorted(TARGET_CLASSES),
                f"{partition} is missing classes",
            )
            for name, count in counts.items():
                self.assertGreater(count, 0, f"{name} absent from {partition}")

    def test_test_partition_support_matches_per_class_table(self):
        test = self.audit["headline"]["test"]
        per_class = {r["class"]: r["support"] for r in test["per_class"]}
        self.assertEqual(
            per_class,
            self.audit["class_balance"]["per_partition"]["test"],
        )
        self.assertEqual(sum(per_class.values()), test["samples"])

    def test_dataset_is_not_severely_imbalanced(self):
        balance = self.audit["class_balance"]
        self.assertLess(balance["imbalance_ratio"], 1.5)

    def test_confusion_matrix_is_a_valid_partition(self):
        test = self.audit["headline"]["test"]
        matrix = np.array(test["confusion_matrix"])
        self.assertEqual(matrix.shape, (6, 6))
        self.assertEqual(int(matrix.sum()), test["samples"])
        self.assertTrue((matrix >= 0).all())
        np.testing.assert_array_equal(matrix.sum(axis=1),
                                      [r["support"] for r in test["per_class"]])


class HeadlineMetricsTest(AuditFixture):
    def test_test_partition_metrics_are_perfect(self):
        test = self.audit["headline"]["test"]
        self.assertEqual(test["samples"], 46)
        self.assertEqual(test["accuracy"], 1.0)
        self.assertEqual(test["macro_f1"], 1.0)
        self.assertEqual(test["macro_precision"], 1.0)
        self.assertEqual(test["macro_recall"], 1.0)
        self.assertEqual(test["weighted_f1"], 1.0)

    def test_every_class_has_non_degenerate_metrics(self):
        for row in self.audit["headline"]["test"]["per_class"]:
            self.assertEqual(row["precision"], 1.0, row["class"])
            self.assertEqual(row["recall"], 1.0, row["class"])
            self.assertEqual(row["f1"], 1.0, row["class"])
            self.assertGreater(row["support"], 0, row["class"])

    def test_accuracy_equals_diagonal_fraction(self):
        test = self.audit["headline"]["test"]
        matrix = np.array(test["confusion_matrix"], dtype=float)
        self.assertAlmostEqual(
            test["accuracy"], float(np.trace(matrix)) / test["samples"], places=12
        )

    def test_partitions_are_reported_for_all_three_splits(self):
        for partition in ("train", "validation", "test"):
            self.assertIn(partition, self.audit["headline"])
            self.assertGreater(self.audit["headline"][partition]["samples"], 0)

    def test_metrics_recomputation_is_not_vacuous(self):
        # Recompute from y_true/y_pred on deliberately wrong predictions: a
        # metric that ignored its inputs would return 1.0 here too.
        y_true = np.array([0, 1, 2, 3, 4, 5])
        y_pred = np.array([0, 1, 2, 3, 4, 4])
        metrics = compute_metrics(y_true, y_pred, list(TARGET_CLASSES))
        self.assertAlmostEqual(metrics["accuracy"], 5 / 6)
        self.assertLess(metrics["macro_f1"], 1.0)
        self.assertEqual(metrics["confusion_matrix"][5][5], 0)
        self.assertEqual(metrics["per_class"][5]["recall"], 0.0)

    def test_present_class_macro_ignores_absent_classes(self):
        # `compute_metrics` scores all six labels, so a class absent from a
        # slice contributes f1=0. The audit's present-class variant must not.
        y_true = np.array([0, 1, 2])
        y_pred = np.array([0, 1, 2])
        self.assertEqual(audit_mod._macro_f1_present(y_true, y_pred, TARGET_CLASSES), 1.0)
        self.assertLess(
            compute_metrics(y_true, y_pred, TARGET_CLASSES)["macro_f1"], 1.0
        )


class PerScenarioTest(AuditFixture):
    def test_every_existing_axis_is_sliced(self):
        for axis in ("mode", "address_family", "nat"):
            self.assertIn(axis, self.audit["per_scenario"])
            self.assertTrue(self.audit["per_scenario"][axis]["test_slices"])

    def test_axes_present_in_train_are_reported_even_if_uncovered_in_test(self):
        # `transport` exists in train but never reaches test; the audit must
        # surface that rather than average it away.
        mode = self.audit["per_scenario"]["mode"]
        self.assertIn("transport", mode["values_seen_in_split"]["train"])
        self.assertEqual(mode["uncovered_in_test"], ["transport"])

    def test_covered_slices_are_accurate(self):
        for axis, payload in self.audit["per_scenario"].items():
            for value, slice_ in payload["test_slices"].items():
                self.assertGreater(slice_["samples"], 0, f"{axis}/{value}")
                self.assertEqual(
                    slice_["accuracy"], 1.0, f"{axis}/{value} regressed"
                )
                self.assertEqual(
                    slice_["macro_f1_present_classes"], 1.0, f"{axis}/{value}"
                )

    def test_slice_samples_sum_to_test_partition(self):
        test_samples = self.audit["headline"]["test"]["samples"]
        for axis, payload in self.audit["per_scenario"].items():
            total = sum(s["samples"] for s in payload["test_slices"].values())
            self.assertEqual(total, test_samples, axis)


class CrossRunHoldoutTest(AuditFixture):
    def test_holdout_excludes_the_protected_training_runs(self):
        holdout = self.audit["cross_run_holdout"]
        if not holdout["available"]:
            self.skipTest(holdout["reason"])
        for run in holdout["runs"]:
            self.assertNotIn(run, PROTECTED_DATASET_RUN_IDS)

    def test_holdout_generalizes_to_unseen_runs(self):
        holdout = self.audit["cross_run_holdout"]
        if not holdout["available"]:
            self.skipTest(holdout["reason"])
        metrics = holdout["metrics"]
        self.assertGreater(holdout["samples"], 0)
        self.assertGreater(holdout["run_count"], 1)
        self.assertEqual(metrics["accuracy"], 1.0)
        self.assertEqual(metrics["macro_f1_present_classes"], 1.0)

    def test_holdout_per_run_counts_are_consistent(self):
        holdout = self.audit["cross_run_holdout"]
        if not holdout["available"]:
            self.skipTest(holdout["reason"])
        self.assertEqual(
            sum(r["samples"] for r in holdout["runs"].values()),
            holdout["samples"],
        )
        self.assertEqual(sum(r["correct"] for r in holdout["runs"].values()),
                         holdout["samples"])

    def test_absent_holdout_classes_are_reported(self):
        holdout = self.audit["cross_run_holdout"]
        if not holdout["available"]:
            self.skipTest(holdout["reason"])
        seen = set()
        for info in holdout["runs"].values():
            seen.update(info["labels"])
        self.assertEqual(
            sorted(holdout["classes_absent_from_holdout"]),
            sorted(set(TARGET_CLASSES) - seen),
        )

    def test_discovery_finds_no_protected_runs(self):
        for run in audit_mod.discover_unseen_runs(DATASETS_DIR):
            self.assertNotIn(run, PROTECTED_DATASET_RUN_IDS)


class TransportHoldoutTest(AuditFixture):
    """Transport-mode performance is the gap this audit exists to close."""

    def test_transport_holdout_is_present_and_scored(self):
        holdout = self.audit["transport_holdout"]
        if not holdout["available"]:
            self.skipTest(holdout["reason"])
        self.assertGreater(holdout["samples"], 0)
        self.assertGreater(holdout["distinct_configurations"], 0)
        metrics = holdout["metrics"]
        self.assertEqual(metrics["accuracy"], 1.0)
        self.assertEqual(metrics["macro_f1_present_classes"], 1.0)

    def test_transport_holdout_uses_no_protected_configuration(self):
        holdout = self.audit["transport_holdout"]
        if not holdout["available"]:
            self.skipTest(holdout["reason"])
        disjoint = holdout["disjointness"]
        self.assertEqual(disjoint["configuration_overlap"], [])
        self.assertTrue(disjoint["is_new_configuration_holdout"])

    def test_transport_holdout_shares_no_exact_feature_row(self):
        holdout = self.audit["transport_holdout"]
        if not holdout["available"]:
            self.skipTest(holdout["reason"])
        # Identical rows would let the model recognise training data rather
        # than generalize, even with a fresh configuration_id.
        self.assertEqual(
            holdout["disjointness"]["exact_duplicate_feature_rows"], 0
        )

    def test_transport_holdout_is_not_a_protected_run(self):
        holdout = self.audit["transport_holdout"]
        if not holdout["available"]:
            self.skipTest(holdout["reason"])
        self.assertNotIn(holdout["run_id"], PROTECTED_DATASET_RUN_IDS)

    def test_transport_holdout_covers_every_traffic_profile(self):
        holdout = self.audit["transport_holdout"]
        if not holdout["available"]:
            self.skipTest(holdout["reason"])
        self.assertEqual(sorted(holdout["labels"]), sorted(TARGET_CLASSES))

    def test_misclassified_samples_are_enumerated(self):
        holdout = self.audit["transport_holdout"]
        if not holdout["available"]:
            self.skipTest(holdout["reason"])
        self.assertEqual(len(holdout["misclassified"]), 0)
        support = sum(
            row["support"] for row in holdout["metrics"]["per_class"]
        )
        self.assertEqual(support, holdout["samples"])

    def test_report_flags_a_run_that_reuses_a_protected_configuration(self):
        """A holdout that overlaps training must be rejected, not reported."""
        import pyarrow as pa
        import pyarrow.parquet as pq
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            datasets = pathlib.Path(tmp) / "datasets"
            ctx = _shared_audit()[0]
            protected_cfg = ctx.samples[0]["configuration_id"]

            run_dir = datasets / "transport-overlap-fixture"
            (run_dir / "staging").mkdir(parents=True)
            (run_dir / "staging" / "plan.json").write_text(json.dumps({
                "target_samples": 1,
                "samples": [{"mode": "transport"}],
            }))
            cols = {"configuration_id": [protected_cfg]}
            cols[audit_mod.TARGET_COLUMN] = [TARGET_CLASSES[0]]
            for name in ctx.feature_names:
                cols[name] = [0.0]
            pq.write_table(pa.table(cols), run_dir / "features.parquet")

            report = audit_mod.transport_holdout_report(
                ctx, datasets_dir=datasets, run_id="transport-overlap-fixture"
            )

        self.assertTrue(report["available"])
        self.assertEqual(report["disjointness"]["configuration_overlap"],
                         [protected_cfg])
        self.assertFalse(report["disjointness"]["is_new_configuration_holdout"])

    def test_report_is_absent_without_a_transport_run(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            datasets = pathlib.Path(tmp) / "datasets"
            datasets.mkdir()
            report = audit_mod.transport_holdout_report(
                _shared_audit()[0], datasets_dir=datasets
            )
        self.assertFalse(report["available"])
        self.assertIn("reason", report)


class NonVacuityTest(AuditFixture):
    def test_shuffled_label_control_lands_near_chance(self):
        controls = self.audit["non_vacuity"]
        self.assertTrue(controls["shuffled_label_control_is_near_chance"])
        self.assertLessEqual(
            controls["grouped_cv_on_train_shuffled_labels"]["mean"],
            controls["chance_accuracy"] + 0.10,
        )

    def test_real_labels_separate_far_above_chance(self):
        controls = self.audit["non_vacuity"]
        self.assertGreater(
            controls["grouped_cv_on_train_real_labels"]["mean"] - controls["chance_accuracy"],
            0.5,
        )

    def test_artifact_beats_majority_class_baseline(self):
        controls = self.audit["non_vacuity"]
        self.assertTrue(controls["artifact_beats_majority_baseline"])
        self.assertGreater(
            controls["artifact_test_accuracy"], controls["majority_class_baseline_accuracy"]
        )

    def test_controls_are_deterministic(self):
        first = audit_mod.non_vacuity_controls(self.ctx)
        second = audit_mod.non_vacuity_controls(self.ctx)
        self.assertEqual(
            first["grouped_cv_on_train_shuffled_labels"]["folds"],
            second["grouped_cv_on_train_shuffled_labels"]["folds"],
        )


class RobustnessTest(AuditFixture):
    def test_accuracy_survives_relative_jitter(self):
        sweep = self.audit["robustness"]["relative_jitter_accuracy"]
        self.assertTrue(sweep)
        for sigma, accuracy in sweep.items():
            self.assertGreaterEqual(accuracy, 0.95, f"jitter sigma={sigma}")

    def test_probability_margin_is_strictly_positive(self):
        margin = self.audit["robustness"]["probability_margin"]
        self.assertGreater(margin["min_top1_probability"], 0.0)
        self.assertGreater(margin["min_top1_minus_top2"], 0.0)

    def test_jitter_is_deterministic(self):
        first = audit_mod.robustness_report(self.ctx)
        second = audit_mod.robustness_report(self.ctx)
        self.assertEqual(
            first["relative_jitter_accuracy"], second["relative_jitter_accuracy"]
        )


class ReportSerializationTest(AuditFixture):
    def test_audit_is_json_serializable_and_reloadable(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = audit_mod.write_report(
                self.audit, pathlib.Path(tmp) / "nested" / "audit.json"
            )
            reloaded = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(sorted(reloaded), sorted(self.audit))

    def test_artifact_sha256_is_pinned_to_the_trained_model(self):
        # Guards against silently evaluating a different artifact than the one
        # recorded at training time.
        train_report = pathlib.Path("results/ml/train_report.json")
        if not train_report.is_file():
            self.skipTest("train_report.json not present")
        recorded = json.loads(train_report.read_text())["model_artifact"]["sha256"]
        self.assertEqual(self.audit["artifact"]["sha256"], recorded)

    def test_build_audit_is_deterministic(self):
        again = audit_mod.build_audit()
        for section in ("split_integrity", "class_balance", "robustness", "non_vacuity"):
            self.assertEqual(self.audit[section], again[section], section)


class ProductionPathParityTest(unittest.TestCase):
    """The artifact must classify the held-out rows the same way production does."""

    def test_inference_path_matches_labels_on_every_test_row(self):
        if not _has_artifact():
            self.skipTest("trained artifact not present")
        from controller import ml_inference as ml_inf

        x, y, feats, _groups, _meta = load_dataset()
        artifact = ml_inf.load_artifact(MODEL_PATH)
        document = audit_mod.load_split(audit_mod.SPLIT_PATH)
        experiment_ids = np.asarray(_meta["experiment_id"], dtype=object)
        from controller.train_random_forest import partition_mask

        mask = partition_mask(experiment_ids, document, "test")
        records = [
            {name: float(value) for name, value in zip(feats, row)}
            for row in x[mask]
        ]
        results = ml_inf.predict_many(
            records, artifact=artifact, timestamp="2026-09-24T00:00:00+00:00"
        )
        self.assertEqual(len(results), int(mask.sum()))
        for result, label in zip(results, y[mask]):
            self.assertEqual(result["traffic_profile"], str(label))


if __name__ == "__main__":
    unittest.main()