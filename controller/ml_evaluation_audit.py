"""Credible, reproducible evaluation audit for the traffic-profile Random Forest.

The trained artifact already has a held-out evaluation
(:func:`controller.evaluate_model.run_evaluate`).  That evaluation reports
accuracy, macro/weighted P/R/F1, per-class support and the confusion matrix on
the ``test`` partition of the grouped split, which is the right primary number.

What it does *not* do is establish that the number means anything.  Nothing in
the repository checked whether the split is actually leak-free, whether the
metric is sensitive enough to detect a bad model, whether the perfect score
survives a perturbation, or whether the model holds up on traffic the training
pipeline never saw.  This module adds exactly those checks and nothing else.

It adds no classifier, no feature extraction, no threshold and no training.  It
reads the committed artifact and the protected datasets, and reports:

* ``split_integrity``      group isolation, duplicate-row contamination,
                           assignment coverage and artifact/split hash agreement.
* ``class_balance``        per-class counts, imbalance ratio, minimum support.
* ``headline``             the existing held-out metrics, recomputed.
* ``per_scenario``         accuracy/macro-F1 sliced by the IPsec configuration
                           axes the project already sweeps (mode, address
                           family, NAT) so a slice that is absent from the test
                           partition is visible rather than silently averaged.
* ``cross_run_holdout``    accuracy on dataset runs on disk that are NOT the
                           protected training runs.  These are re-captures of
                           the same topologies, so this measures run-to-run
                           generalization, not new-configuration generalization.
* ``non_vacuity``          controls proving the metric moves: a shuffled-label
                           model must land near chance and a majority-class
                           baseline must be clearly worse than the artifact.
* ``robustness``           relative Gaussian jitter on the feature matrix and
                           the top-1 probability margin.

The audit deliberately reports a ``macro_f1_present_classes`` alongside the
naive macro average.  ``compute_metrics`` scores all six labels even when a
slice contains none of one class, so an absent class contributes ``f1=0`` and
depresses macro-F1 for what is otherwise a perfect slice.  Both numbers are
reported; neither replaces the other.

Run it as::

    python -m controller.ml_evaluation_audit
    python -m controller.ml_evaluation_audit --output results/ml/audit_report.json

Every result is deterministic given the committed artifact and datasets.
"""

from __future__ import annotations

import argparse
import collections
import hashlib
import json
import pathlib
from typing import Any, Callable, Dict, List, Optional, Sequence

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import StratifiedGroupKFold

from controller.dataset_loader import (
    PROTECTED_DATASET_RUN_IDS,
    TARGET_CLASSES,
    TARGET_COLUMN,
    GROUPS_COLUMN,
    feature_names,
    load_dataset,
)
from controller.evaluate_model import (
    MODEL_PATH,
    RESULTS_ML,
    SPLIT_PATH,
    compute_metrics,
    load_artifact,
)
from controller.grouped_split import load_split
from controller.train_random_forest import partition_mask

__all__ = [
    "AUDIT_PATH",
    "build_audit",
    "class_balance_report",
    "cross_run_holdout",
    "load_evaluation_context",
    "main",
    "non_vacuity_controls",
    "per_scenario_report",
    "robustness_report",
    "split_integrity_report",
    "write_report",
]

AUDIT_PATH = RESULTS_ML / "audit_report.json"

#: ``configuration_id`` is ``<mode>-<af>[-nat]-<esp>-<ike>-<dh>-<pfs>`` (see
#: :func:`controller.dataset_planner.configuration_id`), so the axes this project
#: already sweeps are readable from the id without new metadata.
#:
#: NAT is the ``-nat-`` marker between address family and ESP cipher, NOT the
#: trailing token -- the trailing token is ESP PFS. Reading positionally from the
#: end silently measures the PFS axis instead.
_MODE_AXIS = lambda cfg: cfg.split("-")[0]
_AF_AXIS = lambda cfg: cfg.split("-")[1]
_NAT_AXIS = lambda cfg: "-nat-" in cfg
_PFS_AXIS = lambda cfg: cfg.rsplit("-", 1)[1]

#: Control models are fitted with a smaller forest than the artifact on
#: purpose: they exist to show the metric is sensitive, not to compete with the
#: artifact's accuracy.
_CONTROL_N_ESTIMATORS = 60
_CONTROL_SEED = 0


class EvaluationContext:
    """Committed artifact plus the protected dataset and split it was built on."""

    def __init__(self, model_path=MODEL_PATH, split_path=SPLIT_PATH):
        self.model_path = pathlib.Path(model_path)
        self.split_path = pathlib.Path(split_path)
        self.artifact = load_artifact(self.model_path)
        self.estimator = self.artifact["estimator"]
        self.classes = list(self.artifact["target_classes"])
        self.split = load_split(self.split_path)
        x, y, feats, groups, metadata = load_dataset()
        self.x = x
        self.y = y
        self.feature_names = feats
        self.groups = groups
        self.metadata = metadata
        self.experiment_ids = np.asarray(metadata["experiment_id"], dtype=object)
        self.samples = self.split["samples"]

    def partition(self, name: str) -> np.ndarray:
        return partition_mask(self.experiment_ids, self.split, name)

    def partition_labels(self, name: str) -> np.ndarray:
        mask = self.partition(name)
        return self.y[mask]


def _encode(labels: Sequence[str], classes: Sequence[str]) -> np.ndarray:
    lookup = {str(c): i for i, c in enumerate(classes)}
    return np.array([lookup[str(v)] for v in labels], dtype=np.int64)


def _macro_f1_present(y_true, y_pred, classes) -> float:
    """Macro-F1 averaged only over classes that actually occur in ``y_true``.

    An absent class has no true positives and no support, so scoring it as
    ``f1=0`` is an artifact of the label set rather than a model error.
    """
    present = sorted(set(np.asarray(y_true).tolist()))
    if not present:
        return 0.0
    metrics = compute_metrics(y_true, y_pred, classes)
    by_index = {i: row for i, row in enumerate(metrics["per_class"])}
    return float(np.mean([by_index[i]["f1"] for i in present]))


def _sha256(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


# ---------------------------------------------------------------------------
# Data integrity
# ---------------------------------------------------------------------------


def split_integrity_report(ctx: EvaluationContext) -> dict:
    """Recompute the split's leak-freedom claims instead of trusting them.

    ``results/ml/split_v1.json`` ships a ``verification`` block written by the
    splitter.  A splitter vouching for itself is not evidence, so every claim is
    recomputed here from the split assignments and the feature matrix.
    """
    reported = ctx.split.get("verification", {})

    assignments = collections.defaultdict(set)
    for sample in ctx.samples:
        assignments[sample["configuration_id"]].add(sample["split"])
    spanning = sorted(
        cfg for cfg, splits in assignments.items() if len(splits) > 1
    )

    experiment_ids = [s["experiment_id"] for s in ctx.samples]
    counts = collections.Counter(experiment_ids)

    split_of = {s["experiment_id"]: s["split"] for s in ctx.samples}

    def row_digest(row: np.ndarray) -> str:
        return hashlib.sha256(
            np.ascontiguousarray(row, dtype=np.float64).tobytes()
        ).hexdigest()

    digests: Dict[str, List[str]] = {}
    for i, experiment_id in enumerate(experiment_ids):
        digests.setdefault(split_of[experiment_id], []).append(
            row_digest(ctx.x[i])
        )
    partitions = ("train", "validation", "test")
    duplicate_pairs = {}
    for i, a in enumerate(partitions):
        for b in partitions[i + 1:]:
            duplicate_pairs[f"{a}_x_{b}"] = len(
                set(digests.get(a, [])) & set(digests.get(b, []))
            )

    ordered_targets = [s["target"] for s in ctx.samples]
    targets_match_labels = ordered_targets == [str(v) for v in ctx.y]

    fingerprints_on_disk = {
        run_id: _sha256(
            pathlib.Path("results") / "datasets" / run_id / "features.parquet"
        )
        for run_id in PROTECTED_DATASET_RUN_IDS
    }
    claimed = ctx.split.get("input_fingerprints", {})

    return {
        "strategy": ctx.split.get("strategy"),
        "group_isolation_ok": not spanning,
        "configs_spanning_partitions": spanning,
        "duplicate_experiment_ids": sorted(
            e for e, n in counts.items() if n > 1
        ),
        "duplicate_feature_rows_between_partitions": duplicate_pairs,
        "split_targets_match_feature_labels": targets_match_labels,
        "split_hash_matches_artifact": (
            ctx.split["split_hash"] == ctx.artifact["split_hash"]
        ),
        "dataset_fingerprints_match_split": fingerprints_on_disk == claimed,
        "feature_names_match_loader": (
            tuple(ctx.artifact["feature_names"]) == tuple(ctx.feature_names)
        ),
        "verification_block_agrees": {
            "group_isolation_ok": reported.get("group_isolation_ok") == (not spanning),
            "every_sample_once": reported.get("every_sample_once") is True
            and len(counts) == len(ctx.samples),
        },
    }


def class_balance_report(ctx: EvaluationContext) -> dict:
    overall = collections.Counter(str(v) for v in ctx.y)
    per_partition = {}
    for name in ("train", "validation", "test"):
        labels = ctx.partition_labels(name)
        per_partition[name] = dict(
            sorted(collections.Counter(str(v) for v in labels).items())
        )
    present = [overall[c] for c in ctx.classes if overall.get(c)]
    return {
        "target_column": TARGET_COLUMN,
        "classes": ctx.classes,
        "overall": dict(sorted(overall.items())),
        "per_partition": per_partition,
        "min_class_count": min(present) if present else 0,
        "max_class_count": max(present) if present else 0,
        "imbalance_ratio": (
            round(max(present) / min(present), 4) if present else 0.0
        ),
        "every_class_present_in_test": all(
            per_partition["test"].get(c, 0) > 0 for c in ctx.classes
        ),
    }


# ---------------------------------------------------------------------------
# Headline + sliced metrics
# ---------------------------------------------------------------------------


def _partition_metrics(ctx: EvaluationContext, mask: np.ndarray) -> dict:
    y_true = _encode(ctx.y[mask], ctx.classes)
    y_pred = ctx.estimator.predict(ctx.x[mask])
    metrics = compute_metrics(y_true, y_pred, ctx.classes)
    metrics["macro_f1_present_classes"] = _macro_f1_present(
        y_true, y_pred, ctx.classes
    )
    metrics["samples"] = int(mask.sum())
    return metrics


def headline_report(ctx: EvaluationContext) -> dict:
    report = {
        partition: _partition_metrics(ctx, ctx.partition(partition))
        for partition in ("train", "validation", "test")
    }
    meta = ctx.artifact.get("metadata", {})
    report["artifact_quality"] = {
        "oob_score": meta.get("oob_score"),
        "cv": meta.get("cv"),
        "cv_error": meta.get("cv_error"),
    }
    return report


def per_scenario_report(ctx: EvaluationContext) -> dict:
    """Slice the test partition along the IPsec axes the project already sweeps.

    A slice the test partition never covers is reported as ``covered: false``
    rather than being folded into an average that hides it.
    """
    mask = ctx.partition("test")
    configuration_by_id = {
        s["experiment_id"]: s["configuration_id"] for s in ctx.samples
    }
    configurations = [configuration_by_id[e] for e in ctx.experiment_ids[mask]]
    y_true = _encode(ctx.y[mask], ctx.classes)
    y_pred = ctx.estimator.predict(ctx.x[mask])

    axes = {
        "mode": _MODE_AXIS,
        "address_family": _AF_AXIS,
        "nat": _NAT_AXIS,
        "esp_pfs": _PFS_AXIS,
    }
    report = {}
    for axis, extract in axes.items():
        slices = {}
        for value in sorted({extract(c) for c in configurations}):
            selected = np.array(
                [extract(c) == value for c in configurations], dtype=bool
            )
            slices[value] = {
                "samples": int(selected.sum()),
                "accuracy": float(compute_metrics(
                    y_true[selected], y_pred[selected], ctx.classes
                )["accuracy"]),
                "macro_f1_all_classes": float(compute_metrics(
                    y_true[selected], y_pred[selected], ctx.classes
                )["macro_f1"]),
                "macro_f1_present_classes": _macro_f1_present(
                    y_true[selected], y_pred[selected], ctx.classes
                ),
                "true_labels": dict(
                    sorted(collections.Counter(
                        ctx.y[mask][selected].tolist()
                    ).items())
                ),
            }
        seen_in = {
            axis: {
                partition: sorted({
                    extract(configuration_by_id[e])
                    for e in ctx.experiment_ids[ctx.partition(partition)]
                })
                for partition in ("train", "validation", "test")
            }
        }[axis]
        report[axis] = {
            "values_seen_in_split": seen_in,
            "test_slices": slices,
            "uncovered_in_test": sorted(set(seen_in["train"]) - set(slices)),
        }
    return report


# ---------------------------------------------------------------------------
# Generalization to data the protected runs never contained
# ---------------------------------------------------------------------------


def discover_unseen_runs(
    datasets_dir: pathlib.Path = pathlib.Path("results") / "datasets",
) -> List[str]:
    """Dataset runs on disk that are not the protected training runs."""
    if not datasets_dir.is_dir():
        return []
    protected = set(PROTECTED_DATASET_RUN_IDS)
    runs = []
    for entry in sorted(datasets_dir.iterdir()):
        if not entry.is_dir() or entry.name in protected:
            continue
        if (entry / "features.parquet").is_file():
            runs.append(entry.name)
    return runs


def cross_run_holdout(
    ctx: EvaluationContext,
    datasets_dir: pathlib.Path = pathlib.Path("results") / "datasets",
) -> dict:
    """Score the artifact on every non-protected dataset run present on disk.

    These runs re-capture configurations the model was trained on, so this is a
    run-to-run generalization check, not a new-configuration check.
    """
    import pyarrow.parquet as pq

    runs = discover_unseen_runs(datasets_dir)
    if not runs:
        return {"available": False, "reason": "no non-protected runs on disk"}

    features = ctx.feature_names
    per_run = {}
    labels: List[str] = []
    vectors: List[np.ndarray] = []
    for run_id in runs:
        table = pq.read_table(datasets_dir / run_id / "features.parquet")
        run_labels = [str(v) for v in table.column(TARGET_COLUMN).to_pylist()]
        block = np.column_stack(
            [table.column(name).to_numpy() for name in features]
        ).astype(np.float64)
        per_run[run_id] = {
            "samples": len(run_labels),
            "labels": dict(sorted(collections.Counter(run_labels).items())),
        }
        labels.extend(run_labels)
        vectors.append(block)

    x = np.vstack(vectors)
    y_true = _encode(labels, ctx.classes)
    y_pred = ctx.estimator.predict(x)
    metrics = compute_metrics(y_true, y_pred, ctx.classes)
    metrics["macro_f1_present_classes"] = _macro_f1_present(
        y_true, y_pred, ctx.classes
    )

    absent = [c for c in ctx.classes if c not in set(labels)]
    per_run_correct = {}
    offset = 0
    for run_id, info in per_run.items():
        n = info["samples"]
        block_pred = y_pred[offset:offset + n]
        block_true = y_true[offset:offset + n]
        per_run[run_id]["correct"] = int((block_pred == block_true).sum())
        offset += n

    return {
        "available": True,
        "runs": per_run,
        "run_count": len(per_run),
        "samples": len(labels),
        "metrics": metrics,
        "classes_absent_from_holdout": absent,
        "note": (
            "run-to-run generalization only: these runs re-capture "
            "configurations that appear in the protected training runs"
        ),
    }


def transport_holdout_report(
    ctx: EvaluationContext,
    datasets_dir: pathlib.Path = pathlib.Path("results") / "datasets",
    run_id: Optional[str] = None,
) -> dict:
    """Score the artifact on a transport-mode holdout captured on NEW configs.

    The protected split contains no transport rows outside train, so transport
    performance is untested by the headline metric. This report scores a
    separate transport run and proves it is a genuine new-configuration
    holdout: no configuration_id and no exact feature row may be shared with
    the protected training runs. Without that proof the number would be a
    re-capture, not a generalization measurement.
    """
    import pyarrow.parquet as pq

    if run_id is None:
        candidates = [
            run
            for run in discover_unseen_runs(datasets_dir)
            if _mode_of_run(datasets_dir / run) == "transport"
        ]
        if not candidates:
            return {
                "available": False,
                "reason": (
                    "no finalized transport-mode holdout run on disk"
                ),
            }
        run_id = candidates[-1]

    table = pq.read_table(datasets_dir / run_id / "features.parquet")

    labels = [str(v) for v in table.column(TARGET_COLUMN).to_pylist()]
    groups = [str(v) for v in table.column(GROUPS_COLUMN).to_pylist()]
    x = np.column_stack(
        [table.column(name).to_numpy() for name in ctx.feature_names]
    ).astype(np.float64)

    y_true = _encode(labels, ctx.classes)
    y_pred = ctx.estimator.predict(x)
    metrics = compute_metrics(y_true, y_pred, ctx.classes)
    metrics["macro_f1_present_classes"] = _macro_f1_present(
        y_true, y_pred, ctx.classes
    )

    protected_groups = set(s["configuration_id"] for s in ctx.samples)
    holdout_groups = set(groups)
    overlapping = sorted(protected_groups & holdout_groups)

    # An exact feature-row match would let the model recognise a training row
    # rather than generalize, even with a different configuration_id.
    def _row_keys(block, group_list):
        return {
            (g, row.tobytes())
            for g, row in zip(group_list, block)
        }

    protected_rows = _row_keys(ctx.x, [s["configuration_id"] for s in ctx.samples])
    holdout_rows = _row_keys(x, groups)
    duplicate_rows = len(protected_rows & holdout_rows)

    per_sample = {}
    for i, (group, truth, pred) in enumerate(zip(groups, y_true, y_pred)):
        per_sample[i] = int(truth == pred)

    wrong = [
        {
            "sample": i,
            "configuration_id": groups[i],
            "expected": ctx.classes[truth],
            "predicted": ctx.classes[pred],
        }
        for i, correct in per_sample.items()
        if not correct
    ]

    return {
        "available": True,
        "run_id": run_id,
        "samples": len(labels),
        "labels": dict(sorted(collections.Counter(labels).items())),
        "distinct_configurations": len(holdout_groups),
        "metrics": metrics,
        "misclassified": wrong,
        "disjointness": {
            "protected_configurations": len(protected_groups),
            "holdout_configurations": len(holdout_groups),
            "configuration_overlap": overlapping,
            "is_new_configuration_holdout": not overlapping,
            "exact_duplicate_feature_rows": duplicate_rows,
            "note": (
                "A new-configuration holdout requires zero shared "
                "configuration_ids AND zero shared feature rows."
            ),
        },
        "classes_absent_from_holdout": [
            c for c in ctx.classes if c not in set(labels)
        ],
    }


def _mode_of_run(run_dir: pathlib.Path) -> str:
    """Mode of a finalized run, read from its plan's configuration IDs.

    A plan sample carries no explicit ``mode``; the mode is the leading token of
    its ``configuration_id`` (``<mode>-<af>[-nat]-...``), which is the same
    source the scenario axes use.
    """
    plan = run_dir / "staging" / "plan.json"
    if not plan.is_file():
        return ""
    try:
        samples = json.loads(plan.read_text()).get("samples", [])
    except (json.JSONDecodeError, OSError):
        return ""
    modes = set()
    for sample in samples:
        configuration_id = str(sample.get("configuration_id", ""))
        if not configuration_id:
            return ""
        modes.add(configuration_id.split("-")[0].lower())
    return modes.pop() if len(modes) == 1 else ""


# ---------------------------------------------------------------------------
# Is the metric sensitive? Is the score fragile?
# ---------------------------------------------------------------------------


def non_vacuity_controls(ctx: EvaluationContext) -> dict:
    """Controls that must hold for the headline number to mean anything.

    * A model trained on shuffled labels must sit near chance.  If it did not,
      the label carries no signal and a perfect score would be meaningless.
    * A majority-class baseline must be clearly worse than the artifact.
    * Grouped cross-validation on the *train* partition must reproduce the
      headline behaviour without touching validation or test.
    """
    train_mask = ctx.partition("train")
    x_train = ctx.x[train_mask]
    y_train = _encode(ctx.y[train_mask], ctx.classes)
    groups_train = ctx.groups[train_mask]

    n_classes = len(ctx.classes)
    chance = 1.0 / n_classes

    splitter = StratifiedGroupKFold(
        n_splits=5, shuffle=True, random_state=_CONTROL_SEED
    )
    folds = list(splitter.split(x_train, y_train, groups_train))

    def grouped_cv(target: np.ndarray) -> List[float]:
        scores = []
        for train_idx, val_idx in folds:
            model = RandomForestClassifier(
                n_estimators=_CONTROL_N_ESTIMATORS,
                max_features="sqrt",
                min_samples_leaf=2,
                class_weight="balanced_subsample",
                random_state=_CONTROL_SEED,
                n_jobs=-1,
            )
            model.fit(x_train[train_idx], target[train_idx])
            scores.append(
                float((model.predict(x_train[val_idx]) == target[val_idx]).mean())
            )
        return scores

    real_cv = grouped_cv(y_train)
    shuffled = np.random.default_rng(_CONTROL_SEED).permutation(y_train)
    shuffled_cv = grouped_cv(shuffled)

    test_mask = ctx.partition("test")
    y_true = _encode(ctx.y[test_mask], ctx.classes)
    majority = collections.Counter(y_true.tolist()).most_common(1)[0][0]
    majority_accuracy = float((y_true == majority).mean())
    artifact_accuracy = float((ctx.estimator.predict(ctx.x[test_mask]) == y_true).mean())

    return {
        "chance_accuracy": chance,
        "grouped_cv_on_train_real_labels": {
            "folds": real_cv,
            "mean": float(np.mean(real_cv)),
        },
        "grouped_cv_on_train_shuffled_labels": {
            "folds": shuffled_cv,
            "mean": float(np.mean(shuffled_cv)),
        },
        "shuffled_label_control_is_near_chance": (
            float(np.mean(shuffled_cv)) <= chance + 0.10
        ),
        "majority_class_baseline_accuracy": majority_accuracy,
        "artifact_test_accuracy": artifact_accuracy,
        "artifact_beats_majority_baseline": artifact_accuracy > majority_accuracy,
        "control_n_estimators": _CONTROL_N_ESTIMATORS,
        "control_seed": _CONTROL_SEED,
    }


def robustness_report(
    ctx: EvaluationContext,
    sigmas: Sequence[float] = (0.01, 0.05, 0.10, 0.20, 0.30),
    seed: int = _CONTROL_SEED,
) -> dict:
    """Relative Gaussian jitter on the feature matrix, plus the top-1 margin.

    A perfect score that collapses under a 1% perturbation is not a trustworthy
    score.  The features are already non-negative scale quantities, so a
    multiplicative perturbation keeps them physical.
    """
    mask = ctx.partition("test")
    x_test = ctx.x[mask]
    y_true = _encode(ctx.y[mask], ctx.classes)

    proba = ctx.estimator.predict_proba(x_test)
    ordered = np.sort(proba, axis=1)
    margin = {
        "min_top1_probability": float(ordered[:, -1].min()),
        "min_top1_minus_top2": float((ordered[:, -1] - ordered[:, -2]).min()),
        "median_top1_probability": float(np.median(ordered[:, -1])),
    }

    sweep = {}
    for sigma in sigmas:
        rng = np.random.default_rng(seed)
        perturbed = x_test * (1.0 + rng.normal(0.0, sigma, size=x_test.shape))
        predicted = ctx.estimator.predict(perturbed)
        sweep[str(sigma)] = float((predicted == y_true).mean())

    return {
        "relative_jitter_accuracy": sweep,
        "probability_margin": margin,
        "seed": seed,
    }


# ---------------------------------------------------------------------------
# Assembly
# ---------------------------------------------------------------------------


def build_audit(
    model_path: pathlib.Path = MODEL_PATH,
    split_path: pathlib.Path = SPLIT_PATH,
    datasets_dir: Optional[pathlib.Path] = None,
) -> dict:
    ctx = EvaluationContext(model_path, split_path)
    datasets_dir = datasets_dir or pathlib.Path("results") / "datasets"
    return {
        "artifact": {
            "path": str(ctx.model_path),
            "sha256": _sha256(ctx.model_path),
            "feature_schema_version": ctx.artifact["feature_schema_version"],
            "features": len(ctx.artifact["feature_names"]),
            "target_classes": ctx.classes,
            "split_hash": ctx.artifact["split_hash"],
            "protected_dataset_runs": list(PROTECTED_DATASET_RUN_IDS),
        },
        "dataset": {
            "samples": int(ctx.x.shape[0]),
            "features": int(ctx.x.shape[1]),
            "group_column": GROUPS_COLUMN,
            "unique_configurations": int(
                len(set(s["configuration_id"] for s in ctx.samples))
            ),
        },
        "split_integrity": split_integrity_report(ctx),
        "class_balance": class_balance_report(ctx),
        "headline": headline_report(ctx),
        "per_scenario": per_scenario_report(ctx),
        "cross_run_holdout": cross_run_holdout(ctx, datasets_dir),
        "transport_holdout": transport_holdout_report(ctx, datasets_dir),
        "non_vacuity": non_vacuity_controls(ctx),
        "robustness": robustness_report(ctx),
    }


def write_report(audit: dict, output: pathlib.Path = AUDIT_PATH) -> pathlib.Path:
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(audit, indent=2) + "\n", encoding="utf-8")
    return output


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--output", type=pathlib.Path, default=AUDIT_PATH)
    args = parser.parse_args(argv)

    audit = build_audit()
    path = write_report(audit, args.output)

    test = audit["headline"]["test"]
    print(f"artifact           : {audit['artifact']['path']}")
    print(f"sha256             : {audit['artifact']['sha256']}")
    print(f"test samples       : {test['samples']}")
    print(f"test accuracy      : {test['accuracy']:.4f}")
    print(f"test macro F1      : {test['macro_f1']:.4f}")
    print(
        f"present-class F1   : {test['macro_f1_present_classes']:.4f}"
    )
    for row in test["per_class"]:
        print(
            f"  {row['class']:<10} P={row['precision']:.4f} "
            f"R={row['recall']:.4f} F1={row['f1']:.4f} "
            f"support={row['support']}"
        )
    holdout = audit["cross_run_holdout"]
    if holdout["available"]:
        print(
            f"cross-run holdout  : n={holdout['samples']} "
            f"accuracy={holdout['metrics']['accuracy']:.4f} "
            f"present-class F1="
            f"{holdout['metrics']['macro_f1_present_classes']:.4f}"
        )
    else:
        print(f"cross-run holdout  : unavailable ({holdout['reason']})")
    print(f"report             : {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())