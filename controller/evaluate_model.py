"""Evaluate the trained traffic-profile Random Forest on the untouched test
partition only.

Writes ``results/ml/eval_report.json``, ``results/ml/confusion_matrix.png`` and
a human-readable ``results/ml/eval_report.md``. OOB and model-selection CV
scores are reported from the train metadata, never recomputed on the test set.
"""

from __future__ import annotations

import datetime
import json
from pathlib import Path

import joblib
import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    precision_recall_fscore_support,
)

from controller.grouped_split import load_split
from controller.train_random_forest import partition_mask

RESULTS_ML = Path("results") / "ml"
MODEL_PATH = RESULTS_ML / "model_traffic_rf_v1.joblib"
SPLIT_PATH = RESULTS_ML / "split_v1.json"


def load_artifact(model_path: Path = MODEL_PATH) -> dict:
    artifact = joblib.load(model_path)
    required = (
        "estimator", "feature_names", "feature_schema_version",
        "target_classes", "label_encoder", "split_artifact", "split_hash",
        "input_fingerprints", "metadata",
    )
    missing = [k for k in required if k not in artifact]
    if missing:
        raise ValueError(f"artifact missing keys: {missing}")
    return artifact


def compute_metrics(y_true, y_pred, classes) -> dict:
    labels = list(range(len(classes)))
    accuracy = accuracy_score(y_true, y_pred)
    p, r, f, support = precision_recall_fscore_support(
        y_true, y_pred, labels=labels, zero_division=0
    )
    macro = precision_recall_fscore_support(
        y_true, y_pred, labels=labels, average="macro", zero_division=0
    )
    weighted = precision_recall_fscore_support(
        y_true, y_pred, labels=labels, average="weighted", zero_division=0
    )
    per_class = []
    for i, cls in enumerate(classes):
        per_class.append(
            {
                "class": cls,
                "precision": float(p[i]),
                "recall": float(r[i]),
                "f1": float(f[i]),
                "support": int(support[i]),
            }
        )
    cm = confusion_matrix(y_true, y_pred, labels=labels)
    return {
        "accuracy": float(accuracy),
        "macro_precision": float(macro[0]),
        "macro_recall": float(macro[1]),
        "macro_f1": float(macro[2]),
        "weighted_precision": float(weighted[0]),
        "weighted_recall": float(weighted[1]),
        "weighted_f1": float(weighted[2]),
        "per_class": per_class,
        "confusion_matrix": cm.tolist(),
    }


def run_evaluate():
    artifact = load_artifact()
    model = artifact["estimator"]
    classes = artifact["target_classes"]
    mapping = {str(c): i for i, c in enumerate(classes)}

    from controller.dataset_loader import load_dataset

    x, y, features, groups, metadata = load_dataset()
    document = load_split(SPLIT_PATH)
    if document["split_hash"] != artifact["split_hash"]:
        raise ValueError(
            "split document hash does not match the model artifact split hash"
        )

    experiment_ids = metadata["experiment_id"]
    test_mask = partition_mask(experiment_ids, document, "test")
    if test_mask.sum() == 0:
        raise ValueError("test partition is empty")

    x_test = x[test_mask]
    y_true = np.array([mapping[str(t)] for t in y[test_mask]], dtype=np.int64)

    y_pred = model.predict(x_test)
    proba = model.predict_proba(x_test)

    metrics = compute_metrics(y_true, y_pred, classes)

    meta = artifact["metadata"]
    eval_doc = {
        "dataset": {
            "combined_samples": int(len(y)),
            "test_samples": int(test_mask.sum()),
        },
        "model_artifact": {
            "path": str(MODEL_PATH),
            "feature_names": artifact["feature_names"],
            "feature_schema_version": artifact["feature_schema_version"],
            "target_classes": classes,
        },
        "metrics": metrics,
        "model_quality": {
            "oob_score": meta.get("oob_score"),
            "cv": meta.get("cv"),
            "cv_error": meta.get("cv_error"),
        },
        "proba_range": {
            "min": float(np.min(proba)),
            "max": float(np.max(proba)),
        },
        "reproducibility": {
            "created_at": datetime.datetime.now(
                datetime.timezone.utc
            ).isoformat(timespec="seconds"),
            "git_commit": meta["git_commit"],
            "seed": meta["seed"],
            "library_versions": meta["library_versions"],
            "input_fingerprints": meta["input_fingerprints"],
            "dataset_run_ids": meta["dataset_run_ids"],
            "sample_counts": meta["sample_counts"],
            "split_hash": document["split_hash"],
        },
    }
    RESULTS_ML.mkdir(parents=True, exist_ok=True)
    (RESULTS_ML / "eval_report.json").write_text(
        json.dumps(eval_doc, indent=2) + "\n", encoding="utf-8"
    )
    _write_confusion_png(metrics["confusion_matrix"], classes)
    _write_human_report(eval_doc, metrics)
    return eval_doc


def _write_confusion_png(cm, classes) -> Path:
    cm_max = max(max(row) for row in cm)
    fig, ax = plt.subplots(figsize=(7, 6))
    im = ax.imshow(cm, cmap="Blues")
    ax.set_xticks(range(len(classes)), classes, rotation=45, ha="right")
    ax.set_yticks(range(len(classes)), classes)
    for i in range(len(classes)):
        for j in range(len(classes)):
            ax.text(j, i, str(cm[i][j]), ha="center", va="center",
                    color="white" if cm[i][j] > cm_max / 2 else "black")
    ax.set_xlabel("Predicted traffic_profile")
    ax.set_ylabel("True traffic_profile")
    ax.set_title("Traffic-profile confusion matrix (test)")
    fig.colorbar(im, ax=ax)
    fig.tight_layout()
    path = RESULTS_ML / "confusion_matrix.png"
    fig.savefig(path, dpi=150)
    plt.close(fig)
    return path


def _write_human_report(eval_doc, metrics) -> Path:
    classes = [r["class"] for r in metrics["per_class"]]
    lines = [
        "# ML Evaluation Report",
        "",
        f"- Dataset: {eval_doc['dataset']['combined_samples']} combined samples, "
        f"{eval_doc['dataset']['test_samples']} test samples.",
        f"- Model artifact: {eval_doc['model_artifact']['path']}",
        f"- Feature schema v2, {len(eval_doc['model_artifact']['feature_names'])} features.",
        f"- OOB score: {eval_doc['model_quality']['oob_score']}",
        f"- CV (train-only, StratifiedGroupKFold): "
        f"{eval_doc['model_quality']['cv'] or eval_doc['model_quality']['cv_error']}",
        "",
        "## Metrics (test partition)",
        "",
        f"- accuracy: {metrics['accuracy']:.4f}",
        f"- macro P/R/F1: {metrics['macro_precision']:.4f} / "
        f"{metrics['macro_recall']:.4f} / {metrics['macro_f1']:.4f}",
        f"- weighted P/R/F1: {metrics['weighted_precision']:.4f} / "
        f"{metrics['weighted_recall']:.4f} / {metrics['weighted_f1']:.4f}",
        "",
        "| class | precision | recall | f1 | support |",
        "|---|---|---|---|---|",
    ]
    for row in metrics["per_class"]:
        lines.append(
            f"| {row['class']} | {row['precision']:.4f} | {row['recall']:.4f} | "
            f"{row['f1']:.4f} | {row['support']} |"
        )
    lines.append("")
    lines.append("## Confusion matrix")
    lines.append("")
    cm = metrics["confusion_matrix"]
    lines.append("| true \\ predicted |" + "|".join(classes) + "|")
    lines.append("|" + "|".join(["---"] * (len(cm[0]) + 1)) + "|")
    for i, cls in enumerate(classes):
        row = [cls] + [str(cm[i][j]) for j in range(len(cm))]
        lines.append("|" + "|".join(row) + "|")
    path = RESULTS_ML / "eval_report.md"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def main() -> None:
    doc = run_evaluate()
    print("accuracy:", doc["metrics"]["accuracy"])
    print("macro_f1:", doc["metrics"]["macro_f1"])
    print("per_class:", [(r["class"], r["f1"]) for r in doc["metrics"]["per_class"]])


if __name__ == "__main__":
    main()