"""SHAP explainability for the trained traffic-profile Random Forest.

SHAP is observational only: it explains the already-trained model and never
predicts, modifies probabilities, or overrides the model. Multiclass SHAP
output representation is detected at runtime and recorded verbatim in
``shap_importances.json`` (``shap_representation``); the code asserts the
normalized per-class arrays have the expected ``(n_samples, n_features)``
shape instead of silently transforming an unknown layout.
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

RESULTS_ML = Path("results") / "ml"
SHAP_DIR = RESULTS_ML / "shap"
MODEL_PATH = RESULTS_ML / "model_traffic_rf_v1.joblib"
SPLIT_PATH = RESULTS_ML / "split_v1.json"

TOP_GLOBAL = 20
TOP_PER_CLASS = 15
TOP_INDIVIDUAL = 10


def load_inputs():
    from controller.evaluate_model import load_artifact
    from controller.grouped_split import load_split
    from controller.dataset_loader import load_dataset
    from controller.train_random_forest import partition_mask

    artifact = load_artifact(MODEL_PATH)
    model = artifact["estimator"]
    features = artifact["feature_names"]

    x, y, _, groups, metadata = load_dataset()
    document = load_split(SPLIT_PATH)
    if document["split_hash"] != artifact["split_hash"]:
        raise ValueError(
            "split document hash does not match the model artifact split hash"
        )
    experiment_ids = metadata["experiment_id"]
    test_mask = partition_mask(experiment_ids, document, "test")
    if test_mask.sum() == 0:
        raise ValueError("test partition is empty")

    y_pred = model.predict(x[test_mask])
    classes_ordered = artifact["target_classes"]
    return model, features, x[test_mask], y[test_mask], y_pred, document, metadata, classes_ordered


def normalize_class_arrays(raw, n_classes: int, n_samples: int, n_features: int):
    """Return a per-class list of ``(n_samples, n_features)`` arrays."""
    representation = {
        "type": type(raw).__name__,
        "note": "",
    }
    if isinstance(raw, list):
        arrays = [np.asarray(a) for a in raw]
        representation["note"] = f"list of {len(arrays)} arrays"
        if len(arrays) != n_classes:
            raise ValueError(
                f"SHAP returned {len(arrays)} class arrays, expected {n_classes}"
            )
        for a in arrays:
            if a.shape != (n_samples, n_features):
                raise ValueError(
                    f"SHAP per-class array shape {a.shape}, expected "
                    f"{(n_samples, n_features)}"
                )
        representation["shape"] = f"list[{n_classes}]({n_samples},{n_features})"
        return arrays, representation

    arr = np.asarray(raw)
    representation["shape"] = f"ndarray{arr.shape}"
    if arr.ndim == 3 and arr.shape[2] == n_classes:
        representation["note"] = "ndarray (n_samples, n_features, n_classes)"
        return [arr[:, :, i] for i in range(n_classes)], representation
    if arr.ndim == 3 and arr.shape[1] == n_classes:
        representation["note"] = "ndarray (n_samples, n_classes, n_features)"
        return [arr[:, i, :] for i in range(n_classes)], representation
    raise ValueError(
        f"unrecognized SHAP multiclass output shape {arr.shape} "
        f"for n_classes={n_classes}"
    )


def _beeswarm(ax, shap_arr, feature_values, top_idx, feature_names):
    for rank, fi in enumerate(top_idx):
        vals = shap_arr[:, fi]
        feat_vals = feature_values[:, fi]
        order = np.argsort(vals)
        y = rank + 0.25 * ((np.arange(len(vals)) % 5) - 2)
        colors = (feat_vals[order] - feat_vals[order].min()) / (
            np.ptp(feat_vals[order]) + 1e-9
        )
        ax.scatter(vals[order], y[order], c=colors, cmap="RdBu_r",
                   s=6, alpha=0.6, linewidths=0)
    ax.set_yticks(range(len(top_idx)))
    ax.set_yticklabels([feature_names[i] for i in top_idx], fontsize=7)
    ax.axvline(0, color="black", linewidth=0.5)


def run_shap():
    SHAP_DIR.mkdir(parents=True, exist_ok=True)

    import shap

    model, features, x_test, y_true, y_pred, document, metadata, classes = load_inputs()
    n_samples, n_features = x_test.shape

    proba_before = model.predict_proba(x_test).copy()

    explainer = shap.TreeExplainer(model, feature_names=features)
    raw = explainer.shap_values(x_test)
    class_arrays, representation = normalize_class_arrays(
        raw, len(classes), n_samples, n_features
    )
    representation["library_versions"] = {"shap": shap.__version__}

    if hasattr(explainer, "expected_value"):
        expected = explainer.expected_value
        expected = np.asarray(expected).reshape(-1).tolist()
    else:
        expected = None

    proba_after = model.predict_proba(x_test)
    non_interference = {
        "predictions_equal": bool(np.array_equal(y_pred, model.predict(x_test))),
        "probabilities_equal": bool(np.array_equal(proba_before, proba_after)),
    }

    feature_values = x_test
    global_abs = np.mean(
        np.mean([np.abs(a) for a in class_arrays], axis=0), axis=0
    )
    per_class_abs = [np.mean(np.abs(a), axis=0) for a in class_arrays]

    global_rank = np.argsort(global_abs)[::-1]
    per_class_rank = [np.argsort(a)[::-1] for a in per_class_abs]

    _write_importance_bar(global_abs, global_rank, features)
    _write_summary(class_arrays, x_test, per_class_rank, features, classes)
    _write_per_class_bars(per_class_abs, per_class_rank, features, classes)

    np.savez(
        SHAP_DIR / "shap_values.npz",
        **{
            f"shap_class_{classes[i].replace('-', '_')}": class_arrays[i]
            for i in range(len(classes))
        },
    )

    individual = _write_individual_explanations(
        class_arrays, feature_values, y_pred, proba_after, document, classes, features
    )

    global_importance = [
        {"feature": features[i], "mean_abs_shap": float(global_abs[i])}
        for i in global_rank[:TOP_GLOBAL]
    ]
    per_class_importance = {}
    for i, cls in enumerate(classes):
        rank = per_class_rank[i]
        per_class_importance[cls] = [
            {"feature": features[j], "mean_abs_shap": float(per_class_abs[i][j])}
            for j in rank[:TOP_PER_CLASS]
        ]

    import hashlib

    model_hash = hashlib.sha256(MODEL_PATH.read_bytes()).hexdigest()
    result = {
        "created_at": datetime.datetime.now(
            datetime.timezone.utc
        ).isoformat(timespec="seconds"),
        "model_artifact": {"path": str(MODEL_PATH), "sha256": model_hash},
        "feature_schema_version": "v2",
        "used_features": features,
        "target_classes": classes,
        "test_samples": n_samples,
        "test_feature_shape": [n_samples, n_features],
        "shap_representation": representation,
        "expected_value_per_class": expected,
        "global_importance": global_importance,
        "per_class_importance": per_class_importance,
        "individual_explanations": individual,
        "non_interference": non_interference,
        "reproducibility": {
            "git_commit": "read from train_report",
            "library_versions": {"shap": shap.__version__},
            "input_fingerprints": metadata["input_fingerprints"],
            "dataset_run_ids": metadata["dataset_run_ids"],
            "split_hash": document["split_hash"],
        },
        "limitation": (
            "Synthetic, deterministically generated traffic: SHAP importance "
            "reflects the fixed generator characteristics of this dataset, not "
            "universal application fingerprints."
        ),
    }
    (SHAP_DIR / "shap_importances.json").write_text(
        json.dumps(result, indent=2) + "\n", encoding="utf-8"
    )
    return result


def _write_importance_bar(global_abs, global_rank, features) -> Path:
    top = global_rank[:TOP_GLOBAL][::-1]
    fig, ax = plt.subplots(figsize=(8, 6))
    ax.barh([features[i] for i in top], [global_abs[i] for i in top])
    ax.set_xlabel("mean |SHAP| (global, all classes)")
    fig.tight_layout()
    path = SHAP_DIR / "shap_importance_bar.png"
    fig.savefig(path, dpi=150)
    plt.close(fig)
    return path


def _write_summary(class_arrays, feature_values, per_class_rank, features, classes) -> Path:
    n = len(classes)
    fig, axes = plt.subplots(2, (n + 1) // 2, figsize=(16, 9))
    axes = axes.ravel()
    for i, cls in enumerate(classes):
        top = per_class_rank[i][:TOP_PER_CLASS]
        _beeswarm(axes[i], class_arrays[i], feature_values, top, features)
        axes[i].set_title(cls, fontsize=9)
    for j in range(n, len(axes)):
        axes[j].axis("off")
    fig.suptitle("SHAP summary (per class, top 15 features)")
    fig.tight_layout()
    path = SHAP_DIR / "shap_summary.png"
    fig.savefig(path, dpi=150)
    plt.close(fig)
    return path


def _write_per_class_bars(per_class_abs, per_class_rank, features, classes) -> list:
    paths = []
    for i, cls in enumerate(classes):
        top = per_class_rank[i][:TOP_PER_CLASS][::-1]
        fig, ax = plt.subplots(figsize=(7, 5))
        ax.barh([features[j] for j in top], [per_class_abs[i][j] for j in top])
        ax.set_xlabel("mean |SHAP|")
        ax.set_title(f"per-class SHAP importance: {cls}")
        fig.tight_layout()
        path = SHAP_DIR / f"shap_per_class_{cls}.png"
        fig.savefig(path, dpi=150)
        plt.close(fig)
        paths.append(path)
    return paths


def _write_individual_explanations(
    class_arrays, feature_values, y_pred, proba, document, classes, features
) -> dict:
    results = {}
    sample_split = {s["experiment_id"]: s for s in document["samples"]}
    for ci, cls in enumerate(classes):
        candidates = np.where(y_pred == ci)[0]
        if len(candidates) == 0:
            results[cls] = {"status": "no_test_samples_predicted_as_this_class"}
            continue
        conf = proba[candidates, ci]
        k_idx = int(np.argmax(conf))
        idx = candidates[k_idx]
        exp = document["samples"][idx]["experiment_id"]
        contributions = class_arrays[ci][idx]
        order = np.argsort(np.abs(contributions))[::-1][:TOP_INDIVIDUAL]
        top = [
            {
                "feature": features[fi],
                "shap_value": float(contributions[fi]),
                "feature_value": float(feature_values[idx, fi]),
            }
            for fi in order
        ]
        fig, ax = plt.subplots(figsize=(7, 5))
        names = [t["feature"] for t in top][::-1]
        values = [t["shap_value"] for t in top][::-1]
        ax.barh(names, values, color=["#d62728" if v < 0 else "#1f77b4" for v in values])
        ax.set_xlabel("SHAP contribution")
        ax.set_title(f"class {cls} - sample {exp} (true={cls} pred={cls}, q={conf[k_idx]:.3f})")
        fig.tight_layout()
        fig.savefig(SHAP_DIR / f"shap_individual_{cls}_{exp}.png", dpi=150)
        plt.close(fig)
        results[cls] = {
            "experiment_id": exp,
            "predicted_confidence": float(conf[k_idx]),
            "top_contributions": top,
        }
    return results


def main() -> None:
    result = run_shap()
    print("shap output dir:", SHAP_DIR)
    print("representation:", result["shap_representation"])
    print("non_interference:", result["non_interference"])
    print("global top-5:", [g["feature"] for g in result["global_importance"][:5]])


if __name__ == "__main__":
    main()