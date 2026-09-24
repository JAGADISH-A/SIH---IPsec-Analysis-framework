"""Train the baseline Random Forest traffic-profile classifier.

Pipeline: loader -> grouped split -> StratifiedGroupKFold model selection on
the train partition only -> RandomForestClassifier baseline -> joblib artifact
+ train_report.json. Validation and test partitions are never touched here.
"""

from __future__ import annotations

import datetime
import hashlib
import json
import platform
import subprocess
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import StratifiedGroupKFold

from controller.dataset_loader import TARGET_CLASSES


def git_commit() -> str:
    try:
        return subprocess.run(
            ["git", "rev-parse", "HEAD"],
            capture_output=True, text=True, check=True,
        ).stdout.strip()
    except Exception:
        return "unknown"


def library_versions() -> dict:
    import shap
    import sklearn

    return {
        "python": platform.python_version(),
        "numpy": np.__version__,
        "scikit-learn": sklearn.__version__,
        "joblib": joblib.__version__,
        "shap": shap.__version__,
        "matplotlib": __import__("matplotlib").__version__,
    }


def _file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def partition_mask(experiment_ids, split_document, split_name: str) -> np.ndarray:
    assignment = {s["experiment_id"]: s["split"] for s in split_document["samples"]}
    return np.array(
        [assignment[str(e)] == split_name for e in experiment_ids], dtype=bool
    )


def encode_target(y, target_classes) -> np.ndarray:
    mapping = {c: i for i, c in enumerate(target_classes)}
    return np.array([mapping[str(t)] for t in y], dtype=np.int64)


def configure_model(seed: int) -> RandomForestClassifier:
    return RandomForestClassifier(
        n_estimators=500,
        max_features="sqrt",
        min_samples_leaf=2,
        max_depth=None,
        class_weight="balanced_subsample",
        oob_score=True,
        random_state=seed,
        n_jobs=-1,
    )


def split_class_counts(mask, y_int) -> dict:
    return {
        cls: int(np.sum(y_int[mask] == idx)) for idx, cls in enumerate(TARGET_CLASSES)
    }


def run_train():
    from controller.dataset_loader import load_dataset
    from controller.grouped_split import (
        SPLIT_SEED,
        build_split_json,
        load_split,
    )

    results_ml = Path("results") / "ml"
    results_ml.mkdir(parents=True, exist_ok=True)

    x, y, features, groups, metadata = load_dataset()
    split_path = build_split_json(x, y, groups, metadata, seed=SPLIT_SEED)
    document = load_split(split_path)

    y_int = encode_target(y, TARGET_CLASSES)
    experiment_ids = metadata["experiment_id"]

    train_mask = partition_mask(experiment_ids, document, "train")
    val_mask = partition_mask(experiment_ids, document, "validation")
    test_mask = partition_mask(experiment_ids, document, "test")

    x_train, y_train, g_train = x[train_mask], y_int[train_mask], groups[train_mask]
    x_val, y_val = x[val_mask], y_int[val_mask]
    x_test, y_test = x[test_mask], y_int[test_mask]

    present = set(np.unique(y_train).tolist())
    missing_classes = [c for i, c in enumerate(TARGET_CLASSES) if i not in present]
    if missing_classes:
        raise ValueError(
            f"train partition is missing classes {missing_classes}; "
            "grouped assignation produced an unusable split"
        )

    cv_scores = None
    cv_error = None
    try:
        cv = StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=SPLIT_SEED)
        cv_acc = []
        cv_f1 = []
        from sklearn.metrics import f1_score

        for train_idx, valid_idx in cv.split(x_train, y_train, groups=g_train):
            fold_model = configure_model(seed=SPLIT_SEED)
            fold_model.fit(x_train[train_idx], y_train[train_idx])
            y_pred = fold_model.predict(x_train[valid_idx])
            cv_acc.append(float(fold_model.score(x_train[valid_idx], y_train[valid_idx])))
            cv_f1.append(float(f1_score(y_train[valid_idx], y_pred, average="macro")))
        cv_scores = {
            "accuracy": cv_acc,
            "macro_f1": cv_f1,
            "accuracy_mean": float(np.mean(cv_acc)),
            "accuracy_std": float(np.std(cv_acc)),
            "macro_f1_mean": float(np.mean(cv_f1)),
            "macro_f1_std": float(np.std(cv_f1)),
        }
    except ValueError as exc:
        cv_error = str(exc)

    model = configure_model(seed=SPLIT_SEED)
    model.fit(x_train, y_train)

    seed = SPLIT_SEED
    created_at = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")

    artifact = {
        "estimator": model,
        "feature_names": features,
        "feature_schema_version": metadata["feature_schema_version"],
        "target_classes": list(TARGET_CLASSES),
        "label_encoder": {c: i for i, c in enumerate(TARGET_CLASSES)},
        "split_artifact": split_path.name,
        "split_hash": document["split_hash"],
        "input_fingerprints": metadata["input_fingerprints"],
        "metadata": {
            "git_commit": git_commit(),
            "created_at": created_at,
            "seed": seed,
            "library_versions": library_versions(),
            "dataset_run_ids": metadata["dataset_run_ids"],
            "input_fingerprints": metadata["input_fingerprints"],
            "sample_counts": {
                "total": int(len(y)),
                "train": int(train_mask.sum()),
                "validation": int(val_mask.sum()),
                "test": int(test_mask.sum()),
            },
            "hyperparameters": model.get_params(),
            "oob_score": float(model.oob_score_),
            "cv": cv_scores,
            "cv_error": cv_error,
            "class_mapping": {c: i for i, c in enumerate(TARGET_CLASSES)},
        },
    }

    model_path = results_ml / "model_traffic_rf_v1.joblib"
    joblib.dump(artifact, model_path)
    model_sha256 = _file_sha256(model_path)

    report = {
        "created_at": created_at,
        "git_commit": artifact["metadata"]["git_commit"],
        "seed": seed,
        "library_versions": artifact["metadata"]["library_versions"],
        "dataset_run_ids": metadata["dataset_run_ids"],
        "input_fingerprints": metadata["input_fingerprints"],
        "sample_counts": artifact["metadata"]["sample_counts"],
        "per_split_target": {
            s: split_class_counts(
                partition_mask(experiment_ids, document, s), y_int
            )
            for s in ("train", "validation", "test")
        },
        "feature_schema": {
            "declared_features": metadata["declared_features"],
            "constant_features_removed": metadata["constant_features_removed"],
            "used_features": features,
            "feature_schema_version": metadata["feature_schema_version"],
        },
        "hyperparameters": model.get_params(),
        "class_mapping": artifact["label_encoder"],
        "target_classes": list(TARGET_CLASSES),
        "oob_score": artifact["metadata"]["oob_score"],
        "cv": cv_scores,
        "cv_error": cv_error,
        "split": {
            "path": str(split_path),
            "hash": document["split_hash"],
            "counts": document["split_counts"],
            "strategy": document["strategy"],
            "ratios": document["ratios"],
            "seed": seed,
        },
        "model_artifact": {
            "path": str(model_path),
            "sha256": model_sha256,
        },
    }

    report_path = results_ml / "train_report.json"
    report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    feature_schema_path = results_ml / "feature_schema_v2.json"
    feature_schema_path.write_text(
        json.dumps(report["feature_schema"], indent=2) + "\n", encoding="utf-8"
    )
    return report, model_path


def main() -> None:
    report, model_path = run_train()
    print("model artifact:", model_path)
    print("split_counts:", report["split"]["counts"])
    print("oob_score:", report["oob_score"])
    print("cv:", report["cv_error"] or report["cv"])


if __name__ == "__main__":
    main()