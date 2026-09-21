"""Reproducible training for the deterministic demo model (Phase 5).

Training is STRICTLY separated from runtime inference (``inference.py``).
Every artifact records full provenance: model version, feature schema
version, canonical feature names/order, training dataset identity, class
labels and the exact training configuration.

Algorithm: z-scored nearest-centroid classifier computed from labeled
59-feature rows (standard library only, no randomness). It is the documented
test-double / demo model — it is NEVER claimed to be a production model, and
no accuracy metrics are ever asserted for it (no real labeled dataset is
available in this environment; see PHASE_5_ML_INTEGRATION_REPORT.md §14).

Artifact format: JSON only (trusted-artifact; never pickle). ``load_artifact``
performs path and format safety checks.
"""

import json
import math
import os
from statistics import mean, pstdev
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from .errors import FeatureContractError, ModelArtifactError, ModelMetadataError
from .feature_contract import (
    FEATURE_COLUMNS,
    FEATURE_SCHEMA_VERSION,
    canonical_feature_names,
    validate_feature_values,
)
from .model_metadata import MODEL_TYPE_CENTROID, ModelMetadata
from .models import NearestCentroidModel, model_from_dict

MODEL_ARTIFACT_EXTENSION = ".json"


def _round(v: float, ndigits: int = 6) -> float:
    return round(float(v), ndigits)


def train_nearest_centroid(
    rows: Iterable[Tuple[str, Dict[str, float]]],
    *,
    model_version: str,
    training_dataset: Optional[str] = None,
    training_timestamp: Optional[str] = None,
    class_labels: Optional[Sequence[str]] = None,
    estimate_confidence: bool = False,
) -> NearestCentroidModel:
    """Train the deterministic demo classifier on labeled feature rows.

    ``rows`` yields ``(label, features_dict)`` where ``features_dict`` is a
    dict of the 59 canonical numeric features. Rows are validated with the
    SAME fail-fast feature contract used at inference. Training is pure:
    ``mean``/``pstdev`` only, deterministic output for identical input.

    ``estimate_confidence=True`` attaches a deterministic one-hot probability
    schedule so the adapter can expose a (documented, non-calibrated)
    ``classification_confidence``. Default ``False`` keeps confidence ``None``.
    """
    materialized = []
    labels_seen = []
    for label, features in rows:
        validate_feature_values(features)
        materialized.append((label, [float(features[name]) for name in FEATURE_COLUMNS]))
        if label not in labels_seen:
            labels_seen.append(label)
    if not materialized:
        raise FeatureContractError("training requires at least one labeled row")

    if class_labels is None:
        class_labels = sorted(set(labels_seen))
    else:
        class_labels = list(class_labels)
        unseen = set(class_labels) - set(labels_seen)
        if unseen:
            raise FeatureContractError(
                f"declared class_labels not present in training rows: {sorted(unseen)}"
            )
    for label in labels_seen:
        if label not in class_labels:
            raise FeatureContractError(
                f"training row label {label!r} not in declared class_labels "
                f"{class_labels}"
            )

    n = len(FEATURE_COLUMNS)
    per_class: Dict[str, List[List[float]]] = {label: [] for label in class_labels}
    all_rows = []
    for label, vector in materialized:
        per_class[label].append(vector)
        all_rows.append(vector)

    centroids: Dict[str, List[float]] = {}
    for label in class_labels:
        cols = list(zip(*per_class[label]))
        centroids[label] = [_round(mean(col)) for col in cols]

    feature_means = [_round(mean(cols)) for cols in zip(*all_rows)]
    feature_stds = [_round(pstdev(cols)) for cols in zip(*all_rows)]

    probabilities: Dict[str, List[float]] = {}
    if estimate_confidence:
        for i, label in enumerate(class_labels):
            row = [0.0] * len(class_labels)
            row[i] = 1.0
            probabilities[label] = row

    metadata = ModelMetadata.from_values(
        model_version=model_version,
        model_type=MODEL_TYPE_CENTROID,
        training_dataset=training_dataset,
        training_timestamp=training_timestamp,
        class_labels=class_labels,
    )
    return NearestCentroidModel(
        metadata=metadata,
        class_centroids=centroids,
        feature_means=feature_means,
        feature_stds=feature_stds,
        probabilities=probabilities,
    )


def save_artifact(model: NearestCentroidModel, path: str) -> str:
    """Atomically write a JSON model artifact (no pickle, ever)."""
    path = _validate_artifact_path(path, must_exist=False)
    data = json.dumps(model.to_dict(), indent=2, sort_keys=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write(data)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)
    return path


def load_artifact(path: str) -> NearestCentroidModel:
    """Load a JSON model artifact with path/format safety checks.

    The path must exist, be a regular file and end with ``.json`` — it is
    never taken from untrusted runtime input, and model files are never
    executed. Loading performs the full metadata + ordering validation.
    """
    final = _validate_artifact_path(path, must_exist=True)
    try:
        with open(final, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        raise ModelArtifactError(f"cannot read model artifact {final}: {exc}") from exc
    if not isinstance(data, dict):
        raise ModelArtifactError("model artifact JSON root must be an object")
    try:
        model = model_from_dict(data)
    except ModelMetadataError as exc:
        raise ModelArtifactError(f"invalid model artifact {final}: {exc}") from exc
    return model


def _validate_artifact_path(path: str, *, must_exist: bool) -> str:
    if not isinstance(path, str) or not path.strip():
        raise ModelArtifactError("artifact path must be a non-empty string")
    final = os.path.abspath(path)
    if not final.endswith(MODEL_ARTIFACT_EXTENSION):
        raise ModelArtifactError(
            "unsupported model artifact format; only "
            f"{MODEL_ARTIFACT_EXTENSION} is accepted (no pickle/joblib)"
        )
    if must_exist:
        if not os.path.isfile(final):
            raise ModelArtifactError(f"model artifact not found: {final}")
    return final