"""Deterministic, standard-library-only model (Phase 5).

No trained model exists anywhere in the authoritative ``D:\\sihipsec``
repository (verified in Phase 5 discovery: stdlib-only feature pipeline, no
sklearn/joblib/pickle artifacts, no classifier weights). This workspace
therefore provides a small, FULLY DETERMINISTIC classifier: a z-scored
nearest-centroid model trained from labeled feature rows by ``training.py``.

Trust status:
* It is the documented integration test-double / demo model. It is a real,
  reproducible classifier, but it has NEVER been trained on real captures (no
  real dataset is present in either repository), so NO accuracy/precision/
  recall/F1 claim is ever made for it.
* It exists so the ML CONTRACT (feature validation, ordering, provenance,
  confidence policy, anomaly seam, label mapping) is exercised end-to-end
*without* inventing an external dependency. The adapter boundary is model
*agnostic: an externally supplied model that implements the same interface
*(predict / optional predict_proba / optional anomaly score + ModelMetadata)
*substitutes directly.
"""

import math
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence

from .errors import ModelMetadataError
from .feature_contract import canonical_feature_names
from .model_metadata import MODEL_TYPE_CENTROID, ModelMetadata


@dataclass(frozen=True)
class NearestCentroidModel:
    """Deterministic z-scored nearest-centroid classifier.

    Artifact fields (JSON-serializable):
      metadata            ModelMetadata (version/type/schema/dataset/labels)
      class_centroids     {label: [59 floats]} in class_labels order
      feature_means       [59 floats]
      feature_stds        [59 floats]
      probabilities       optional {label: [1.0]} per-class fixed schedule --
                          ONLY present when ``estimate_confidence=True`` was
                          requested; it is a documented deterministic
                          similarity schedule, NEVER a calibrated posterior.
      anomaly_threshold   optional float; when absent the model has no
                          anomaly capability (anomaly stays null upstream).
    """

    metadata: ModelMetadata
    class_centroids: Dict[str, List[float]]
    feature_means: List[float]
    feature_stds: List[float]
    probabilities: Dict[str, List[float]] = field(default_factory=dict)
    anomaly_threshold: Optional[float] = None

    def __post_init__(self) -> None:
        n = len(canonical_feature_names())
        if len(self.feature_means) != n or len(self.feature_stds) != n:
            raise ModelMetadataError("feature means/stds must have 59 entries")
        labels = self.metadata.class_labels
        if list(self.class_centroids.keys()) != list(labels):
            raise ModelMetadataError(
                "class_centroids keys must equal class_labels order exactly"
            )
        for label in labels:
            centroid = self.class_centroids[label]
            if len(centroid) != n:
                raise ModelMetadataError(
                    f"centroid for {label!r} must have {n} entries, got {len(centroid)}"
                )
            for value in centroid:
                if not isinstance(value, (int, float)) or isinstance(value, bool):
                    raise ModelMetadataError(f"centroid value non-numeric: {value!r}")
        for name, value in (("feature_means", self.feature_means),
                            ("feature_stds", self.feature_stds)):
            for v in value:
                if not isinstance(v, (int, float)) or isinstance(v, bool):
                    raise ModelMetadataError(f"{name} value non-numeric: {v!r}")
        for label, probs in self.probabilities.items():
            if label not in labels:
                raise ModelMetadataError(
                    f"probability entry for unknown label {label!r}"
                )
            if len(probs) != len(labels) or abs(sum(probs) - 1.0) > 1e-9:
                raise ModelMetadataError(
                    f"probability vector for {label!r} must have {len(labels)} "
                    "entries summing to 1"
                )

    # -------- model interface used by the adapter ---------------------------
    def supports_probability(self) -> bool:
        return bool(self.probabilities)

    def predict(self, vector: Sequence[float]) -> str:
        distances = self._distances(vector)
        best = distances.index(min(distances))
        return self.metadata.class_labels[best]

    def predict_proba(self, vector: Sequence[float]) -> Dict[str, float]:
        if not self.supports_probability():
            return {label: 0.0 for label in self.metadata.class_labels}
        label = self.predict(vector)
        return {
            other: prob for other, prob in zip(self.metadata.class_labels, self.probabilities[label])
        }

    def supports_anomaly(self) -> bool:
        return self.anomaly_threshold is not None

    def score_anomaly(self, vector: Sequence[float]) -> float:
        """Deterministic normalized distance to the nearest centroid."""
        distances = self._distances(vector)
        return round(min(distances) / math.sqrt(len(vector)), 6)

    # -------- internals -----------------------------------------------------
    def _zscaled(self, vector: Sequence[float]) -> List[float]:
        out = []
        for value, mean, std in zip(vector, self.feature_means, self.feature_stds):
            if std and std > 0:
                out.append((value - mean) / std)
            else:
                out.append(0.0)
        return out

    def _distances(self, vector: Sequence[float]) -> List[float]:
        z = self._zscaled(vector)
        distances = []
        for label in self.metadata.class_labels:
            centroid = self.class_centroids[label]
            cz = self._zscaled(centroid)
            distances.append(sum((a - b) ** 2 for a, b in zip(z, cz)))
        return distances

    # -------- artifact I/O --------------------------------------------------
    def to_dict(self) -> Dict[str, Any]:
        return {
            "metadata": self.metadata.to_dict(),
            "class_centroids": {k: list(v) for k, v in self.class_centroids.items()},
            "feature_means": [float(x) for x in self.feature_means],
            "feature_stds": [float(x) for x in self.feature_stds],
            "probabilities": {
                k: [float(x) for x in v] for k, v in self.probabilities.items()
            },
            "anomaly_threshold": self.anomaly_threshold,
        }


def model_from_dict(data: Dict[str, Any]) -> NearestCentroidModel:
    try:
        return NearestCentroidModel(
            metadata=ModelMetadata.from_dict(data["metadata"]),
            class_centroids={
                k: [float(x) for x in v] for k, v in data["class_centroids"].items()
            },
            feature_means=[float(x) for x in data["feature_means"]],
            feature_stds=[float(x) for x in data["feature_stds"]],
            probabilities={
                k: [float(x) for x in v] for k, v in data.get("probabilities", {}).items()
            },
            anomaly_threshold=data.get("anomaly_threshold"),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise ModelMetadataError(f"malformed model artifact: {exc}") from exc