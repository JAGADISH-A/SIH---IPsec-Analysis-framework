"""Shared helpers + fixtures for Phase 5 ML tests.

The demo model/feature windows here are synthetic but DETERMINISTIC. They
exist to exercise the ML contract end-to-end; no accuracy claim is attached
(see PHASE_5_ML_INTEGRATION_REPORT.md). ``centroid-demo-v0.json`` in this
directory is a real artifact produced by ``correlation.ml.training.save_artifact``.
"""

import math
import os
from typing import Any, Dict, List, Tuple

from correlation.ml.feature_contract import (
    FEATURE_COLUMNS,
    INT_FEATURES,
    FEATURE_SCHEMA_VERSION,
)
from correlation.ml.models import NearestCentroidModel
from correlation.ml.training import train_nearest_centroid
from correlation.models import LiveFeatureWindow

FIXTURE_DIR = os.path.dirname(os.path.abspath(__file__))
CENTROID_ARTIFACT = os.path.join(FIXTURE_DIR, "centroid-demo-v0.json")

VOIP_BASE = 100.0
VIDEO_BASE = 1200.0


def make_row(base: float, variation: int = 0) -> Dict[str, Any]:
    """Deterministic synthetic 59-feature row (variation shifts most cols)."""
    features: Dict[str, Any] = {}
    for index, name in enumerate(FEATURE_COLUMNS):
        value = base + variation * (index % 7)
        features[name] = value
    for name in sorted(INT_FEATURES):
        features[name] = int(features[name])
    return features


def feature_window(
    features: Dict[str, Any],
    *,
    version: str = FEATURE_SCHEMA_VERSION,
) -> LiveFeatureWindow:
    return LiveFeatureWindow(
        feature_schema_version=version,
        window_start_ns=0,
        window_end_ns=1000,
        features=dict(features),
    )


def valid_window(profile: str = "voip", variation: int = 0) -> LiveFeatureWindow:
    base = VOIP_BASE if profile == "voip" else VIDEO_BASE
    return feature_window(make_row(base, variation))


def build_demo_model(
    *,
    estimate_confidence: bool = True,
    model_version: str = "v0-demo",
    anomaly_threshold: float | None = None,
) -> NearestCentroidModel:
    """Deterministic demo model trained on two separable classes."""
    rows: List[Tuple[str, Dict[str, Any]]] = []
    for i in range(4):
        rows.append(("voip", make_row(VOIP_BASE, i)))
    for i in range(4):
        rows.append(("video", make_row(VIDEO_BASE, i)))

    def _build() -> NearestCentroidModel:
        return train_nearest_centroid(
            rows,
            model_version=model_version,
            training_dataset="tests/fixtures/ml (synthetic, deterministic)",
            training_timestamp="2026-01-01T00:00:00Z",
            estimate_confidence=estimate_confidence,
        )

    model = _build()
    if anomaly_threshold is not None:
        model = model.__class__(
            metadata=model.metadata,
            class_centroids=model.class_centroids,
            feature_means=model.feature_means,
            feature_stds=model.feature_stds,
            probabilities=model.probabilities,
            anomaly_threshold=anomaly_threshold,
        )
    return model


def specifically_mutated_row(base: float = VOIP_BASE, **mutations: Any) -> Dict[str, Any]:
    row = make_row(base)
    row.update(mutations)
    return row