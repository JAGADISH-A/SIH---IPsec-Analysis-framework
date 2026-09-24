"""Dataset loader for the traffic-profile ML layer.

Reads the two protected ``features.parquet`` runs, validates the feature
schema against ``controller.dataset_artifacts.FEATURE_COLUMNS`` (v2), combines
the runs preserving ``dataset_run_id`` provenance, verifies data quality
(no nulls / non-finite values, declared int/float types), removes the two
verified constant features, and builds the 57-feature ML matrix.

Leakage columns are never returned in ``X``; labels stay separate.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import numpy as np
import pyarrow as pa
import pyarrow.parquet as pq

from controller.dataset_artifacts import (
    FEATURE_COLUMNS,
    FEATURE_SCHEMA_VERSION,
    FLOAT_FEATURES,
    INT_FEATURES,
)

PROTECTED_DATASET_RUN_IDS = ("dataset-20260923-221430", "dataset-20260924-003710")
DEFAULT_DATASETS_DIR = Path("results") / "datasets"

TARGET_COLUMN = "traffic_profile"
GROUPS_COLUMN = "configuration_id"
TARGET_CLASSES = ("voip", "video", "messaging", "email", "web", "icmp")

CONSTANT_FEATURES = ("burst_packet_ratio", "ike_packet_count")

LINKAGE_COLUMNS = (
    "dataset_run_id",
    "sequence",
    "experiment_id",
    "attempt_number",
    "traffic_profile",
    "security_posture",
    "configuration_id",
    "captured_at",
    "pcap_path",
    "feature_schema_version",
)

LEAKAGE_COLUMNS = (
    "security_posture",
    "configuration_id",
    "dataset_run_id",
    "sequence",
    "experiment_id",
    "attempt_number",
    "captured_at",
    "pcap_path",
    "feature_schema_version",
)

ALLOWED_COLUMNS = frozenset(LINKAGE_COLUMNS) | frozenset(FEATURE_COLUMNS)


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _require_int32(table: pa.Table, column: str) -> None:
    field = table.schema.field(column)
    expected = pa.int32()
    if field.type != expected:
        raise TypeError(
            f"feature '{column}' has type {field.type!r}, expected {expected!r}"
        )


def _require_double(table: pa.Table, column: str) -> None:
    field = table.schema.field(column)
    expected = pa.float64()
    if field.type != expected:
        raise TypeError(
            f"feature '{column}' has type {field.type!r}, expected {expected!r}"
        )


def validate_table(table: pa.Table, run_id: str) -> None:
    """Validate one run's feature table against the v2 feature schema."""
    schema_version = FEATURE_SCHEMA_VERSION
    actual_version = sorted(
        str(v) for v in set(table.column("feature_schema_version").to_pylist())
    )
    if table.column("feature_schema_version").null_count:
        raise ValueError(f"run {run_id}: null feature_schema_version")
    if actual_version != [schema_version]:
        raise ValueError(
            f"run {run_id}: unsupported feature_schema_version {actual_version!r}, "
            f"expected {[schema_version]!r}"
        )

    observed = set(table.column_names)
    missing = set(FEATURE_COLUMNS) - observed
    if missing:
        raise ValueError(
            f"run {run_id}: missing feature columns {sorted(missing)}"
        )
    unexpected = observed - ALLOWED_COLUMNS
    if unexpected:
        raise ValueError(
            f"run {run_id}: unexpected columns {sorted(unexpected)}"
        )

    for column in FEATURE_COLUMNS:
        if table.column(column).null_count:
            raise ValueError(
                f"run {run_id}: feature '{column}' contains null rows"
            )
        if column in INT_FEATURES:
            _require_int32(table, column)
        elif column in FLOAT_FEATURES:
            _require_double(table, column)
        else:
            raise ValueError(f"run {run_id}: feature '{column}' untyped")

    for column in FLOAT_FEATURES:
        values = table.column(column).to_numpy()
        if not np.isfinite(values).all():
            raise ValueError(f"run {run_id}: feature '{column}' has non-finite rows")


def read_run(path: Path) -> pa.Table:
    table = pq.read_table(str(path))
    if table.column("feature_schema_version").null_count:
        raise ValueError("null feature_schema_version")
    run_id = table.column("dataset_run_id").to_pylist()
    if not run_id:
        raise ValueError("empty dataset_run_id column")
    validate_table(table, run_id[0])
    return table


def feature_names() -> list[str]:
    """Deterministic ordered 57-feature list (59 declared minus the 2 constants)."""
    return [c for c in FEATURE_COLUMNS if c not in CONSTANT_FEATURES]


def load_dataset(
    run_ids: tuple[str, ...] = PROTECTED_DATASET_RUN_IDS,
    datasets_dir: Path = DEFAULT_DATASETS_DIR,
) -> tuple[np.ndarray, np.ndarray, list[str], np.ndarray, dict]:
    """Load and combine both protected datasets.

    Returns ``(X, y, feature_names, groups, metadata)`` with:
      X             : float64 2-D matrix, ``n_samples x 57``
      y             : traffic_profile labels (str)
      feature_names : the deterministic 57-column order
      groups        : configuration_id per sample (split grouping key)
      metadata      : provenance + quality report
    """
    run_ids = tuple(run_ids)
    missing = [r for r in run_ids if not (datasets_dir / r / "features.parquet").exists()]
    if missing:
        raise FileNotFoundError(f"missing feature parquets: {missing}")

    features = feature_names()
    columns = ["dataset_run_id", "sequence", "experiment_id", TARGET_COLUMN,
               GROUPS_COLUMN] + features

    x_parts: list[np.ndarray] = []
    y_parts: list[np.ndarray] = []
    g_parts: list[np.ndarray] = []
    ids: dict[str, list] = {"dataset_run_id": [], "sequence": [],
                            "experiment_id": []}
    fingerprints: dict[str, str] = {}
    counts: dict[str, int] = {}

    for run_id in run_ids:
        path = datasets_dir / run_id / "features.parquet"
        table = read_run(path)
        row = {col: table.column(col).to_numpy() for col in columns}
        y_part = row[TARGET_COLUMN]
        unknown = sorted(set(map(str, y_part)) - set(TARGET_CLASSES))
        if unknown:
            raise ValueError(
                f"run {run_id}: unknown traffic_profile values {unknown}"
            )
        x_parts.append(np.column_stack([row[c] for c in features]).astype(np.float64))
        y_parts.append(y_part)
        g_parts.append(row[GROUPS_COLUMN])
        for key in ids:
            ids[key].extend(row[key].tolist())
        fingerprints[run_id] = _sha256(path)
        counts[run_id] = int(len(y_part))

    x = np.vstack(x_parts)
    y = np.concatenate(y_parts)
    groups = np.concatenate(g_parts)

    if x.shape[1] != len(features):
        raise ValueError(
            f"built matrix has {x.shape[1]} columns, expected {len(features)}"
        )
    if x.shape[0] != len(y) or x.shape[0] != len(groups):
        raise ValueError(
            "X/y/groups row counts disagree: "
            f"X={x.shape[0]} y={len(y)} groups={len(groups)}"
        )

    metadata = {
        "feature_schema_version": FEATURE_SCHEMA_VERSION,
        "declared_features": 59,
        "constant_features_removed": list(CONSTANT_FEATURES),
        "used_features": features,
        "target_column": TARGET_COLUMN,
        "target_classes": list(TARGET_CLASSES),
        "groups_column": GROUPS_COLUMN,
        "leakage_columns_excluded": list(LEAKAGE_COLUMNS),
        "dataset_run_ids": list(run_ids),
        "sample_counts": counts,
        "input_fingerprints": fingerprints,
        "experiment_id": ids["experiment_id"],
        "sequence": ids["sequence"],
        "dataset_run_id": ids["dataset_run_id"],
    }
    return x, y, features, groups, metadata


def load_dataset_or_fail() -> tuple[np.ndarray, np.ndarray, list[str], np.ndarray, dict]:
    """Loader entry point for tools/tests; raises if the canonical datasets are absent."""
    return load_dataset()