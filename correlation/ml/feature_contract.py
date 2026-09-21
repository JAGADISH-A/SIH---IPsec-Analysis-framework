"""Canonical v2 feature contract for the ML layer (Phase 5).

The 59 canonical feature names, their order and their int/float split are a
snapshot of the AUTHORITATIVE SIHPsec contract:

    D:\\sihipsec\\controller\\dataset_artifacts.py   -> FEATURE_COLUMNS / INT_FEATURES
    D:\\sihipsec\\controller\\features.py            -> the only feature computation
    D:\\sihipsec\\controller\\live_features.py        -> the live record bridge

The snapshot copies the authoritative FEATURE_COLUMNS list EXACTLY (names and
order) and the INT_FEATURES set, because the workspace must never import from
``D:\\sihipsec`` at runtime (read-only reference, not a dependency). A guard
test re-verifies the snapshot against the live authoritative module whenever
that path is importable, so the two can never silently drift.

Validation policy (deterministic, fail-fast):

* feature_schema_version MUST be ``"v2"``.
* ``features`` MUST contain EXACTLY the 59 canonical keys — no missing key, no
  extra key. An extra key is a schema drift (the authoritative recorders emit
  exactly 59) and is rejected deterministically with the offending names.
* Every value MUST be a real number: ``int``/``float``, not ``bool``, not a
  string, not ``None``.  ``NaN`` and ``+/-inf`` are rejected.
* Missing values are NEVER filled with zeros. There is no documented
  imputation strategy in the authoritative pipeline, so the adapter fails
  fast (``FeatureContractError``).
* Feature ordering is explicit: a model artifact records the canonical ordered
  names and inference verifies them against the artifact before building the
  input vector.

No ML feature is ever renamed, reordered, dropped or added here.
"""

import math
from typing import Any, Dict, List, Tuple, Union

from ..models import LiveFeatureWindow
from .errors import FeatureContractError

FEATURE_SCHEMA_VERSION = "v2"
FEATURE_COUNT = 59

# Authoritative snapshot: D:\\sihipsec\\controller\\dataset_artifacts.py
# ``FEATURE_COLUMNS`` (names + order MUST match that source exactly).
FEATURE_COLUMNS = [
    "packet_count", "total_bytes", "mean_packet_size", "packet_size_std",
    "min_packet_size", "max_packet_size", "packet_size_p10", "packet_size_p50",
    "packet_size_p90", "packet_size_p95", "packet_size_p99",
    "unique_packet_size_count", "packet_size_entropy", "small_packet_ratio",
    "large_packet_ratio", "mean_inter_arrival_time", "inter_arrival_time_std",
    "min_inter_arrival_time", "max_inter_arrival_time", "packets_per_second",
    "bytes_per_second", "flow_duration", "outbound_packet_count",
    "inbound_packet_count", "outbound_bytes", "inbound_bytes",
    "outbound_packet_ratio", "inbound_packet_ratio", "outbound_byte_ratio",
    "inbound_byte_ratio", "outbound_mean_packet_size",
    "inbound_mean_packet_size", "outbound_packets_per_second",
    "inbound_packets_per_second", "outbound_packet_size_p10",
    "outbound_packet_size_p50", "outbound_packet_size_p90",
    "outbound_packet_size_p95", "outbound_packet_size_p99",
    "inbound_packet_size_p10", "inbound_packet_size_p50",
    "inbound_packet_size_p90", "inbound_packet_size_p95",
    "inbound_packet_size_p99", "burst_count", "mean_burst_packets",
    "mean_burst_duration", "burst_packet_ratio", "burst_count_10ms",
    "mean_burst_packets_10ms", "burst_count_50ms", "mean_burst_packets_50ms",
    "burst_count_200ms", "mean_burst_packets_200ms", "ike_packet_count",
    "ike_datagram_bytes", "ike_min_packet_size", "ike_max_packet_size",
    "ike_mean_packet_size",
]

# Authoritative snapshot: dataset_artifacts ``INT_FEATURES`` (17 int32).
INT_FEATURES = frozenset({
    "packet_count", "total_bytes", "min_packet_size", "max_packet_size",
    "unique_packet_size_count", "outbound_packet_count", "inbound_packet_count",
    "outbound_bytes", "inbound_bytes", "burst_count", "burst_count_10ms",
    "burst_count_50ms", "burst_count_200ms", "ike_packet_count",
    "ike_datagram_bytes", "ike_min_packet_size", "ike_max_packet_size",
})

FLOAT_FEATURES = frozenset(FEATURE_COLUMNS) - INT_FEATURES
assert len(FLOAT_FEATURES) + len(INT_FEATURES) == FEATURE_COUNT == len(
    FEATURE_COLUMNS
)
assert len(set(FEATURE_COLUMNS)) == FEATURE_COUNT


def canonical_feature_names() -> Tuple[str, ...]:
    return tuple(FEATURE_COLUMNS)


def canonical_int_features() -> frozenset:
    return INT_FEATURES


def canonical_float_features() -> frozenset:
    return FLOAT_FEATURES


def is_feature_name(name: str) -> bool:
    return name in set(FEATURE_COLUMNS)


def verify_authoritative_contract(sihipsec_root: str) -> Dict[str, Any]:
    """Cross-check this snapshot against the authoritative SIHPsec module.

    Read-only and dependency-free: parses ``controller/dataset_artifacts.py``
    with ``ast`` (the module itself imports heavy third-party deps such as
    ``pyarrow``, so it is never executed here) and compares the canonical
    names/order, the int/float split and the schema version. Returns a report
    dict; raises ``FeatureContractError`` on drift. Never modifies the
    reference repository.
    """
    import ast
    import os

    report = {
        "authoritative_root": sihipsec_root,
        "checked": False,
        "feature_schema_version": FEATURE_SCHEMA_VERSION,
        "feature_count": FEATURE_COUNT,
        "snapshot_matches_authoritative": None,
        "detail": "",
    }
    artifact_path = os.path.join(sihipsec_root, "controller", "dataset_artifacts.py")
    if not os.path.isfile(artifact_path):
        report["detail"] = f"authoritative module not present: {artifact_path}"
        return report
    try:
        with open(artifact_path, "r", encoding="utf-8") as fh:
            source = fh.read()
    except OSError as exc:
        report["detail"] = f"cannot read authoritative module: {exc}"
        return report
    try:
        tree = ast.parse(source, filename=artifact_path)
    except SyntaxError as exc:
        report["detail"] = f"authoritative module could not be parsed: {exc}"
        return report

    auth_names = ()
    auth_int = frozenset()
    auth_version = None
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        for target in node.targets:
            name = getattr(target, "id", None)
            if name == "FEATURE_COLUMNS":
                try:
                    auth_names = tuple(ast.literal_eval(node.value))
                except Exception:
                    auth_names = ()
            elif name == "INT_FEATURES":
                try:
                    value = node.value
                    if isinstance(value, ast.Call) and getattr(value.func, "id", None) == "frozenset":
                        auth_int = frozenset(ast.literal_eval(value.args[0]))
                    else:
                        auth_int = frozenset(ast.literal_eval(value))
                except Exception:
                    auth_int = frozenset()
            elif name == "FEATURE_SCHEMA_VERSION":
                try:
                    auth_version = ast.literal_eval(node.value)
                except Exception:
                    auth_version = None

    report["checked"] = True
    name_ok = auth_names == tuple(FEATURE_COLUMNS)
    type_ok = (frozenset(auth_names) - auth_int) == FLOAT_FEATURES
    report["authoritative_feature_schema_version"] = auth_version
    report["authoritative_feature_count"] = len(auth_names)
    report["snapshot_matches_authoritative"] = bool(
        name_ok and type_ok and auth_version == FEATURE_SCHEMA_VERSION
    )
    if report["snapshot_matches_authoritative"]:
        report["detail"] = (
            "names, order, int/float split and schema version match "
            "(AST-verified against controller/dataset_artifacts.py)"
        )
    else:
        raise FeatureContractError(
            "feature contract drift vs authoritative controller/dataset_artifacts.py: "
            f"names_match={name_ok} types_match={type_ok} version={auth_version!r}"
        )
    return report


def _bad_number(name: str, value: Any) -> str:
    if isinstance(value, bool):
        return f"{name}: bool is not a numeric feature "
        "value (authoritative int32/double columns)"
    if isinstance(value, str):
        return f"{name}: string {value!r} is not a numeric feature value"
    if value is None:
        return f"{name}: missing value is never filled with a default"
    return f"{name}: non-numeric value {value!r}"


def normalize_feature_values(features: Dict[str, Any]) -> Dict[str, float]:
    """Normalize the 59 feature VALUES exactly like the authoritative pipeline.

    Mirrors ``controller/dataset_artifacts.normalize_feature_record``:

    * INT columns accept ``int`` or a finite float with an integer value and
      are cast to ``int`` (authority ``_require_int``);
    * FLOAT columns accept int/float (cast to float); non-finite rejected
      (authority ``_require_float``);
    * bool/str/None are NEVER coerced, missing/extra keys are NEVER patched.

    Returns a fresh, deterministically-typed dict in canonical key order.
    """
    if not isinstance(features, dict):
        raise FeatureContractError("features must be a dict")
    keys = set(features.keys())
    canonical = set(FEATURE_COLUMNS)
    missing = sorted(canonical - keys)
    if missing:
        raise FeatureContractError(
            f"missing {len(missing)} required features: {missing}"
        )
    extra = sorted(keys - canonical)
    if extra:
        raise FeatureContractError(
            f"extra unknown features present (schema drift; expected exactly "
            f"{FEATURE_COUNT} canonical keys, nothing more): {extra}"
        )
    normalized: Dict[str, float] = {}
    for name in FEATURE_COLUMNS:
        value = features[name]
        if isinstance(value, bool):
            raise FeatureContractError(_bad_number(name, value))
        if isinstance(value, str) or value is None:
            raise FeatureContractError(_bad_number(name, value))
        if not isinstance(value, (int, float)):
            raise FeatureContractError(_bad_number(name, value))
        if isinstance(value, float) and (math.isnan(value) or math.isinf(value)):
            raise FeatureContractError(
                f"{name}: non-finite value {value!r} (NaN/inf rejected)"
            )
        if name in INT_FEATURES:
            if isinstance(value, float):
                if not value.is_integer():
                    raise FeatureContractError(
                        f"{name}: float {value!r} is not an integer; INT columns "
                        "require an int or a float with an integer value "
                        "(authority _require_int)"
                    )
                value = int(value)
        else:
            value = float(value)
        normalized[name] = value
    return normalized


def validate_feature_values(features: Dict[str, Any]) -> None:
    """Validate the 59 feature VALUES only (no values are ever filled in)."""
    normalize_feature_values(features)


def validate_feature_window(window: Union[LiveFeatureWindow, Dict[str, Any]]) -> None:
    """Fail-fast validation against the v2 contract.

    Accepts a ``LiveFeatureWindow`` or the RAW live record dict produced by
    ``controller/live_features.py`` (``{"feature_schema_version": "v2",
    "window_start_ns":..., "window_end_ns":..., "features": {...}}``).
    Deterministic: the first problem found is reported with a precise reason.
    """
    if isinstance(window, LiveFeatureWindow):
        version = window.feature_schema_version
        features = window.features
    elif isinstance(window, dict):
        version = window.get("feature_schema_version")
        features = window.get("features")
        if not isinstance(features, dict):
            raise FeatureContractError(
                "live record features must be a dict"
            )
    else:
        raise FeatureContractError(
            f"expected LiveFeatureWindow or live record dict, got "
            f"{type(window).__name__}"
        )
    if version != FEATURE_SCHEMA_VERSION:
        raise FeatureContractError(
            f"feature_schema_version must be {FEATURE_SCHEMA_VERSION!r}, "
            f"got {version!r}"
        )
    validate_feature_values(features)


def feature_vector(window: LiveFeatureWindow) -> List[float]:
    """Build the model input vector in the canonical fixed column order.

    Ordering is EXPLICIT: always ``FEATURE_COLUMNS`` order regardless of the
    dict's key insertion order, and the model artifact re-validates the same
    order at load time. Values are normalized (authority ``_require_int`` /
    ``_require_float`` typing) and cast to float for the vector; malformed
    values already failed validation.
    """
    normalized = normalize_feature_values(window.features)
    return [float(normalized[name]) for name in FEATURE_COLUMNS]