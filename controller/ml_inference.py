"""Live 100-ms window -> ML inference adapter.

Connects the live feature bridge (``controller/live_features.py``, exact-v2
records) to the trained traffic Random Forest without modifying either side.
A live v2 record produced by :class:`LiveFeatureExtractor` is validated,
reduced to the 57-feature vector the estimator was trained on (in the exact
order of ``results/ml/feature_schema_v2.json``), passed through
``estimator.predict_proba``, and serialized as a machine-readable ML result.

Pipeline
--------
    XDP events -> 100 ms window aggregator -> LiveFeatureExtractor
              -> exact-v2 record (59 features)
              -> ml_inference.predict()  (validated 57, canonical order)
              -> ML result JSONL

Input contract (one JSONL object, from the live pipeline)::

    {"feature_schema_version": "v2", "window_start_ns": ...,
     "window_end_ns": ..., "features": {59 columns}}

ML result contract (one JSONL object)::

    {"model_version": "traffic_rf_v1",
     "feature_schema_version": "v2",
     "window_id": "<window_start_ns>-<window_end_ns>",
     "timestamp": "<UTC ISO-8601 generation time>",
     "traffic_profile": "<one of voip|video|messaging|email|web|icmp>",
     "probabilities": {"voip": ..., "video": ..., "messaging": ...,
                       "email": ..., "web": ..., "icmp": ...}}

Feature-set rule
----------------
The ML vector is *exactly* 57 features in the order of
``results/ml/feature_schema_v2.json``.  The live record carries 59 columns:
the 57 ML features plus the two verified constants ``burst_packet_ratio`` and
``ike_packet_count`` (constant 1.0 / 4 across all 300 protected samples).  The
adapter drops those two names only after verifying the record matches the full
59-column v2 schema (``assert_feature_keys``); a bare feature mapping is
accepted directly and must be exactly the 57 ML features.  In every case the
57-feature strict contract is enforced: missing, extra, duplicate or unknown
feature names and NaN/inf/non-numeric (or bool) values are rejected with a
:class:`ValueError` -- never silently repaired.

Timestamp provenance
--------------------
The live window geometry (``window_start_ns`` / ``window_end_ns``) is
kernel-monotonic, not wall-clock, so no wall-clock time is recovered from the
window bounds.  ``timestamp`` is the UTC wall-clock time the ML result was
generated; ``window_id`` preserves the window identity from the live pipeline.

SHAP is observational and on-demand only (``--explain`` / :func:`explain`);
it never changes the classification outputs (asserted by the accompanying
non-interference flag and by ``controller/test_ml_inference.py``).
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import numbers
import sys
from collections.abc import Mapping
from functools import lru_cache
from pathlib import Path

import numpy as np

from controller import dataset_loader
from controller.dataset_artifacts import (
    FEATURE_SCHEMA_VERSION,
    assert_feature_keys,
)
from controller.evaluate_model import MODEL_PATH, load_artifact
from ebpf.xdp_window_aggregator import WINDOW_SIZE_MS, iter_jsonl_events

RESULTS_ML = Path("results") / "ml"
FEATURE_SCHEMA_PATH = RESULTS_ML / "feature_schema_v2.json"

#: Logical model version reported in every ML result (path stem suffix).
MODEL_VERSION = "traffic_rf_v1"

#: Fields of the live v2 record that sit outside the feature dict.
_LIVE_METADATA_FIELDS = ("feature_schema_version", "window_start_ns",
                         "window_end_ns")


@lru_cache(maxsize=1)
def feature_order() -> tuple[str, ...]:
    """Authoritative 57-feature order from ``results/ml/feature_schema_v2.json``.

    Guards: the schema file must declare 59 features (v2) minus the two
    documented constants, contain no duplicates, and agree with the loader's
    canonical order.
    """
    if not FEATURE_SCHEMA_PATH.is_file():
        raise FileNotFoundError(f"feature schema missing: {FEATURE_SCHEMA_PATH}")
    schema = json.loads(FEATURE_SCHEMA_PATH.read_text(encoding="utf-8"))
    order = tuple(schema["used_features"])
    if len(order) != 57:
        raise ValueError(
            f"feature_schema_v2.json used_features has {len(order)} entries, "
            f"expected 57"
        )
    if len(set(order)) != len(order):
        raise ValueError("feature_schema_v2.json used_features contains duplicates")
    declared = schema.get("declared_features")
    if declared not in (None, 59):
        raise ValueError(f"schema declared_features={declared!r}, expected 59")
    removed = tuple(schema.get("constant_features_removed", ()))
    if removed != dataset_loader.CONSTANT_FEATURES:
        raise ValueError(
            "schema constant_features_removed disagrees with "
            f"dataset_loader.CONSTANT_FEATURES ({removed!r})"
        )
    loader_order = tuple(dataset_loader.feature_names())
    if order != loader_order:
        raise ValueError(
            "feature_schema_v2.json order disagrees with "
            "dataset_loader.feature_names()"
        )
    return order


def validate_artifact(artifact: dict) -> None:
    """Fail if the model artifact no longer matches the schema/order contract."""
    order = feature_order()
    required = (
        "estimator", "feature_names", "feature_schema_version",
        "target_classes", "label_encoder", "split_artifact", "split_hash",
        "input_fingerprints", "metadata",
    )
    missing = [k for k in required if k not in artifact]
    if missing:
        raise ValueError(f"model artifact missing keys: {missing}")
    if artifact["feature_schema_version"] != FEATURE_SCHEMA_VERSION:
        raise ValueError(
            "model artifact feature_schema_version "
            f"{artifact['feature_schema_version']!r}, expected "
            f"{FEATURE_SCHEMA_VERSION!r}"
        )
    if list(artifact["feature_names"]) != list(order):
        raise ValueError(
            "model artifact feature_names disagree with feature_schema_v2.json"
        )
    if getattr(artifact["estimator"], "n_features_in_", None) != 57:
        raise ValueError(
            f"estimator expects {artifact['estimator'].n_features_in_} features, "
            f"expected 57"
        )
    classes = tuple(artifact["target_classes"])
    if classes != dataset_loader.TARGET_CLASSES:
        raise ValueError(
            f"model artifact target_classes {classes!r}, expected "
            f"{dataset_loader.TARGET_CLASSES!r}"
        )
    expected_mapping = {c: i for i, c in enumerate(classes)}
    if dict(artifact["label_encoder"]) != expected_mapping:
        raise ValueError(
            "model artifact label_encoder does not match target_classes order"
        )


@lru_cache(maxsize=1)
def model_provenance() -> dict:
    """Deterministic provenance of the committed RF artifact itself.

    ``train_report.json`` already records the artifact digest, but that record
    is not carried by a live result, so a result naming only
    ``model_version`` cannot be tied to a specific file.  This surfaces the
    digest of the artifact actually loaded plus the training facts the artifact
    already carries, so every result is traceable to one exact file.  Cached:
    the digest is computed once per process.
    """
    digest = hashlib.sha256(MODEL_PATH.read_bytes()).hexdigest()
    metadata = dict(load_artifact(MODEL_PATH).get("metadata") or {})
    return {
        "model_artifact_sha256": digest,
        "model_trained_git_commit": str(metadata.get("git_commit") or "") or None,
        "model_training_datasets": [
            str(run_id) for run_id in (metadata.get("dataset_run_ids") or ())
        ],
        "model_trained_at": str(metadata.get("created_at") or "") or None,
    }


def _is_finite_number(value) -> bool:
    if isinstance(value, bool) or not isinstance(value, numbers.Number):
        return False
    try:
        return bool(np.isfinite(float(value)))
    except (ValueError, OverflowError, TypeError):
        return False


def validate_features(features) -> dict:
    """Strictly validate the 57 ML features and return a canonical dict.

    ``features`` may be a Mapping or a sequence of ``(name, value)`` pairs
    (pair input is how duplicate names can be detected).  The 57-feature
    contract is enforced exactly: count, set, names, and every value must be a
    finite number.  Returns ``{name: value}`` keyed in canonical order.
    """
    order = feature_order()
    if isinstance(features, Mapping):
        items = list(features.items())
    elif isinstance(features, (list, tuple)):
        items = list(features)
        if not all(
            isinstance(i, (list, tuple)) and len(i) == 2 for i in items
        ):
            raise ValueError("feature sequence must be (name, value) pairs")
    else:
        raise ValueError(
            "features must be a mapping or a sequence of (name, value) pairs"
        )

    if len(items) != len(order):
        raise ValueError(
            f"expected exactly {len(order)} features, got {len(items)}"
        )
    names = [str(k) for k, _ in items]
    if len(set(names)) != len(names):
        duplicates = sorted({n for n in names if names.count(n) > 1})
        raise ValueError(f"duplicate feature names: {duplicates}")
    missing = sorted(set(order) - set(names))
    extra = sorted(set(names) - set(order))
    if missing or extra:
        raise ValueError(
            f"feature set mismatch (missing={missing}, extra={extra})"
        )
    canonical = {}
    for name, value in items:
        if not _is_finite_number(value):
            raise ValueError(
                f"feature '{name}' value {value!r} is not a finite number"
            )
        canonical[str(name)] = value
    return {name: canonical[name] for name in order}


def vectorize(features) -> np.ndarray:
    """Build the (1, 57) float64 estimator input in canonical order."""
    canonical = validate_features(features)
    order = feature_order()
    return np.asarray(
        [canonical[name] for name in order], dtype=np.float64
    ).reshape(1, -1)


def _extract_input(record):
    """Unwrap a live v2 record or a bare 57-feature mapping.

    Returns ``(canonical_57, window_id)``.  A live record must match the full
    59-column v2 schema (``assert_feature_keys``) and its two constant columns
    are dropped before the 57-feature strict check; a bare mapping must be
    exactly the 57 ML features.
    """
    if not isinstance(record, Mapping):
        raise ValueError("record must be a mapping")
    if "features" in record:
        if record.get("feature_schema_version") != FEATURE_SCHEMA_VERSION:
            raise ValueError(
                "record feature_schema_version "
                f"{record.get('feature_schema_version')!r}, expected "
                f"{FEATURE_SCHEMA_VERSION!r}"
            )
        raw = record["features"]
        if not isinstance(raw, Mapping):
            raise ValueError("record 'features' must be a mapping")
        assert_feature_keys(raw)
        start = record.get("window_start_ns", 0)
        end = record.get("window_end_ns", 0)
        window_id = f"{start}-{end}"
        constants = set(dataset_loader.CONSTANT_FEATURES)
        items = [(k, v) for k, v in raw.items() if k not in constants]
        canonical = validate_features(items)
    else:
        canonical = validate_features(record)
        window_id = "unknown"
    return canonical, window_id


def _now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")


def predict(record, *, artifact: dict | None = None, timestamp: str | None = None) -> dict:
    """Produce the ML result for one live record (or one 57-feature mapping).

    Never mutates the model or the record; deterministic for a fixed
    ``timestamp``.
    """
    if artifact is None:
        artifact = load_artifact(MODEL_PATH)
    validate_artifact(artifact)
    features, window_id = _extract_input(record)
    vector = vectorize(features)
    proba = artifact["estimator"].predict_proba(vector)[0]
    classes = artifact["target_classes"]
    class_index = int(np.argmax(proba))
    if timestamp is None:
        timestamp = _now_iso()
    return {
        "model_version": MODEL_VERSION,
        "feature_schema_version": str(artifact["feature_schema_version"]),
        **model_provenance(),
        "window_id": window_id,
        "timestamp": timestamp,
        "traffic_profile": str(classes[class_index]),
        "probabilities": {
            str(c): float(p) for c, p in zip(classes, proba)
        },
    }


def predict_many(records, *, artifact: dict | None = None,
                 timestamp: str | None = None) -> list[dict]:
    """Batch variant of :func:`predict`: one ``predict_proba`` call for all.

    The estimator was trained with ``n_jobs=-1`` and that hyperparameter is
    frozen (never changed), so a single-sample ``predict_proba`` pays joblib's
    full pool spawn/teardown (hundreds of ms).  Scoring a set of windows in one
    call avoids that overhead entirely and returns results identical to calling
    :func:`predict` per record.  ``timestamp`` is a single generation time for
    the batch (per-record timestamps are produced by the sequential variant).
    """
    if artifact is None:
        artifact = load_artifact(MODEL_PATH)
    validate_artifact(artifact)
    if timestamp is None:
        timestamp = _now_iso()

    vectors = []
    window_ids = []
    for record in records:
        features, window_id = _extract_input(record)
        vectors.append(vectorize(features))
        window_ids.append(window_id)
    if not vectors:
        return []

    proba = artifact["estimator"].predict_proba(np.vstack(vectors))
    classes = artifact["target_classes"]
    schema_version = str(artifact["feature_schema_version"])
    provenance = model_provenance()
    results = []
    for row, window_id in zip(proba, window_ids):
        class_index = int(np.argmax(row))
        results.append({
            "model_version": MODEL_VERSION,
            "feature_schema_version": schema_version,
            **provenance,
            "window_id": window_id,
            "timestamp": timestamp,
            "traffic_profile": str(classes[class_index]),
            "probabilities": {
                str(c): float(p) for c, p in zip(classes, row)
            },
        })
    return results


def explain(record, *, artifact: dict | None = None, top_k: int = 10) -> dict:
    """On-demand observational SHAP explanation for the predicted class.

    Requested explicitly per result (never run implicitly per window).  The
    returned ``non_interference`` block reports whether predictions and
    probabilities were byte-identical before and after the explanation.
    """
    import shap

    from controller.shap_analysis import normalize_class_arrays

    if artifact is None:
        artifact = load_artifact(MODEL_PATH)
    validate_artifact(artifact)
    features, window_id = _extract_input(record)
    vector = vectorize(features)
    estimator = artifact["estimator"]
    classes = artifact["target_classes"]
    proba_before = estimator.predict_proba(vector)
    class_index = int(np.argmax(proba_before[0]))

    explainer = shap.TreeExplainer(estimator, feature_names=list(feature_order()))
    raw = explainer.shap_values(vector)
    class_arrays, representation = normalize_class_arrays(
        raw, len(classes), 1, len(feature_order())
    )
    values = class_arrays[class_index][0]
    ranked = sorted(
        zip(feature_order(), values.tolist()), key=lambda kv: -abs(kv[1])
    )
    top = [
        {"feature": name, "shap_value": float(value)}
        for name, value in ranked[:max(1, top_k)]
    ]

    proba_after = estimator.predict_proba(vector)
    non_interference = {
        "predictions_equal": bool(
            int(np.argmax(proba_after[0])) == class_index
        ),
        "probabilities_equal": bool(np.array_equal(proba_before, proba_after)),
    }
    return {
        "model_version": MODEL_VERSION,
        "feature_schema_version": str(artifact["feature_schema_version"]),
        **model_provenance(),
        "window_id": window_id,
        "traffic_profile": str(classes[class_index]),
        "n_features": len(feature_order()),
        "shap_representation": representation,
        "top_features": top,
        "non_interference": non_interference,
        "note": "observational and on-demand; model outputs are unchanged",
    }


def iter_window_records(events, *, capture_ip=None, window_ms: int = WINDOW_SIZE_MS):
    """Group an event stream into per-100 ms live records (live sensor shape).

    Each aligned ``window_ms``-bucket seen in the stream yields one exact-v2
    record, exactly as the live window aggregator + extractor would emit it.
    ``events`` may yield :class:`PacketEvent` objects (from the live reader /
    ``iter_jsonl_events``) or plain event dicts.
    """
    from controller.live_features import LiveFeatureExtractor

    def ts_of(event) -> int:
        return int(event.ts if hasattr(event, "ts") else event["ts"])

    window_ns = window_ms * 1_000_000
    buckets: dict[int, list] = {}
    for event in events:
        key = ts_of(event) // window_ns
        buckets.setdefault(key, []).append(event)
    for key in sorted(buckets):
        extractor = LiveFeatureExtractor(capture_ip=capture_ip, window_ms=window_ms)
        for event in buckets[key]:
            if isinstance(event, Mapping):
                extractor.accept_dict(event)
            else:
                extractor.accept(event)
        yield extractor.snapshot()


def main(argv: list | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Live 100-ms feature records -> ML results (JSONL)."
    )
    source = parser.add_mutually_exclusive_group()
    source.add_argument(
        "--events", default=None,
        help="JSONL XDP event input; bucket into 100-ms windows first",
    )
    source.add_argument(
        "--records", default="-",
        help="JSONL exact-v2 feature-record input ('-' = stdin)",
    )
    parser.add_argument(
        "--output", default="-",
        help="JSONL ML-result output ('-' = stdout)",
    )
    parser.add_argument(
        "--capture-ip", default=None,
        help="capture-point WAN address (direction anchor for --events)",
    )
    parser.add_argument(
        "--nominal-duration", type=float, default=None,
        help="reuse offline densest-window logic for --events (seconds)",
    )
    parser.add_argument(
        "--window-ms", type=int, default=WINDOW_SIZE_MS,
        help="window size for --events batching (ms)",
    )
    parser.add_argument(
        "--explain", action="store_true",
        help="attach an on-demand SHAP explanation to every result",
    )
    args = parser.parse_args(argv)

    artifact = load_artifact(MODEL_PATH)
    validate_artifact(artifact)
    order = feature_order()

    if args.events is not None:
        in_stream = open(args.events, "r")
        records = list(iter_window_records(
            iter_jsonl_events(in_stream),
            capture_ip=args.capture_ip,
            window_ms=args.window_ms,
        ))
        results = predict_many(records, artifact=artifact)
        if args.explain:
            results = [
                dict(r, explanation=explain(rec, artifact=artifact))
                for r, rec in zip(results, records)
            ]
    else:
        in_stream = sys.stdin if args.records == "-" else open(args.records, "r")

        def results_gen():
            for line in in_stream:
                if not line.strip():
                    continue
                record = json.loads(line)
                result = predict(record, artifact=artifact)
                if args.explain:
                    result["explanation"] = explain(record, artifact=artifact)
                yield result

        results = results_gen()

    out_stream = sys.stdout if args.output == "-" else open(args.output, "w")
    emitted = 0
    try:
        for result in results:
            out_stream.write(json.dumps(result, separators=(",", ":")) + "\n")
            emitted += 1
    finally:
        if args.events is not None or args.records != "-":
            in_stream.close()
        if args.output != "-":
            out_stream.close()
        print(
            f"ml-inference: results_emitted={emitted} model={MODEL_VERSION} "
            f"schema={FEATURE_SCHEMA_VERSION} features={len(order)}",
            file=sys.stderr,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())