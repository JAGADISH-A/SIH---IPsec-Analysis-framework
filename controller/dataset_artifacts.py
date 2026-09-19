"""Successful-sample artifact collection and finalization (Module 5).

Conceptual pipeline that this module implements:

    Module 3/4 execution
        -> SUCCESSFUL sample (IPsec + connectivity + traffic + capture +
                             feature extraction all verified)
        -> Module 5 artifact collector
        -> staging/successful_samples.jsonl   (append-safe, durable source)
        -> finalization (validate + materialize)
        -> features.parquet
        -> metadata.jsonl
        -> captures/<sequence>/<experiment_id>.pcap   (evidence)

Only samples the execution engine has *committed* may ever enter the final ML
dataset.  Failed, interrupted, partial, abandoned or uncommitted attempts are
never staged as successful.

Data contract (all documented again in SCHEMA.md)
--------------------------------------------------
``dataset_schema_version = "v1"``.  The feature table is the 59-column output
of ``controller/features.py`` (the feature extraction authority) at
``feature_schema_version = "v2"``.  Every column must be obtainable from the
live WAN-side XDP event stream as well as from a training PCAP; the IKE
exchange-type and observed-version columns (``ike_sa_init_count``,
``ike_auth_count``, ``ike_create_child_sa_count``, ``ike_informational_count``,
``ike_version``) were removed in v2 for exactly that reason (the live sensor
classifies IKE by transport port but does not parse the IKE header).  The
schema is declared explicitly here -- it must never "emerge" from whatever
dictionary the extractor happens to return.  ``assert_feature_keys()``
cross-checks the declared feature columns against the live extractor so drift
is caught.

Collection / commit boundary
----------------------------
The collector runs *inside* the execution engine's commit path (``collector_fn``
in ``execute_dataset_run``): a sample is only counted as successful after its
dataset artifacts (staged record + PCAP evidence) have been safely persisted.
If artifact persistence fails, the engine treats the attempt as FAILED (Module
4 semantics) and never commits the logical sequence.  Collection is opt-in at
the engine API level (``collector_fn=None`` keeps the Module 3/4 behaviour
unchanged); the CLI wires it for real runs.

Staging / finalization
----------------------
``staging/successful_samples.jsonl`` is appended (with fsync) one JSON object
per committed successful sample and is the durable source of truth for
materialization.  Finalization re-validates every Module 5 consistency
invariant (counts, uniqueness, ground-truth posture/profile/configuration,
plan fingerprint, PCAP references, schema consistency) and only then writes
``features.parquet`` (atomic tmp + replace) and ``metadata.jsonl`` (atomic).
The artifact-finalization status is recorded in ``finalization.json`` and is
separate from the engine-run status in ``state.json``.

The Parquet file is never used as an append log and is never rewritten per
sample: it is produced once, atomically, from staging at finalization time.

No experiment is executed by anything in this module, and no security /
confidentiality score is computed here.
"""

import json
import math
import os
import shutil
import zipfile
from collections import Counter
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq

from . import dataset_run as dataset_run_mod
from .dataset_executor import (
    OUTCOME_SUCCESS,
    STATUS_COMPLETED,
    load_plan,
    parse_experiment_id,
    plan_fingerprint,
    validate_runtime_state,
)

SCHEMA_VERSION = "v1"             # dataset artifact schema version
FEATURE_SCHEMA_VERSION = "v2"     # feature-record schema version
SUCCESS_LABEL = "SUCCESS"

SUCCESSFUL_SAMPLES_FILENAME = "successful_samples.jsonl"
ORPHAN_STAGING_FILENAME = "staging-orphans.jsonl"
METADATA_FILENAME = "metadata.jsonl"
FEATURES_PARQUET_FILENAME = "features.parquet"
FINALIZATION_FILENAME = "finalization.json"
RUN_README_FILENAME = "README.txt"
CAPTURES_SUBDIR = "captures"
STAGING_SUBDIR = "staging"

# The final downloadable dataset artifact: the materialized run directory.
# Per-sample evidence directories (captures/, experiments/, failures/) are
# provenance, not part of the final artifact, so they are never exported.
EXPORT_ARTIFACT_FILENAMES = (
    FEATURES_PARQUET_FILENAME,      # Module 5 materialized feature table
    METADATA_FILENAME,              # Module 5 materialized metadata records
    dataset_run_mod.MANIFEST_FILENAME,   # Module 1 derived run summary
    RUN_README_FILENAME,            # Module 5 run-level documentation
)

# ---------------------------------------------------------------------------
# Feature schema (v2) -- the 59 columns produced by controller/features.py.
# Every column is obtainable from the live WAN-side XDP event stream (per-
# event ts/src/dst/len/type/ports) as well as from a training PCAP.  v2
# removed the five IKE exchange-type / observed-version columns of v1 because
# the live sensor never parses the IKE header.
# Types are the source-of-truth extractor types for real captures.
# ---------------------------------------------------------------------------

FEATURE_COLUMNS = [
    "packet_count",                    # int  : number of ESP frames observed
    "total_bytes",                     # int  : sum of ESP outer-IP lengths
    "mean_packet_size",                # float: mean frame size (bytes)
    "packet_size_std",                 # float: stdev of frame sizes (bytes)
    "min_packet_size",                 # int  : smallest frame (bytes)
    "max_packet_size",                 # int  : largest frame (bytes)
    "packet_size_p10",                 # float: 10th percentile size (bytes)
    "packet_size_p50",                 # float: 50th percentile size (bytes)
    "packet_size_p90",                 # float: 90th percentile size (bytes)
    "packet_size_p95",                 # float: 95th percentile size (bytes)
    "packet_size_p99",                 # float: 99th percentile size (bytes)
    "unique_packet_size_count",        # int  : distinct observed sizes
    "packet_size_entropy",             # float: Shannon entropy of sizes (bits)
    "small_packet_ratio",              # float: fraction <= small threshold
    "large_packet_ratio",              # float: fraction > large threshold
    "mean_inter_arrival_time",         # float: mean inter-arrival gap (s)
    "inter_arrival_time_std",          # float: stdev of inter-arrival gaps (s)
    "min_inter_arrival_time",          # float: smallest gap (s)
    "max_inter_arrival_time",          # float: largest gap (s)
    "packets_per_second",              # float: frame rate (1/s)
    "bytes_per_second",                # float: throughput (bytes/s)
    "flow_duration",                   # float: capture window duration (s)
    "outbound_packet_count",           # int  : frames leaving the capture point
    "inbound_packet_count",            # int  : frames entering the capture point
    "outbound_bytes",                  # int  : outbound bytes
    "inbound_bytes",                   # int  : inbound bytes
    "outbound_packet_ratio",           # float: outbound frame share (0..1)
    "inbound_packet_ratio",            # float: inbound frame share (0..1)
    "outbound_byte_ratio",             # float: outbound byte share (0..1)
    "inbound_byte_ratio",              # float: inbound byte share (0..1)
    "outbound_mean_packet_size",       # float: mean outbound size (bytes)
    "inbound_mean_packet_size",        # float: mean inbound size (bytes)
    "outbound_packets_per_second",     # float: outbound frame rate (1/s)
    "inbound_packets_per_second",      # float: inbound frame rate (1/s)
    "outbound_packet_size_p10",        # float: 10th pct outbound size (bytes)
    "outbound_packet_size_p50",        # float: 50th pct outbound size (bytes)
    "outbound_packet_size_p90",        # float: 90th pct outbound size (bytes)
    "outbound_packet_size_p95",        # float: 95th pct outbound size (bytes)
    "outbound_packet_size_p99",        # float: 99th pct outbound size (bytes)
    "inbound_packet_size_p10",         # float: 10th pct inbound size (bytes)
    "inbound_packet_size_p50",         # float: 50th pct inbound size (bytes)
    "inbound_packet_size_p90",         # float: 90th pct inbound size (bytes)
    "inbound_packet_size_p95",         # float: 95th pct inbound size (bytes)
    "inbound_packet_size_p99",         # float: 99th pct inbound size (bytes)
    "burst_count",                     # int  : bursts in the default window
    "mean_burst_packets",              # float: mean packets per burst
    "mean_burst_duration",             # float: mean burst length (s)
    "burst_packet_ratio",              # float: share of frames inside bursts
    "burst_count_10ms",                # int  : bursts gated at 10 ms
    "mean_burst_packets_10ms",         # float: mean burst size (10 ms gate)
    "burst_count_50ms",                # int  : bursts gated at 50 ms
    "mean_burst_packets_50ms",         # float: mean burst size (50 ms gate)
    "burst_count_200ms",               # int  : bursts gated at 200 ms
    "mean_burst_packets_200ms",        # float: mean burst size (200 ms gate)
    "ike_packet_count",                # int  : IKE frames (UDP 500/4500)
    "ike_datagram_bytes",              # int  : total IKE datagram bytes
    "ike_min_packet_size",             # int  : smallest IKE frame (bytes)
    "ike_max_packet_size",             # int  : largest IKE frame (bytes)
    "ike_mean_packet_size",            # float: mean IKE frame size (bytes)
]

# NOTE: feature_schema_version v1 also carried ike_version and the four
# per-exchange-type counts (ike_sa_init/auth/create_child_sa/informational).
# They are not reproducible by the live XDP feed (which classifies IKE by
# port only), so v2 removes them from the ML feature vector.

INT_FEATURES = frozenset({
    "packet_count", "total_bytes", "min_packet_size", "max_packet_size",
    "unique_packet_size_count",
    "outbound_packet_count", "inbound_packet_count",
    "outbound_bytes", "inbound_bytes",
    "burst_count", "burst_count_10ms", "burst_count_50ms",
    "burst_count_200ms",
    "ike_packet_count", "ike_datagram_bytes",
    "ike_min_packet_size", "ike_max_packet_size",
})

FLOAT_FEATURES = frozenset(FEATURE_COLUMNS) - INT_FEATURES
FEATURE_KEYS = frozenset(FEATURE_COLUMNS)

# ---------------------------------------------------------------------------
# Parquet layout: linkage / ground-truth columns followed by the feature
# columns.  Every row is traceable back to its metadata record and PCAP.
# ---------------------------------------------------------------------------

PARQUET_ID_COLUMNS = [
    ("dataset_run_id", pa.string()),
    ("sequence", pa.int32()),
    ("experiment_id", pa.string()),
    ("attempt_number", pa.int32()),
    ("traffic_profile", pa.string()),
    ("security_posture", pa.string()),
    ("configuration_id", pa.string()),
    ("captured_at", pa.string()),
    ("pcap_path", pa.string()),
    ("feature_schema_version", pa.string()),
]

PARQUET_SCHEMA = pa.schema(PARQUET_ID_COLUMNS + [
    (name, pa.int32() if name in INT_FEATURES else pa.float64())
    for name in FEATURE_COLUMNS
])
PARQUET_COLUMNS = [field.name for field in PARQUET_SCHEMA]

# Full metadata schema of one staged / finalized successful sample record.
METADATA_REQUIRED_KEYS = [
    "dataset_schema_version", "feature_schema_version", "status",
    "dataset_run_id", "sequence", "experiment_id", "attempt_number",
    "traffic_profile", "security_posture", "configuration_id",
    "mode", "address_family", "ike_version", "ike_encryption",
    "ike_integrity", "ike_dh_group", "esp_encryption", "esp_integrity",
    "esp_dh_group", "pfs", "ipsec_configuration",
    "captured_at", "pcap_path", "features",
]

FLATTENED_CONFIG_KEYS = {
    "mode", "address_family", "ike_version", "ike_encryption",
    "ike_integrity", "ike_dh_group", "esp_encryption", "esp_integrity",
    "esp_dh_group", "pfs",
}


def assert_feature_keys(features):
    """Fail if a feature dict does not match the declared v2 feature schema."""
    observed = set(features)
    if observed != FEATURE_KEYS:
        missing = sorted(FEATURE_KEYS - observed)
        extra = sorted(observed - FEATURE_KEYS)
        raise ValueError(
            f"feature record does not match schema v2 "
            f"(missing={missing}, extra={extra})"
        )


def reference_feature_record():
    """Canonical (all-zero) feature record produced by the live extractor.

    Derived by running features.py on an empty but well-formed PCAP.  Used to
    self-check the declared schema against the extractor and to build
    synthetic records in tests.  Never fabricates production feature values.
    """
    import struct
    import tempfile
    from . import features as features_mod

    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as fh:
        fh.write(b"\xd4\xc3\xb2\xa1" + struct.pack("<HHIIII", 2, 4, 0, 0, 0, 65535))
        path = fh.name
    try:
        record = features_mod.extract_features(
            path, capture_ip="192.168.100.1", nominal_duration=30.0
        )
    finally:
        os.unlink(path)
    return record


def utcnow_iso():
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Atomic / durable staging primitives
# ---------------------------------------------------------------------------

def read_staging(run):
    """Return the list of staged successful-sample records (in append order).

    Raises ValueError if any line is not valid JSON, so a corrupt staging log
    can never silently pass finalization.
    """
    path = run.directory / STAGING_SUBDIR / SUCCESSFUL_SAMPLES_FILENAME
    if not path.exists():
        return []
    records = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(
                f"corrupt staging record (line {number} in "
                f"{SUCCESSFUL_SAMPLES_FILENAME}): {exc}"
            )
        if not isinstance(record, dict):
            raise ValueError(
                f"corrupt staging record (line {number}): not a JSON object"
            )
        records.append(record)
    return records


def _append_staged_record(run, record):
    path = run.directory / STAGING_SUBDIR / SUCCESSFUL_SAMPLES_FILENAME
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, sort_keys=True) + "\n")
        fh.flush()
        os.fsync(fh.fileno())


def _rewrite_staging_without(run, experiment_id):
    """Remove one stale record from the staging log (rewrite, atomic)."""
    staging_path = run.directory / STAGING_SUBDIR / SUCCESSFUL_SAMPLES_FILENAME
    records = [r for r in read_staging(run) if r["experiment_id"] != experiment_id]
    text = "".join(
        json.dumps(record, sort_keys=True) + "\n" for record in records
    )
    tmp = staging_path.with_suffix(staging_path.suffix + ".tmp")
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write(text)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, staging_path)


def _archive_orphan_staged_record(run, record, log):
    """Report and archive a staging record with no committed backing sample."""
    log = log or (lambda msg: None)
    log(
        f"[artifacts] orphaned staging record for sequence "
        f"{record['sequence']} ({record['experiment_id']}) never committed; "
        f"archiving before re-staging"
    )
    archive_path = run.directory / STAGING_SUBDIR / ORPHAN_STAGING_FILENAME
    with open(archive_path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, sort_keys=True) + "\n")
        fh.flush()
        os.fsync(fh.fileno())
    _rewrite_staging_without(run, record["experiment_id"])


# ---------------------------------------------------------------------------
# Feature record normalization
# ---------------------------------------------------------------------------

def _require_int(value, column):
    if isinstance(value, bool):
        raise ValueError(f"feature '{column}': boolean where integer expected")
    if isinstance(value, int):
        return value
    if isinstance(value, float) and math.isfinite(value) and value.is_integer():
        return int(value)
    raise ValueError(
        f"feature '{column}': value {value!r} is not a valid integer"
    )


def _require_float(value, column):
    if isinstance(value, bool):
        raise ValueError(f"feature '{column}': boolean where real number expected")
    if isinstance(value, int):
        return float(value)
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError(f"feature '{column}': non-finite value {value!r}")
        return float(value)
    raise ValueError(
        f"feature '{column}': value {value!r} is not a valid real number"
    )


def normalize_feature_record(features):
    """Coerce a feature dict into the canonical v2 schema.

    Enforces the exact feature-set (no missing / extra columns) and the exact
    per-column type.  Strings are never silently coerced into numbers: a mixed
    int/float/string corrupt record is rejected, not "fixed".
    """
    if not isinstance(features, dict):
        raise ValueError("features must be a dict")
    assert_feature_keys(features)
    normalized = {}
    for column in FEATURE_COLUMNS:
        value = features[column]
        if column in INT_FEATURES:
            normalized[column] = _require_int(value, column)
        else:
            normalized[column] = _require_float(value, column)
    return normalized


# ---------------------------------------------------------------------------
# Metadata / ground-truth building
# ---------------------------------------------------------------------------

def flatten_config(config):
    """Flatten one validated ``ipsec_configuration`` dict to flat fields."""
    return {
        "mode": config["mode"],
        "address_family": config["address_family"],
        "ike_version": config["ike"]["version"],
        "ike_encryption": config["ike"]["encryption"],
        "ike_integrity": config["ike"]["integrity"],
        "ike_dh_group": config["ike"]["dh_group"],
        "esp_encryption": config["esp"]["encryption"],
        "esp_integrity": config["esp"]["integrity"],
        "esp_dh_group": config["esp"]["dh_group"],
        "pfs": config["esp"]["pfs"],
    }


def build_successful_record(run, sample, experiment_id, attempt, outcome,
                            pcap_path):
    """Build the full metadata record for one committed successful sample.

    Ground truth (security_posture, traffic_profile, configuration_id and the
    full ipsec_configuration) comes from the Module 2 plan sample -- never
    recalculated and never derived from traffic characteristics.  The feature
    values come from the outcome returned by the execution engine.
    """
    config = sample["ipsec_configuration"]
    timestamp = None
    traffic_model = None
    metadata = outcome.get("metadata")
    if isinstance(metadata, dict):
        timestamp = metadata.get("timestamp")
        traffic_model = metadata.get("traffic_model")
    record = {
        "dataset_schema_version": SCHEMA_VERSION,
        "feature_schema_version": FEATURE_SCHEMA_VERSION,
        "status": SUCCESS_LABEL,
        "dataset_run_id": run.id,
        "sequence": sample["sequence"],
        "experiment_id": experiment_id,
        "attempt_number": attempt,
        "traffic_profile": sample["traffic_profile"],
        "security_posture": sample["security_posture"],
        "configuration_id": sample["configuration_id"],
        **flatten_config(config),
        "ipsec_configuration": config,
        "captured_at": timestamp or utcnow_iso(),
        "pcap_path": pcap_path,
        "features": normalize_feature_record(outcome["features"]),
    }
    if traffic_model is not None:
        record["traffic_model"] = traffic_model
    return record


def _committed_experiment_by_sequence(run):
    mapping = {}
    for exp_id in run.data["committed_run_ids"]:
        parsed = parse_experiment_id(exp_id)
        if parsed is not None:
            mapping[parsed[1]] = exp_id
    return mapping


def collect_successful_sample(run, experiment_id, attempt, sample, outcome,
                              log=None):
    """Stage one committed successful sample (idempotent, duplicate-guarded).

    Called at the Module 3/4 commit boundary.  Verifies the successful outcome,
    copies the PCAP evidence to ``captures/<sequence>/<experiment_id>.pcap``,
    then appends the record to ``staging/successful_samples.jsonl``.

    Duplicate protection: a logical sequence may contribute at most one staged
    record.  A record with the *same* experiment_id is treated as an idempotent
    re-collection and returned unchanged; a duplicate with a *different*
    experiment_id for an already-committed sequence is rejected; an orphan
    record (never committed) is archived and reported before re-staging.

    Raises on any persistence failure, in which case the execution engine marks
    the attempt FAILED and never commits the sequence.
    """
    log = log or (lambda msg: None)
    if outcome.get("status") != OUTCOME_SUCCESS:
        raise ValueError(
            f"refusing to stage non-successful outcome for {experiment_id}"
        )
    sequence = sample["sequence"]
    if "pcap_path" not in outcome or not outcome["pcap_path"]:
        raise ValueError(f"successful outcome for {experiment_id} has no pcap")

    staged_by_seq = {r["sequence"]: r for r in read_staging(run)}
    if sequence in staged_by_seq:
        existing = staged_by_seq[sequence]
        if existing["experiment_id"] == experiment_id:
            return existing
        if sequence in _committed_experiment_by_sequence(run):
            raise ValueError(
                f"duplicate successful sample: sequence {sequence} already "
                f"staged with experiment {existing['experiment_id']} but "
                f"about to be re-staged with {experiment_id}"
            )
        _archive_orphan_staged_record(run, existing, log)

    relative_pcap = (
        f"{CAPTURES_SUBDIR}/{sequence:04d}/{experiment_id}.pcap"
    )
    dest_pcap = run.directory / relative_pcap
    dest_pcap.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(outcome["pcap_path"], dest_pcap)

    record = build_successful_record(
        run, sample, experiment_id, attempt, outcome, relative_pcap
    )
    if record["features"]["packet_count"] < 1:
        dest_pcap.unlink(missing_ok=True)
        raise ValueError(
            f"features for {experiment_id} violate the minimum validity "
            f"requirement (packet_count < 1)"
        )
    try:
        _append_staged_record(run, record)
    except Exception:
        dest_pcap.unlink(missing_ok=True)
        raise
    log(
        f"[artifacts] staged successful sample seq={sequence} "
        f"experiment={experiment_id}"
    )
    return record


# ---------------------------------------------------------------------------
# Materialization (atomic tmp + replace)
# ---------------------------------------------------------------------------

def _flatten_parquet_row(record):
    features = record["features"]
    row = {}
    for name, _field_type in PARQUET_ID_COLUMNS:
        row[name] = record[name]
    for column in FEATURE_COLUMNS:
        row[column] = features[column]
    return row


def _ordered_records(staged):
    return sorted(staged, key=lambda r: r["sequence"])


def materialize_parquet(run, staged):
    """Atomically materialize ``features.parquet`` from the staged records.

    Writes to ``features.parquet.tmp`` first and atomically renames, so a
    partially written file is never visible as the final artifact.  The
    previous valid ``features.parquet`` is preserved if materialization fails.
    """
    rows = _ordered_records(staged)
    columns = {name: [] for name in PARQUET_COLUMNS}
    for record in rows:
        row = _flatten_parquet_row(record)
        for name in PARQUET_COLUMNS:
            columns[name].append(row[name])
    table = pa.table(columns, schema=PARQUET_SCHEMA)
    parquet_path = run.directory / FEATURES_PARQUET_FILENAME
    tmp_path = parquet_path.with_suffix(parquet_path.suffix + ".tmp")
    try:
        pq.write_table(table, tmp_path)
        with open(tmp_path, "ab") as fh:
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp_path, parquet_path)
    except Exception:
        tmp_path.unlink(missing_ok=True)
        raise
    return parquet_path


def materialize_metadata(run, staged):
    """Atomically materialize ``metadata.jsonl`` from the staged records."""
    lines = b"".join(
        json.dumps(record, sort_keys=True).encode("utf-8") + b"\n"
        for record in _ordered_records(staged)
    )
    path = run.directory / METADATA_FILENAME
    tmp = path.with_suffix(path.suffix + ".tmp")
    with open(tmp, "wb") as fh:
        fh.write(lines)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)
    return path


# ---------------------------------------------------------------------------
# Consistency validation
# ---------------------------------------------------------------------------

def validate_final_dataset(run, plan, staged):
    """Every Module 5 consistency check on a finalized dataset.

    Raises ValueError on the first violation.  A dataset is only "complete"
    when all of these hold.  No count is ever repaired silently here.
    """
    target = run.target_samples
    successful = run.successful_samples
    committed = run.data["committed_run_ids"]

    if run.status != STATUS_COMPLETED:
        raise ValueError(
            f"dataset run {run.id} is {run.status}; finalization requires "
            f"{STATUS_COMPLETED}"
        )
    if plan_fingerprint(plan) != run.data.get("plan_fingerprint"):
        raise ValueError(
            "plan fingerprint mismatch: plan.json differs from the plan the "
            "run started with"
        )
    validate_runtime_state(run, target)

    if successful != target:
        raise ValueError(
            f"dataset incomplete: successful_samples ({successful}) != "
            f"target ({target})"
        )
    if len(staged) != successful:
        raise ValueError(
            f"dataset inconsistent: staged successful samples ({len(staged)}) "
            f"!= successful_samples ({successful})"
        )
    if len(committed) != successful:
        raise ValueError(
            f"dataset inconsistent: committed_run_ids ({len(committed)}) != "
            f"successful_samples ({successful})"
        )

    staged_seqs = [r["sequence"] for r in staged]
    if len(set(staged_seqs)) != len(staged_seqs):
        raise ValueError("duplicate logical sequence in successful staging")
    if sorted(staged_seqs) != list(range(1, target + 1)):
        raise ValueError(
            f"staged sequences {sorted(staged_seqs)} do not cover 1..{target}"
        )
    if {r["experiment_id"] for r in staged} != set(committed):
        raise ValueError(
            "staged experiment ids differ from committed_run_ids"
        )

    samples_by_seq = {s["sequence"]: s for s in plan["samples"]}
    for record in staged:
        seq = record["sequence"]
        sample = samples_by_seq.get(seq)
        if sample is None:
            raise ValueError(f"staged record sequence {seq} not in the plan")

        for key in METADATA_REQUIRED_KEYS:
            if key not in record:
                raise ValueError(
                    f"staged record for sequence {seq} is missing "
                    f"'{key}'; refusing to finalize"
                )
        if record["status"] != SUCCESS_LABEL:
            raise ValueError(
                f"staged record for sequence {seq} is not successful "
                f"(status={record['status']!r})"
            )
        if record["dataset_schema_version"] != SCHEMA_VERSION:
            raise ValueError(
                f"record for sequence {seq} has unsupported dataset schema "
                f"version {record['dataset_schema_version']!r}"
            )
        if record["feature_schema_version"] != FEATURE_SCHEMA_VERSION:
            raise ValueError(
                f"record for sequence {seq} has unsupported feature schema "
                f"version {record['feature_schema_version']!r}"
            )
        if record["security_posture"] != sample["security_posture"]:
            raise ValueError(
                f"sequence {seq} posture mismatch: staged "
                f"{record['security_posture']!r} vs plan "
                f"{sample['security_posture']!r}"
            )
        if record["traffic_profile"] != sample["traffic_profile"]:
            raise ValueError(
                f"sequence {seq} traffic mismatch: staged "
                f"{record['traffic_profile']!r} vs plan "
                f"{sample['traffic_profile']!r}"
            )
        if record["configuration_id"] != sample["configuration_id"]:
            raise ValueError(
                f"sequence {seq} configuration_id mismatch: staged "
                f"{record['configuration_id']!r} vs plan "
                f"{sample['configuration_id']!r}"
            )
        expected_config = sample["ipsec_configuration"]
        if record["ipsec_configuration"] != expected_config:
            raise ValueError(
                f"sequence {seq} ipsec_configuration does not match the plan"
            )
        for key, expected in flatten_config(expected_config).items():
            if record[key] != expected:
                raise ValueError(
                    f"sequence {seq} flattened config field '{key}' mismatch: "
                    f"staged {record[key]!r} vs plan {expected!r}"
                )
        parsed = parse_experiment_id(record["experiment_id"])
        if parsed != (run.id, seq, record["attempt_number"]):
            raise ValueError(
                f"sequence {seq} experiment_id/attempt_number inconsistency"
            )
        pcap_path = run.directory / record["pcap_path"]
        if not pcap_path.is_file():
            raise ValueError(
                f"sequence {seq} PCAP reference missing: {record['pcap_path']}"
            )
        normalize_feature_record(record["features"])

    traffic_observed = Counter(r["traffic_profile"] for r in staged)
    plan_quota = plan.get("traffic_quota")
    if plan_quota is not None:
        for profile, expected in plan_quota.items():
            if traffic_observed.get(profile, 0) != expected:
                raise ValueError(
                    f"traffic distribution mismatch: profile '{profile}' has "
                    f"{traffic_observed.get(profile, 0)} successful samples "
                    f"but the plan requires {expected}"
                )
    posture_observed = Counter(r["security_posture"] for r in staged)
    posture_planned = plan.get("posture_planned")
    if posture_planned is not None:
        for posture, expected in posture_planned.items():
            if posture_observed.get(posture, 0) != expected:
                raise ValueError(
                    f"security posture distribution mismatch: posture "
                    f"'{posture}' has {posture_observed.get(posture, 0)} "
                    f"successful samples but the plan requires {expected}"
                )
    return True


# ---------------------------------------------------------------------------
# Run README
# ---------------------------------------------------------------------------

def _readme_text(run, plan, staged, finalized):
    from .traffic import PROFILES, PROFILE_LABELS
    from .dataset_planner import POSTURE_ORDER

    lines = [
        f"dataset_run_id: {run.id}",
        f"dataset_schema_version: {SCHEMA_VERSION}",
        f"target_samples: {run.target_samples}",
        f"successful_samples: {len(staged)}",
        "status: " + ("FINALIZED" if finalized else "NOT FINALIZED"),
        "",
        "Artifacts",
        f"  features table : {FEATURES_PARQUET_FILENAME}",
        f"  metadata       : {METADATA_FILENAME}",
        f"  pcap evidence  : {CAPTURES_SUBDIR}/<sequence>/<experiment_id>.pcap",
        f"  staging source : {STAGING_SUBDIR}/{SUCCESSFUL_SAMPLES_FILENAME}",
        "",
        "Security posture categories (deterministic ground truth, Module 2):",
    ]
    lines += [f"  {posture}" for posture in POSTURE_ORDER]
    lines += [
        "",
        "Traffic profiles (independent of security posture):",
    ]
    lines += [
        f"  {label} ({profile})"
        for profile in PROFILES
        for label in [PROFILE_LABELS.get(profile, profile)]
    ]
    lines += [
        "",
        "Ground truth: each sample's security_posture, traffic_profile and",
        "ipsec_configuration come from the Module 2 plan for its logical",
        "sequence.  Traffic characteristics never alter the posture label, and",
        "traffic type never determines security posture.",
        "",
        "This module records artifacts; it does NOT compute the future",
        "security/confidentiality score and does not perform any ML.",
        "",
        "To inspect:",
        f"  import pyarrow.parquet as pq; pq.read_table('{FEATURES_PARQUET_FILENAME}')",
        f"  jq -s . {METADATA_FILENAME}",
        f"  plan json: {STAGING_SUBDIR}/plan.json",
        "",
    ]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Finalization orchestrator
# ---------------------------------------------------------------------------

def finalization_state(dataset_run_id, status, error=None, **extra):
    state = {
        "dataset_run_id": dataset_run_id,
        "status": status,
        "updated_at": utcnow_iso(),
    }
    if error is not None:
        state["error"] = str(error)
    state.update(extra)
    return state


def finalize_dataset(results_root, dataset_run_id, log=None, write_artifacts=True):
    """Validate and materialize a complete dataset run's artifacts.

    Order:
      1. load the plan and verify it still matches the run's stored
         ``plan_fingerprint`` (no silent plan regeneration),
      2. run every Module 5 consistency check,
      3. atomically materialize ``features.parquet`` and ``metadata.jsonl``,
      4. write the run ``README.txt``,
      5. record ``finalization.json`` status = COMPLETED.

    On any failure: ``finalization.json`` is written with status = FAILED and
    the error, no final artifact is replaced (previous valid artifacts are
    preserved), and the exception is re-raised.
    """
    log = log or (lambda msg: None)
    run = dataset_run_mod.load_dataset_run(results_root, dataset_run_id)
    run_dir = run.directory
    plan = None
    staged = []

    try:
        plan = load_plan(results_root, dataset_run_id)
        staged = read_staging(run)
        validate_final_dataset(run, plan, staged)
        log(
            f"[finalize] {dataset_run_id}: {len(staged)}/{run.target_samples} "
            f"successful samples validated"
        )

        completed = {}
        if write_artifacts:
            materialize_parquet(run, staged)
            materialize_metadata(run, staged)
            readme_path = run_dir / RUN_README_FILENAME
            readme_path.write_text(
                _readme_text(run, plan, staged, finalized=True),
                encoding="utf-8",
            )
            completed = {
                "parquet_rows": len(staged),
                "metadata_records": len(staged),
            }
        dataset_run_mod._atomic_write_json(
            run_dir / FINALIZATION_FILENAME,
            finalization_state(dataset_run_id, "COMPLETED", **completed),
        )
        log(f"[finalize] {dataset_run_id}: artifacts finalized")
        return json.loads(
            (run_dir / FINALIZATION_FILENAME).read_text(encoding="utf-8")
        )

    except Exception as exc:
        dataset_run_mod._atomic_write_json(
            run_dir / FINALIZATION_FILENAME,
            finalization_state(dataset_run_id, "FAILED", error=exc),
        )
        raise


# ---------------------------------------------------------------------------
# Dataset download / export (final artifact bundle)
# ---------------------------------------------------------------------------

def export_artifact_paths(run):
    """Resolve the final downloadable artifacts of a dataset run.

    Returns the four files that constitute the final dataset: ``features.
    parquet``, ``metadata.jsonl``, the Module-1 ``manifest.json`` summary and
    the run ``README.txt``.  Per-sample evidence directories (``captures/``,
    ``experiments/``, ``failures/``) are provenance, not part of the final
    downloadable artifact, so they are intentionally not exported.

    Guards against both missing artifacts and path traversal: a missing file
    raises ``ValueError``, and any artifact whose resolved path escapes the
    run directory raises ``ValueError``.  Source files are only read here;
    they are never modified or removed.
    """
    base = run.directory.resolve()
    paths = []
    for name in EXPORT_ARTIFACT_FILENAMES:
        path = base / name
        if not path.is_file():
            raise ValueError(
                f"final dataset artifact is missing: {run.id}/{name}"
            )
        resolved = path.resolve()
        if not resolved.is_relative_to(base):
            raise ValueError(
                f"artifact path escapes the run directory: {path}"
            )
        paths.append(resolved)
    return paths


def build_dataset_zip(run, destination, log=None):
    """Write the final dataset archive (ZIP) for a COMPLETED run.

    Members are exactly ``export_artifact_paths(run)``, stored at the archive
    root under their original filename (no paths, so no traversal can reach
    outside the run directory).  The source artifacts are opened read-only and
    are never modified or deleted.  ``destination`` may be a filesystem path
    or an open binary file object.  Returns the resolved member paths.
    """
    log = log or (lambda msg: None)
    members = export_artifact_paths(run)
    with zipfile.ZipFile(destination, "w", zipfile.ZIP_DEFLATED) as archive:
        for path in members:
            archive.write(path, arcname=path.name)
            log(f"[export] {run.id}: {path.name}")
    return list(members)