"""Dataset regeneration under the current feature schema (v2) + live parity.

Background
----------
The dataset generator finalizes ``features.parquet`` / ``metadata.jsonl`` from
staging records whose feature dicts are produced at commit time.  When the
feature authority moves to a newer ``feature_schema_version`` (v1 -> v2 removed
the five live-irreproducible IKE exchange/version columns), a stored run's
artifacts keep the old feature vectors even though every row remains
reproducible from its preserved PCAP evidence.

This module re-derives the feature vector of an already-committed, COMPLETED
run from the stored PCAP evidence with the *current* authority
(``controller/features.extract_features`` -> ``summarize_capture``), re-validates
every Module 5 invariant, atomically materializes v2 ``features.parquet`` /
``metadata.jsonl``, and then verifies the regenerated rows bit-for-bit against
the live feature path (``controller/live_features.LiveFeatureExtractor`` over
``iterate_capture_as_live_events``).

Ground truth is untouched by design: ``security_posture``, ``traffic_profile``
and ``configuration_id`` always come from the Module 2 plan sample for the
record's logical sequence, never from traffic (see
``dataset_artifacts.build_successful_record``).

Reuse, never reimplementation: this module only orchestrates existing modules
(``dataset_run``, ``dataset_executor``, ``dataset_artifacts``, ``features``,
``live_features``, ``capture``).  No ML is implemented, trained or scored here.

CLI::

    python -m controller.dataset_rebuild --run-id dataset-20260916-231246
    python -m controller.dataset_rebuild --run-id dataset-20260916-231246 --no-write
    python -m controller.dataset_rebuild --run-id dataset-20260916-231246 --verify-only
"""

import argparse
import json
import sys
from pathlib import Path

from . import capture as capture_mod
from . import dataset_artifacts as artifacts_mod
from . import dataset_run as dataset_run_mod
from . import features as features_mod
from . import live_features as live_mod
from .dataset_executor import STATUS_COMPLETED, load_plan

DEFAULT_RESULTS_ROOT = "results"
DEFAULT_DURATION = 30.0


def _record_duration(record):
    """Nominal experiment duration for density-window feature extraction."""
    traffic = record.get("traffic_model") or {}
    duration = traffic.get("duration") or record.get("traffic_duration")
    if duration is None:
        return DEFAULT_DURATION
    return float(duration)


def capture_ip_for(record):
    """WAN address of the capture point (direction anchor), from the map."""
    return capture_mod.capture_facing(record["mode"], record["address_family"])[1]


def extract_features_for(run, record):
    """v2 feature record re-derived from the preserved PCAP evidence.

    Runs the current feature authority over the stored capture exactly as the
    dataset pipeline does at collection time (same capture point, same nominal
    duration) and enforces the declared v2 schema (59 columns, exact types).
    """
    pcap = run.directory / record["pcap_path"]
    if not pcap.is_file():
        raise ValueError(
            f"PCAP evidence missing for {record['experiment_id']}: {pcap}"
        )
    features = features_mod.extract_features(
        str(pcap),
        capture_ip=capture_ip_for(record),
        nominal_duration=_record_duration(record),
    )
    return artifacts_mod.normalize_feature_record(features)


def regenerate_run(results_root, run_id, *, write=True, log=None):
    """Re-derive a COMPLETED run's features at the current v2 schema.

    Loads the run and its plan, re-extracts v2 features for every staged
    record from the preserved PCAP evidence, validates every Module 5
    invariant in memory first, then (when ``write``) rewrites staging and
    re-finalizes the artifacts.  Returns ``(new_records, plan)``.
    """
    log = log or print
    run = dataset_run_mod.load_dataset_run(results_root, run_id)
    if run.status != STATUS_COMPLETED:
        raise SystemExit(
            f"dataset run {run_id} is {run.status}; only COMPLETED runs can "
            f"be regenerated"
        )
    plan = load_plan(results_root, run_id)
    staged = artifacts_mod.read_staging(run)
    if not staged:
        raise SystemExit(f"no staged successful samples for {run_id}")

    regenerated = []
    for record in staged:
        features = extract_features_for(run, record)
        new_record = dict(record)
        new_record["feature_schema_version"] = artifacts_mod.FEATURE_SCHEMA_VERSION
        new_record["features"] = features
        regenerated.append(new_record)

    artifacts_mod.validate_final_dataset(run, plan, regenerated)
    log(
        f"[rebuild] {run_id}: {len(regenerated)} record(s) validated at "
        f"{artifacts_mod.FEATURE_SCHEMA_VERSION} "
        f"({len(artifacts_mod.FEATURE_COLUMNS)} feature columns)"
    )

    if write:
        artifacts_mod.rewrite_staging(run, regenerated)
        artifacts_mod.finalize_dataset(results_root, run_id, log=log)
        log(f"[rebuild] {run_id}: staging rewritten and artifacts finalized")
    return regenerated, plan


def _verify_row(run, record, log):
    """Bit-for-bit parity of one stored row against offline and live paths."""
    pcap = run.directory / record["pcap_path"]
    cap_ip = capture_ip_for(record)
    duration = _record_duration(record)

    offline = artifacts_mod.normalize_feature_record(features_mod.extract_features(
        str(pcap), capture_ip=cap_ip, nominal_duration=duration))
    live_record = live_mod.extract_record(
        live_mod.iterate_capture_as_live_events(str(pcap)),
        capture_ip=cap_ip,
        nominal_duration=duration,
    )
    live = artifacts_mod.normalize_feature_record(live_record["features"])
    stored = artifacts_mod.normalize_feature_record(record["features"])

    same_offline = stored == offline
    same_live = stored == live
    v2 = record.get("feature_schema_version") == artifacts_mod.FEATURE_SCHEMA_VERSION
    exact_schema = set(stored) == artifacts_mod.FEATURE_KEYS and len(stored) == len(
        artifacts_mod.FEATURE_COLUMNS
    )
    geometry = (
        live_record["feature_schema_version"] == artifacts_mod.FEATURE_SCHEMA_VERSION
    )
    return {
        "sequence": record["sequence"],
        "experiment_id": record["experiment_id"],
        "security_posture": record["security_posture"],
        "traffic_profile": record["traffic_profile"],
        "packet_count": stored["packet_count"],
        "ike_packet_count": stored["ike_packet_count"],
        "feature_schema_version": record.get("feature_schema_version"),
        "rows": len(stored),
        "parity_offline": same_offline,
        "parity_live": same_live,
        "schema_v2": v2,
        "schema_exact": exact_schema,
        "live_geometry_v2": geometry,
    }


def verify_live_parity(results_root, run_id, *, records=None, log=None):
    """Verify regenerated artifacts against the live feature path.

    Asserts for every row:
      1. the v2 feature dict is exactly ``FEATURE_KEYS`` (59 cols),
      2. it equals ``extract_features`` re-run on the stored PCAP,
      3. it equals the live ``LiveFeatureExtractor`` record for the same
         frames, and
      4. ``feature_schema_version`` == "v2" (metadata, parquet linkage column
         and live record geometry).

    ``records`` defaults to the materialized ``metadata.jsonl`` (``None``);
    pass the in-memory regenerated records for a ``--no-write`` dry run.
    Returns ``(ok, rows, parquet_check)``.
    """
    run = dataset_run_mod.load_dataset_run(results_root, run_id)
    from_disk = records is None
    if from_disk:
        metadata_path = run.directory / artifacts_mod.METADATA_FILENAME
        if not metadata_path.is_file():
            raise SystemExit(
                f"metadata.jsonl missing for {run_id}; run regeneration first"
            )
        records = [
            json.loads(line)
            for line in metadata_path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
    rows = [_verify_row(run, record, log) for record in records]
    ok = all(
        row["parity_offline"] and row["parity_live"] and row["schema_v2"]
        and row["schema_exact"] and row["live_geometry_v2"]
        for row in rows
    )

    parquet_check = None
    if from_disk:
        parquet_path = run.directory / artifacts_mod.FEATURES_PARQUET_FILENAME
        if parquet_path.is_file():
            import pyarrow.parquet as pq

            table = pq.read_table(str(parquet_path))
            names = table.column_names
            expected_cols = len(artifacts_mod.PARQUET_ID_COLUMNS) + len(
                artifacts_mod.FEATURE_COLUMNS
            )
            version_col = table.column("feature_schema_version").to_pylist()
            parquet_check = {
                "rows": table.num_rows,
                "columns": len(names),
                "expected_columns": expected_cols,
                "all_v2": all(str(v) == artifacts_mod.FEATURE_SCHEMA_VERSION
                              for v in version_col),
                "feature_columns_present": all(
                    name in names for name in artifacts_mod.FEATURE_COLUMNS
                ),
            }
            ok = ok and parquet_check["rows"] == len(rows) and parquet_check["all_v2"]

    return ok, rows, parquet_check


def main(argv=None):
    parser = argparse.ArgumentParser(
        description=__doc__.splitlines()[0],
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--results-root", default=DEFAULT_RESULTS_ROOT)
    parser.add_argument(
        "--no-write", action="store_true",
        help="validate the regeneration in memory without persisting it")
    parser.add_argument(
        "--verify-only", action="store_true",
        help="skip regeneration; only verify current artifacts against the "
             "live feature path")
    args = parser.parse_args(argv)

    regenerated = None
    if not args.verify_only:
        regenerated, _plan = regenerate_run(
            args.results_root, args.run_id, write=not args.no_write
        )
        if args.no_write:
            print(
                f"[dry-run] {len(regenerated)} record(s) would be regenerated "
                f"at {artifacts_mod.FEATURE_SCHEMA_VERSION}; nothing written"
            )

    verify_records = regenerated if not args.verify_only and args.no_write else None
    ok, rows, parquet_check = verify_live_parity(
        args.results_root, args.run_id, records=verify_records
    )

    print("\n=== Per-record parity (persisted == offline == live) ===")
    header = (
        f"{'seq':>3s} {'posture':8s} {'profile':10s} {'esp':>5s} {'ike':>3s} "
        f"{'cols':>4s} {'ver':>3s} {'offline':>7s} {'live':>4s} {'schema':>6s}"
    )
    print(header)
    print("-" * len(header))
    for row in rows:
        print(
            f"{row['sequence']:>3d} {row['security_posture']:8s} "
            f"{row['traffic_profile']:10s} {row['packet_count']:>5d} "
            f"{row['ike_packet_count']:>3d} {row['rows']:>4d} "
            f"{row['feature_schema_version']:>3s} "
            f"{'OK' if row['parity_offline'] else 'FAIL':>7s} "
            f"{'OK' if row['parity_live'] else 'FAIL':>4s} "
            f"{'OK' if row['schema_v2'] and row['schema_exact'] else 'FAIL':>6s}"
        )

    if parquet_check:
        print("\n=== features.parquet ===")
        print(
            f"  rows={parquet_check['rows']} columns={parquet_check['columns']}"
            f" (expected {parquet_check['expected_columns']}) "
            f"all_rows_v2={parquet_check['all_v2']} "
            f"feature_columns_present={parquet_check['feature_columns_present']}"
        )
    elif args.no_write:
        print(
            "\n[note] features.parquet not checked (not regenerated in this "
            "dry run)"
        )

    if not ok:
        print("\nPARITY/Schema check FAILED")
        return 1
    print(
        f"\nOK: {len(rows)}/{len(rows)} records match the live v2 feature path"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())