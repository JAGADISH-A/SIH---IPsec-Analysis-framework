"""Capture a transport-mode dataset run from the real testbed (Part A helper).

This is a *driver*, not new dataset machinery.  It reuses the existing, already
committed pipeline end to end:

    controller.dataset_run.create_dataset_run
    controller.dataset_planner.build_catalogue / traffic_quota / profile_sequence
    controller.dataset_planner.write_sample_plan
    controller.dataset_executor.execute_dataset_run
    controller.dataset_artifacts.finalize_dataset

The only thing it adds is *selection*: the standard planner round-robins across
every posture band, and every transport posture cell it would pick first is
already present in the protected training runs, so the resulting run would carry
configurations the model has already seen.  This driver instead selects accepted
catalogue configurations that are **absent from every protected training run**,
so the captured run is a legitimate held-out transport set.

Design constraints honoured here:

* transport mode only -- no new mode, no testbed change;
* existing traffic profiles only (``traffic_quota`` / ``profile_sequence``);
* configurations must pass the unchanged ``validate_config``;
* ``configuration_id`` and ``security_posture`` come from the existing
  catalogue, never synthesised;
* grouping key stays ``configuration_id`` so the audit can prove the captured
  configurations are disjoint from the training partitions;
* the feature schema is whatever ``finalize_dataset`` already writes -- this
  driver never touches feature extraction.

Usage::

    python -m controller.transport_holdout_capture --target-samples 12
    python -m controller.transport_holdout_capture --target-samples 12 --dry-run
"""

from __future__ import annotations

import argparse
import json
import collections
import pathlib
from typing import Dict, List, Optional

import pyarrow.parquet as pq

from .dataset_artifacts import finalize_dataset
from .dataset_executor import execute_dataset_run, validate_plan
from .dataset_planner import (
    PLAN_FILENAME,
    POSTURE_ORDER,
    build_catalogue,
    traffic_quota,
    profile_sequence,
    write_sample_plan,
)
from .dataset_run import create_dataset_run, load_dataset_run
from .dataset_loader import GROUPS_COLUMN, PROTECTED_DATASET_RUN_IDS
from .validate import validate_config

DEFAULT_RESULTS_ROOT = pathlib.Path("results")
DEFAULT_DATASETS_DIR = DEFAULT_RESULTS_ROOT / "datasets"

TRANSPORT_MODE = "transport"


def training_configurations(
    datasets_dir: pathlib.Path = DEFAULT_DATASETS_DIR,
    protected_runs: tuple = PROTECTED_DATASET_RUN_IDS,
) -> set:
    """Every ``configuration_id`` that appears in the protected training runs."""
    seen = set()
    for run_id in protected_runs:
        path = datasets_dir / run_id / "features.parquet"
        if not path.is_file():
            raise FileNotFoundError(
                f"protected dataset missing: {path}; the model was trained on "
                f"these runs so their configurations cannot be reused"
            )
        seen.update(pq.read_table(path).column(GROUPS_COLUMN).to_pylist())
    return seen


def select_transport_configurations(
    exclude: set,
    limit: int,
    mode: str = TRANSPORT_MODE,
) -> List[dict]:
    """Accepted catalogue configurations for ``mode`` that training never saw.

    Catalogue order is fixed by ``enumerate_candidates()``, so selection is
    deterministic.  Postures are visited round-robin in ``POSTURE_ORDER`` so a
    small run still spans the crypto-strength axis instead of exhausting one
    band.
    """
    catalogue = build_catalogue()
    by_posture: Dict[str, List[dict]] = collections.defaultdict(list)
    for entry in catalogue["accepted"]:
        config = entry["config"]
        if config["mode"] != mode:
            continue
        if entry["configuration_id"] in exclude:
            continue
        # Re-validate through the production validator: a catalogue entry must
        # still satisfy the current shape rules.
        validate_config(config)
        by_posture[entry["security_posture"]].append(entry)

    selected: List[dict] = []
    postures = [p for p in POSTURE_ORDER if by_posture.get(p)]
    index = 0
    while len(selected) < limit and any(by_posture[p] for p in postures):
        posture = postures[index % len(postures)]
        index += 1
        if not by_posture[posture]:
            continue
        selected.append(by_posture[posture].pop(0))
    if len(selected) < limit:
        raise RuntimeError(
            f"only {len(selected)} unseen {mode} configurations available, "
            f"needed {limit}"
        )
    return selected


def build_transport_plan(
    target_samples: int,
    exclude: set,
    mode: str = TRANSPORT_MODE,
) -> dict:
    """Assemble a transport-only dataset plan over unseen configurations.

    Traffic profiles come from the existing balanced quota/sequence helpers, so
    every profile is represented exactly as the standard planner would balance
    them -- the only deviation is the configuration selection.
    """
    entries = select_transport_configurations(exclude, target_samples, mode=mode)
    profiles = profile_sequence(target_samples)
    samples = []
    for index, profile in enumerate(profiles):
        entry = entries[index]
        samples.append(
            {
                "sequence": index + 1,
                "traffic_profile": profile,
                "security_posture": entry["security_posture"],
                "configuration_id": entry["configuration_id"],
                "ipsec_configuration": entry["config"],
            }
        )
    plan = {
        "planner_version": "transport-holdout-selection",
        "dataset_schema_version": "v2",
        "target_samples": target_samples,
        "traffic_quota": traffic_quota(target_samples),
        "selection": {
            "mode": mode,
            "rule": (
                "accepted catalogue configurations for the mode, excluding every "
                "configuration_id present in the protected training runs"
            ),
            "excluded_configuration_count": len(exclude),
            "distinct_configurations": len(
                {s["configuration_id"] for s in samples}
            ),
        },
        "samples": samples,
    }
    validate_plan(plan)
    return plan


def plan_summary(plan: dict) -> dict:
    return {
        "target_samples": plan["target_samples"],
        "profiles": dict(
            sorted(collections.Counter(
                s["traffic_profile"] for s in plan["samples"]
            ).items())
        ),
        "postures": dict(
            sorted(collections.Counter(
                s["security_posture"] for s in plan["samples"]
            ).items())
        ),
        "distinct_configurations": len(
            {s["configuration_id"] for s in plan["samples"]}
        ),
        "configurations": sorted(
            {s["configuration_id"] for s in plan["samples"]}
        ),
    }


def capture(
    target_samples: int,
    run_id: str,
    results_root: pathlib.Path = DEFAULT_RESULTS_ROOT,
    duration: Optional[float] = None,
    dry_run: bool = False,
    log=None,
) -> dict:
    """Create, plan, execute and finalize one transport-mode dataset run."""
    log = log or (lambda msg: print(msg))
    exclude = training_configurations(results_root / "datasets")
    log(f"training configurations in protected runs: {len(exclude)}")

    plan = build_transport_plan(target_samples, exclude)
    summary = plan_summary(plan)
    log(
        f"plan: {summary['target_samples']} samples, "
        f"{summary['distinct_configurations']} distinct unseen configurations"
    )
    for posture, count in summary["postures"].items():
        log(f"  posture {posture}: {count}")

    if dry_run:
        return {"dry_run": True, "run_id": run_id, "plan": summary}

    run_dir = results_root / "datasets" / run_id
    resuming = run_dir.exists()

    if resuming:
        # An interrupted capture (SIGKILL, shell timeout, lab reboot) leaves a
        # partial run on disk. execute_dataset_run is resumable: it reads the
        # persisted plan and counters and only attempts the samples that are
        # still outstanding. Rewriting the plan here would be a no-op at best
        # and would discard committed work at worst, so it is skipped.
        existing = load_dataset_run(results_root, run_id)
        if existing.data["target_samples"] != target_samples:
            raise ValueError(
                f"existing run {run_id} targets "
                f"{existing.data['target_samples']} samples, not "
                f"{target_samples}"
            )
        if existing.data["successful_samples"] >= target_samples:
            log(
                f"resuming {run_id}: already has "
                f"{existing.data['successful_samples']}/{target_samples} "
                "committed samples"
            )
        else:
            log(
                f"resuming interrupted run {run_id}: "
                f"{existing.data['successful_samples']}/{target_samples} "
                "samples already committed"
            )
        # The resumed run must use the same unseen-configuration plan, so
        # verify the persisted plan still matches this selection.
        persisted_path = run_dir / "staging" / PLAN_FILENAME
        persisted = plan_summary(json.loads(persisted_path.read_text()))
        if persisted["configurations"] != summary["configurations"]:
            raise RuntimeError(
                f"persisted plan for {run_id} does not match the current "
                "unseen-configuration selection; refusing to mix plans"
            )
    else:
        create_dataset_run(results_root, target_samples, run_id)
        plan_path = write_sample_plan(results_root, run_id, plan)
        log(f"plan written: {plan_path}")

    run_options = None
    if duration is not None:
        from .dataset_executor import RunOptions
        from .traffic import DEFAULT_CAPTURE_FILTER, DEFAULT_PORT

        run_options = RunOptions(
            duration=float(duration),
            port=DEFAULT_PORT,
            capture_filter=DEFAULT_CAPTURE_FILTER,
        )

    # ``collector_fn`` stages each successful sample into
    # staging/successful_samples.jsonl. It defaults to None in the library
    # (only the CLI wires it), and omitting it would commit samples to state
    # while staging nothing, so finalization would then reject the run as
    # inconsistent. Pass it explicitly, exactly as controller/dataset_api.py
    # does for the production worker.
    from .dataset_artifacts import collect_successful_sample

    run = execute_dataset_run(
        results_root,
        run_id,
        collector_fn=collect_successful_sample,
        run_options=run_options,
        log=log,
    )
    log(
        f"execution: status={run.status} "
        f"successful={run.data['successful_samples']} "
        f"failed={run.data['failed_samples']}"
    )
    if run.data["successful_samples"] != target_samples:
        raise RuntimeError(
            f"only {run.data['successful_samples']}/{target_samples} samples "
            f"committed; refusing to finalize a partial dataset"
        )

    finalize_dataset(results_root, run_id, log=log)
    parquet = results_root / "datasets" / run_id / "features.parquet"
    table = pq.read_table(parquet)
    log(f"features.parquet: {table.num_rows} rows x {table.num_columns} columns")

    return {
        "dry_run": False,
        "run_id": run_id,
        "plan": summary,
        "status": run.status,
        "rows": table.num_rows,
        "columns": table.num_columns,
        "parquet": str(parquet),
    }


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--target-samples", type=int, required=True)
    parser.add_argument("--run-id", default=None)
    parser.add_argument("--results-root", type=pathlib.Path,
                        default=DEFAULT_RESULTS_ROOT)
    parser.add_argument("--duration", type=float, default=None,
                        help="per-sample traffic duration override (seconds)")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)

    from .dataset_run import generate_dataset_run_id

    run_id = args.run_id or generate_dataset_run_id()
    result = capture(
        args.target_samples,
        run_id,
        results_root=args.results_root,
        duration=args.duration,
        dry_run=args.dry_run,
    )
    if args.dry_run:
        print(json.dumps(result, indent=2))
    else:
        print(f"captured {result['run_id']}: {result['rows']} rows")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())