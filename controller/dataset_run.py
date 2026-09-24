"""Dataset Run state and storage foundation (Module 1).

A Dataset Run is a single self-contained request to build a dataset of
``target_samples`` IPsec experiments.  This module only owns the persistent
state/storage for such a run:

    results/datasets/<dataset_run_id>/
        manifest.json     # human-readable run summary
        state.json        # authoritative mutable run state
        staging/          # reserved: intermediate files
        captures/         # reserved: captured pcaps
        experiments/      # reserved: per-experiment artifacts
        failures/         # reserved: recorded failures
        logs/             # reserved: run logs

Execution, configuration selection, traffic generation, API and UI are out of
scope for this module and are left to future modules.

No experiment is executed by anything in this module.
"""

import json
import os
import re
import time
from pathlib import Path

from . import dataset as dataset_mod

SCHEMA_VERSION = "v1"

STATUS_CREATED = "CREATED"
VALID_STATUSES = ("CREATED", "RUNNING", "PAUSED", "COMPLETED", "FAILED")

MANIFEST_FILENAME = "manifest.json"
STATE_FILENAME = "state.json"
DATASETS_SUBDIR = "datasets"
SUB_DIRECTORIES = ("staging", "captures", "experiments", "failures", "logs")

RUN_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")

# Top-level state keys that cannot change after a run is created.
IMMUTABLE_FIELDS = frozenset({"dataset_run_id", "created_at", "target_samples"})


def default_state(dataset_run_id, target_samples, timestamp):
    return {
        "dataset_run_id": dataset_run_id,
        "target_samples": target_samples,
        "attempted_runs": 0,
        "successful_samples": 0,
        "failed_samples": 0,
        "interrupted_samples": 0,
        "committed_run_ids": [],
        "status": STATUS_CREATED,
        "created_at": timestamp,
        "updated_at": timestamp,
        # Reserved for future modules (execution / selection / allocation).
        "current_experiment": None,
        "current_configuration": None,
        "current_traffic_profile": None,
        "current_sequence": None,
        "current_security_posture": None,
        "traffic_allocation_progress": {},
        "configuration_selection_progress": {},
        # Hardening fields owned by the execution engine (Module 4).
        # attempts_per_sequence tracks, per logical sequence, how many physical
        # attempts have STARTED (the durable budget counter).  Keys are the
        # sequence numbers as JSON-safe strings.
        "attempts_per_sequence": {},
        # attempt_in_progress is persisted BEFORE a physical attempt starts and
        # cleared once its outcome is recorded.  After SIGKILL it tells the
        # engine that an attempt started but never recorded an outcome.
        "attempt_in_progress": None,
        # plan_fingerprint pins the exact plan.json a run started with, so a
        # resume can never silently pick up a different plan.
        "plan_fingerprint": None,
        # stale_sequence / stale_experiment record the attempt whose cleanup
        # failed; the next attempt must re-clean it before starting.
        "stale_sequence": None,
        "stale_experiment": None,
        "error": None,
    }


def generate_dataset_run_id():
    return "dataset-" + time.strftime("%Y%m%d-%H%M%S")


def dataset_runs_root(results_root):
    return Path(results_root) / DATASETS_SUBDIR


def run_directory(results_root, dataset_run_id):
    return dataset_runs_root(results_root) / dataset_run_id


def validate_dataset_run_id(dataset_run_id):
    if not isinstance(dataset_run_id, str) or not dataset_run_id:
        raise ValueError("dataset_run_id must be a non-empty string")
    if dataset_run_id in {".", ".."}:
        raise ValueError(f"invalid dataset_run_id: {dataset_run_id}")
    if not RUN_ID_PATTERN.fullmatch(dataset_run_id):
        raise ValueError(
            f"dataset_run_id '{dataset_run_id}' is not safe for filesystem paths"
        )


def validate_counters(state):
    target = state.get("target_samples")
    if isinstance(target, bool) or not isinstance(target, int):
        raise ValueError("target_samples must be an integer")
    if target <= 0:
        raise ValueError(f"target_samples must be > 0, got {target}")

    for key in (
        "attempted_runs",
        "successful_samples",
        "failed_samples",
        "interrupted_samples",
    ):
        value = state.get(key)
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError(f"{key} must be an integer, got {value!r}")
        if value < 0:
            raise ValueError(f"{key} must be >= 0, got {value}")

    attempted = state["attempted_runs"]
    successful = state["successful_samples"]
    failed = state["failed_samples"]
    interrupted = state["interrupted_samples"]

    if successful > attempted:
        raise ValueError(
            f"successful_samples ({successful}) exceeds "
            f"attempted_runs ({attempted})"
        )
    if successful > target:
        raise ValueError(
            f"successful_samples ({successful}) exceeds "
            f"target_samples ({target})"
        )
    if failed + interrupted > attempted:
        raise ValueError(
            f"failed_samples ({failed}) + interrupted_samples ({interrupted}) "
            f"exceeds attempted_runs ({attempted})"
        )

    return True


def validate_state(state):
    validate_dataset_run_id(state.get("dataset_run_id"))
    validate_counters(state)

    status = state.get("status")
    if status not in VALID_STATUSES:
        raise ValueError(f"invalid status '{status}', expected one of {VALID_STATUSES}")

    committed = state.get("committed_run_ids")
    if not isinstance(committed, list):
        raise ValueError("committed_run_ids must be a list")
    if any(not isinstance(run_id, str) for run_id in committed):
        raise ValueError("committed_run_ids must contain only strings")
    if len(set(committed)) != len(committed):
        raise ValueError("committed_run_ids must not contain duplicates")

    current_sequence = state.get("current_sequence")
    if current_sequence is not None and (
        isinstance(current_sequence, bool) or not isinstance(current_sequence, int)
    ):
        raise ValueError("current_sequence must be an integer or null")

    current_posture = state.get("current_security_posture")
    if current_posture is not None and not isinstance(current_posture, str):
        raise ValueError("current_security_posture must be a string or null")

    error = state.get("error")
    if error is not None and not isinstance(error, str):
        raise ValueError("error must be a string or null")

    attempts_per_seq = state.get("attempts_per_sequence")
    if attempts_per_seq is not None:
        if not isinstance(attempts_per_seq, dict):
            raise ValueError("attempts_per_sequence must be a dict")
        for key, value in attempts_per_seq.items():
            if not isinstance(key, (str, int)):
                raise ValueError(
                    "attempts_per_sequence keys must be sequence numbers"
                )
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValueError(
                    "attempts_per_sequence values must be non-negative integers"
                )

    in_progress = state.get("attempt_in_progress")
    if in_progress is not None:
        if not isinstance(in_progress, dict):
            raise ValueError("attempt_in_progress must be a dict or null")
        for field in ("sequence", "attempt", "experiment_id"):
            if field not in in_progress:
                raise ValueError(f"attempt_in_progress missing '{field}'")
        if (
            isinstance(in_progress["sequence"], bool)
            or not isinstance(in_progress["sequence"], int)
        ):
            raise ValueError("attempt_in_progress sequence must be an integer")
        if (
            isinstance(in_progress["attempt"], bool)
            or not isinstance(in_progress["attempt"], int)
            or in_progress["attempt"] < 1
        ):
            raise ValueError(
                "attempt_in_progress attempt must be a positive integer"
            )
        if not isinstance(in_progress["experiment_id"], str) or not in_progress["experiment_id"]:
            raise ValueError(
                "attempt_in_progress experiment_id must be a non-empty string"
            )

    fingerprint = state.get("plan_fingerprint")
    if fingerprint is not None and (
        not isinstance(fingerprint, str) or not fingerprint
    ):
        raise ValueError("plan_fingerprint must be a non-empty string or null")

    stale_sequence = state.get("stale_sequence")
    if stale_sequence is not None and (
        isinstance(stale_sequence, bool) or not isinstance(stale_sequence, int)
    ):
        raise ValueError("stale_sequence must be an integer or null")

    stale_experiment = state.get("stale_experiment")
    if stale_experiment is not None and (
        not isinstance(stale_experiment, str) or not stale_experiment
    ):
        raise ValueError("stale_experiment must be a non-empty string or null")

    return True


def build_manifest(state):
    return {
        "dataset_run_id": state["dataset_run_id"],
        "created_at": state["created_at"],
        "updated_at": state["updated_at"],
        "target_samples": state["target_samples"],
        "attempted_runs": state["attempted_runs"],
        "successful_samples": state["successful_samples"],
        "failed_samples": state["failed_samples"],
        "interrupted_samples": state["interrupted_samples"],
        "status": state["status"],
        "dataset_schema_version": SCHEMA_VERSION,
    }


def _atomic_write_json(path, data):
    """Write JSON via a temporary file and an atomic replace.

    The temporary file lives next to the destination so ``os.replace`` stays on
    the same filesystem.  A stale temporary file is simply reused/overwritten.
    """
    path = Path(path)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)


class DatasetRun:
    def __init__(self, results_root, data):
        self.results_root = Path(results_root)
        self.data = data

    @property
    def id(self):
        return self.data["dataset_run_id"]

    @property
    def directory(self):
        return run_directory(self.results_root, self.id)

    @property
    def state_path(self):
        return self.directory / STATE_FILENAME

    @property
    def manifest_path(self):
        return self.directory / MANIFEST_FILENAME

    @property
    def target_samples(self):
        return self.data["target_samples"]

    @property
    def attempted_runs(self):
        return self.data["attempted_runs"]

    @property
    def successful_samples(self):
        return self.data["successful_samples"]

    @property
    def failed_samples(self):
        return self.data["failed_samples"]

    @property
    def interrupted_samples(self):
        return self.data["interrupted_samples"]

    @property
    def status(self):
        return self.data["status"]

    def _persist(self):
        validate_state(self.data)
        self.data["updated_at"] = dataset_mod.utcnow_iso()
        _atomic_write_json(self.state_path, self.data)
        _atomic_write_json(self.manifest_path, build_manifest(self.data))

    def update(self, **fields):
        if not fields:
            return self
        for key in fields:
            if key in IMMUTABLE_FIELDS:
                raise ValueError(f"field '{key}' cannot be changed after creation")
            if key not in self.data:
                raise ValueError(f"unknown state field '{key}'")

        # Validate the would-be state before mutating anything, so a rejected
        # update never corrupts the in-memory run.
        candidate = dict(self.data)
        for key, value in fields.items():
            candidate[key] = value
        validate_state(candidate)

        for key, value in fields.items():
            self.data[key] = value
        self._persist()
        return self

    def record_attempt(self):
        return self.update(attempted_runs=self.data["attempted_runs"] + 1)

    def record_success(self):
        return self.update(successful_samples=self.data["successful_samples"] + 1)

    def record_failure(self):
        return self.update(failed_samples=self.data["failed_samples"] + 1)

    def record_interruption(self):
        return self.update(interrupted_samples=self.data["interrupted_samples"] + 1)

    def commit_run(self, run_id):
        if not isinstance(run_id, str) or not run_id:
            raise ValueError("committed run_id must be a non-empty string")
        committed = self.data["committed_run_ids"]
        if run_id in committed:
            raise ValueError(f"run_id '{run_id}' already committed")
        return self.update(committed_run_ids=[*committed, run_id])

    def set_status(self, status):
        return self.update(status=status)


def create_dataset_run(results_root, target_samples, dataset_run_id=None):
    """Create a Dataset Run on disk and return its DatasetRun object."""
    draft = default_state(
        dataset_run_id or "unset",
        target_samples,
        dataset_mod.utcnow_iso(),
    )
    validate_counters(draft)

    if dataset_run_id is None:
        dataset_run_id = generate_dataset_run_id()
    validate_dataset_run_id(dataset_run_id)

    run_dir = run_directory(results_root, dataset_run_id)
    if run_dir.exists():
        raise ValueError(f"dataset run already exists: {dataset_run_id}")

    run_dir.mkdir(parents=True)
    for sub in SUB_DIRECTORIES:
        (run_dir / sub).mkdir(exist_ok=True)

    data = default_state(
        dataset_run_id,
        target_samples,
        dataset_mod.utcnow_iso(),
    )
    validate_state(data)

    run = DatasetRun(results_root, data)
    # state.json is authoritative; manifest.json is the derived summary.
    _atomic_write_json(run.state_path, run.data)
    _atomic_write_json(run.manifest_path, build_manifest(run.data))
    return run


def load_dataset_run(results_root, dataset_run_id):
    """Load a Dataset Run from disk, validating its state."""
    validate_dataset_run_id(dataset_run_id)
    run_dir = run_directory(results_root, dataset_run_id)
    if not run_dir.exists():
        raise FileNotFoundError(f"dataset run not found: {dataset_run_id}")

    state_path = run_dir / STATE_FILENAME
    if not state_path.exists():
        raise FileNotFoundError(
            f"dataset run has no {STATE_FILENAME}: {run_dir}"
        )

    data = json.loads(state_path.read_text(encoding="utf-8"))
    validate_state(data)

    run = DatasetRun(results_root, data)
    manifest_path = run_dir / MANIFEST_FILENAME
    if not manifest_path.exists():
        _atomic_write_json(manifest_path, build_manifest(run.data))
    return run