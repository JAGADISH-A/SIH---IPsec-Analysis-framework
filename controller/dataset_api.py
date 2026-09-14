"""Dataset Run API (Module 6).

Exposes the Modules 1-5 dataset-generation backend over FastAPI with one hard
rule: the **required** number of successful samples is supplied by the user
and flows unchanged through the whole stack:

    POST /dataset-runs  {"target_samples": N}
        -> DatasetRun(target_samples=N)                 (Module 1)
        -> plan with exactly N logical samples          (Module 2)
        -> execution until N successful samples         (Modules 3/4)
        -> artifact finalization with N feature rows    (Module 5)

No default, clamp, rounding or reinterpretation of ``N`` exists anywhere in
this module.  A configurable ``max_target_samples`` is only a *safety
ceiling*: requests above it are rejected (never silently reduced).

Execution/building background
-----------------------------
Dataset generation is long running, so the POST endpoint returns immediately
with the ``dataset_run_id`` and the initial state; the execution runs on a
worker thread bound to this process (same architecture as the existing manual
experiment API).  ``resume`` does the same.  Exactly one execution worker can
exist for the shared testbed at a time: this module shares the single
reservation registry with the manual experiment API
(``controller.testbed_lock``), and no DatasetRun may have two workers.

Progress
--------
``progress_percentage`` is always ``successful_samples / target_samples * 100``
-- committed successful samples only.  Failed/interrupted attempts never move
it.

Reuse, never reimplementation
-----------------------------
This module has no posture classification, no configuration generation, no
traffic allocation, no retry/cleanup logic and no artifact finalization logic
of its own.  It delegates to Module 1 (``dataset_run``), Module 2
(``dataset_planner``), Modules 3/4 (``dataset_executor``) and Module 5
(``dataset_artifacts``).  All functions are reached through module attribute
lookup so tests can instrument them without changing behaviour.
"""

import json
import os
import tempfile
import time
from collections import Counter
from threading import Lock, Thread

from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, ConfigDict, Field, field_validator

from . import dataset_artifacts as artifacts_mod
from . import dataset_executor as executor_mod
from . import dataset_planner as planner_mod
from . import dataset_run as dataset_run_mod
from .dataset_executor import (
    DEFAULT_ATTEMPTS_PER_SEQUENCE,
    STATUS_COMPLETED,
    STATUS_RUNNING,
    parse_experiment_id,
)
from .testbed_lock import DATASET, TestbedLock

DEFAULT_RESULTS_ROOT = "results"
DEFAULT_MAX_TARGET_SAMPLES = int(
    os.environ.get("DATASET_MAX_TARGET_SAMPLES", "1000")
)
MIN_TARGET_SAMPLES = 1

PLAN_FILENAME = "plan.json"


# ---------------------------------------------------------------------------
# Request / response models (these are the OpenAPI data contract)
# ---------------------------------------------------------------------------

class DatasetTargetRequest(BaseModel):
    """Request body for creating a dataset run.

    ``target_samples`` is the exact number of successfully committed samples
    the run must produce.  It is never clamped, rounded or replaced with a
    default.  Booleans, floats and strings are rejected.
    """

    model_config = ConfigDict(
        strict=True,
        json_schema_extra={
            "description": (
                "Exact number of successful samples to generate. Must be a "
                "positive integer; booleans, floats and strings are rejected. "
                "Rejected when above the configured safety maximum."
            ),
            "examples": [2, 50, 500],
        },
    )

    target_samples: int = Field(
        ...,
        gt=0,
        description=(
            "Exact number of successfully committed dataset samples. "
            "Must be >= 1 and <= the configured maximum target samples."
        ),
    )

    @field_validator("target_samples")
    @classmethod
    def _reject_boolean(cls, value):
        if isinstance(value, bool):
            raise ValueError(
                "target_samples must be a positive integer, not a boolean"
            )
        return value


class DatasetRunStatusResponse(BaseModel):
    """Current state of a dataset run (progress is success-based)."""

    dataset_run_id: str
    status: str
    target_samples: int
    successful_samples: int
    attempted_runs: int
    failed_samples: int
    interrupted_samples: int
    committed_samples: int
    current_sequence: int | None = None
    current_experiment: str | None = None
    current_security_posture: str | None = None
    current_traffic_profile: str | None = None
    current_configuration: dict | None = None
    progress_percentage: float | None = None
    finalization: dict | None = None
    error: str | None = None


class DatasetRunResultsResponse(BaseModel):
    """Lightweight results summary (never the full feature table)."""

    dataset_run_id: str
    status: str
    target_samples: int
    successful_samples: int
    attempted_runs: int
    failed_samples: int
    interrupted_samples: int
    traffic_distribution: dict
    security_posture_distribution: dict
    feature_row_count: int | None = None
    metadata_record_count: int | None = None
    artifact_paths: dict
    finalization: dict | None = None


class DatasetSettingsResponse(BaseModel):
    """Operational settings a frontend needs before posting a run."""

    maximum_target_samples: int


# ---------------------------------------------------------------------------
# Response builders -- read / derive from persisted state only.
# ---------------------------------------------------------------------------

def status_payload(run, finalization=None):
    """One status dict from the persisted DatasetRun (never fabricated)."""
    target = run.target_samples
    successful = run.data["successful_samples"]
    if target > 0:
        progress = round(successful / target * 100.0, 2)
    else:
        progress = 0.0
    return {
        "dataset_run_id": run.id,
        "status": run.status,
        "target_samples": target,
        "successful_samples": successful,
        "attempted_runs": run.data["attempted_runs"],
        "failed_samples": run.data["failed_samples"],
        "interrupted_samples": run.data["interrupted_samples"],
        "committed_samples": len(run.data["committed_run_ids"]),
        "current_sequence": run.data["current_sequence"],
        "current_experiment": run.data["current_experiment"],
        "current_security_posture": run.data["current_security_posture"],
        "current_traffic_profile": run.data["current_traffic_profile"],
        "current_configuration": run.data["current_configuration"],
        "progress_percentage": progress,
        "finalization": finalization,
        "error": run.data.get("error"),
    }


def _read_finalization(run):
    path = run.directory / artifacts_mod.FINALIZATION_FILENAME
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (ValueError, OSError):
        return None


def _committed_distributions(run, plan):
    """Observed traffic/posture counts over committed samples only.

    Committed samples are read from ``committed_run_ids`` (the authoritative
    Module 3/4 counter) and mapped to their plan sample; nothing else is
    derived here.  Returns ({}, {}) for a run with no committed samples.
    """
    traffic = Counter()
    posture = Counter()
    if plan is None:
        return {}, {}
    by_seq = {s["sequence"]: s for s in plan.get("samples", [])}
    for experiment_id in run.data.get("committed_run_ids", []):
        parsed = parse_experiment_id(experiment_id)
        if parsed is None:
            continue
        sample = by_seq.get(parsed[1])
        if sample is None:
            continue
        traffic[sample["traffic_profile"]] += 1
        posture[sample["security_posture"]] += 1
    return dict(traffic), dict(posture)


def results_payload(run, plan, finalization=None):
    feature_row_count = None
    metadata_record_count = None
    artifact_paths = {}

    parquet = run.directory / artifacts_mod.FEATURES_PARQUET_FILENAME
    metadata = run.directory / artifacts_mod.METADATA_FILENAME
    plan_path = run.directory / "staging" / PLAN_FILENAME

    if parquet.exists():
        try:
            import pyarrow.parquet as pq
            feature_row_count = pq.read_metadata(parquet).num_rows
        except Exception:
            feature_row_count = None
        artifact_paths["features_parquet"] = str(
            run.directory / artifacts_mod.FEATURES_PARQUET_FILENAME
        )
    if metadata.exists():
        metadata_record_count = sum(
            1 for _line in metadata.read_text(encoding="utf-8").splitlines()
            if _line.strip()
        )
        artifact_paths["metadata"] = str(
            run.directory / artifacts_mod.METADATA_FILENAME
        )
    if plan is not None:
        artifact_paths["plan"] = str(plan_path)
    artifact_paths["staging"] = str(
        run.directory / artifacts_mod.STAGING_SUBDIR
    )

    traffic, posture = _committed_distributions(run, plan)
    return {
        "dataset_run_id": run.id,
        "status": run.status,
        "target_samples": run.target_samples,
        "successful_samples": run.data["successful_samples"],
        "attempted_runs": run.data["attempted_runs"],
        "failed_samples": run.data["failed_samples"],
        "interrupted_samples": run.data["interrupted_samples"],
        "traffic_distribution": traffic,
        "security_posture_distribution": posture,
        "feature_row_count": feature_row_count,
        "metadata_record_count": metadata_record_count,
        "artifact_paths": artifact_paths,
        "finalization": finalization,
    }


# ---------------------------------------------------------------------------
# Background worker
# ---------------------------------------------------------------------------

def _run_dataset_worker(results_root, dataset_run_id, lock, *, run_attempt_fn,
                        cleanup_fn, collector_fn, max_attempts_per_sequence):
    """Execute and finalize one dataset run; release the testbed afterwards.

    Catches nothing it can avoid: ``execute_dataset_run`` (Modules 3/4) and
    ``finalize_dataset`` (Module 5) own all orchestration and validation.  If
    they raise, the failure is recorded on the run (unless it already
    completed) and the testbed is always released.
    """
    runner = run_attempt_fn if run_attempt_fn is not None else executor_mod.run_attempt
    cleaner = cleanup_fn if cleanup_fn is not None else executor_mod.cleanup_attempt
    collector = collector_fn
    if collector is None:
        collector = artifacts_mod.collect_successful_sample
    try:
        run = executor_mod.execute_dataset_run(
            results_root, dataset_run_id,
            run_attempt_fn=runner,
            cleanup_fn=cleaner,
            max_attempts_per_sequence=max_attempts_per_sequence,
            collector_fn=collector,
        )
        if run.status == STATUS_COMPLETED:
            artifacts_mod.finalize_dataset(results_root, dataset_run_id)
    except Exception as exc:
        try:
            run = dataset_run_mod.load_dataset_run(
                results_root, dataset_run_id
            )
            if run.status != STATUS_COMPLETED:
                run.update(
                    status=executor_mod.STATUS_FAILED,
                    error=(
                        f"background execution failed "
                        f"({type(exc).__name__}: {exc})"
                    ),
                )
        except Exception:
            pass
    finally:
        lock.release(DATASET, dataset_run_id)


# ---------------------------------------------------------------------------
# Load helpers
# ---------------------------------------------------------------------------

def _load_run(results_root, dataset_run_id):
    """Load a run: 404 when absent, 500 when persisted state is corrupt."""
    try:
        dataset_run_mod.validate_dataset_run_id(dataset_run_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    try:
        return dataset_run_mod.load_dataset_run(results_root, dataset_run_id)
    except FileNotFoundError:
        raise HTTPException(
            status_code=404, detail=f"dataset run not found: {dataset_run_id}"
        )
    except (ValueError, json.JSONDecodeError) as exc:
        raise HTTPException(
            status_code=500,
            detail=f"dataset run state is corrupt and will not be repaired: {exc}",
        )


def _load_plan_or_none(results_root, dataset_run_id):
    path = dataset_run_mod.run_directory(
        results_root, dataset_run_id
    ) / "staging" / PLAN_FILENAME
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (ValueError, OSError):
        return None


def _allocate_dataset_run_id(results_root):
    """A fresh, filesystem-safe run id (pattern preserved for Module 1).

    ``generate_dataset_run_id()`` has one-second resolution, so repeated calls
    inside the same second return the *same* id.  When a freshly-generated id
    collides with an existing run directory (rapid duplicate POSTs, or a run
    started earlier in the same second) we walk backwards through distinct
    seconds so every candidate is a different, valid ``dataset-%Y%m%d-%H%M%S``
    id instead of looping forever on one equal string.
    """
    for offset in range(100_000):
        candidate = "dataset-" + time.strftime(
            "%Y%m%d-%H%M%S", time.localtime(time.time() - offset)
        )
        if not dataset_run_mod.run_directory(results_root, candidate).exists():
            return candidate
    raise RuntimeError("could not allocate a unique dataset run id")


# ---------------------------------------------------------------------------
# Router factory (a fresh router per app; tests inject fakes/max limits)
# ---------------------------------------------------------------------------

def create_dataset_router(
    *,
    results_root=None,
    max_target_samples=DEFAULT_MAX_TARGET_SAMPLES,
    max_attempts_per_sequence=DEFAULT_ATTEMPTS_PER_SEQUENCE,
    run_attempt_fn=None,
    cleanup_fn=None,
    collector_fn=None,
    lock=None,
    background=True,
):
    """Build the dataset-run ``APIRouter``.

    ``results_root``       where DatasetRuns live (default ``results``).
    ``max_target_samples`` safety ceiling for the requested target.
    ``run_attempt_fn`` / ``cleanup_fn`` / ``collector_fn`` dependency
                           injection for tests (defaults are the real Module
                           3/4/5 implementations).
    ``lock``               the shared ``TestbedLock`` reservation registry
                           (defaults to a private one; the real app passes the
                           single ``TESTBED_LOCK`` shared with the manual API).
    ``background``         execute on a worker thread (production) instead of
                           inline (used by deterministic unit tests).
    """
    results_root = results_root if results_root is not None else DEFAULT_RESULTS_ROOT
    lock = lock if lock is not None else TestbedLock()
    router = APIRouter()

    def _spawn(run_id):
        if background:
            thread = Thread(
                target=_run_dataset_worker,
                args=(results_root, run_id, lock),
                kwargs={
                    "run_attempt_fn": run_attempt_fn,
                    "cleanup_fn": cleanup_fn,
                    "collector_fn": collector_fn,
                    "max_attempts_per_sequence": max_attempts_per_sequence,
                },
                daemon=True,
            )
            thread.start()
        else:
            _run_dataset_worker(
                results_root, run_id, lock,
                run_attempt_fn=run_attempt_fn,
                cleanup_fn=cleanup_fn,
                collector_fn=collector_fn,
                max_attempts_per_sequence=max_attempts_per_sequence,
            )

    @router.get("/dataset-runs/settings",
                response_model=DatasetSettingsResponse,
                summary="Dataset generation settings")
    def get_settings():
        return {"maximum_target_samples": max_target_samples}

    @router.post("/dataset-runs",
                 response_model=DatasetRunStatusResponse,
                 status_code=201,
                 summary="Create and start a dataset run",
                 responses={
                     422: {"description": "Invalid target_samples (non-positive, "
                                         "non-integer, boolean, or above the "
                                         "configured safety maximum)"},
                     409: {"description": "Another dataset run or a manual "
                                          "experiment is already using the "
                                          "shared testbed"},
                 })
    def create_dataset_run(request: DatasetTargetRequest):
        target = request.target_samples
        if target > max_target_samples:
            raise HTTPException(
                status_code=422,
                detail=(
                    f"target_samples {target} exceeds the configured maximum "
                    f"of {max_target_samples}"
                ),
            )

        dataset_run_id = _allocate_dataset_run_id(results_root)
        reserved, owner = lock.try_reserve(DATASET, dataset_run_id)
        if not reserved:
            kind, owner_id = owner
            raise HTTPException(
                status_code=409,
                detail=(
                    f"the shared testbed is already in use by {kind} "
                    f"'{owner_id}'; a dataset run cannot start now"
                ),
            )

        try:
            run = dataset_run_mod.create_dataset_run(
                results_root, target, dataset_run_id=dataset_run_id
            )
            plan = planner_mod.build_sample_plan(target)
            planner_mod.write_sample_plan(
                results_root, dataset_run_id, plan
            )
        except HTTPException:
            lock.release(DATASET, dataset_run_id)
            raise
        except Exception as exc:
            lock.release(DATASET, dataset_run_id)
            raise HTTPException(
                status_code=500,
                detail=f"could not create the dataset run: {exc}",
            )

        _spawn(dataset_run_id)
        loaded = dataset_run_mod.load_dataset_run(
            results_root, dataset_run_id
        )
        return status_payload(loaded, _read_finalization(loaded))

    @router.get("/dataset-runs/{dataset_run_id}",
                response_model=DatasetRunStatusResponse,
                summary="Get dataset run state and success-based progress",
                responses={404: {"description": "Dataset run not found"},
                           500: {"description": "Persisted dataset run state "
                                               "is corrupt"}})
    def get_dataset_run(dataset_run_id: str):
        run = _load_run(results_root, dataset_run_id)
        return status_payload(run, _read_finalization(run))

    @router.post("/dataset-runs/{dataset_run_id}/resume",
                 response_model=DatasetRunStatusResponse,
                 summary="Resume a paused (or created) dataset run",
                 responses={
                     404: {"description": "Dataset run not found"},
                     400: {"description": "Plan fingerprint mismatch; the run "
                                          "cannot be resumed with a different "
                                          "plan"},
                     409: {"description": "Already running, already completed, "
                                          "failed, or the shared testbed is "
                                          "otherwise in use"},
                     500: {"description": "Persisted dataset run state is "
                                          "corrupt"},
                 })
    def resume_dataset_run(dataset_run_id: str):
        run = _load_run(results_root, dataset_run_id)
        finalization = _read_finalization(run)

        if run.status == STATUS_COMPLETED:
            return {
                **status_payload(run, finalization),
                "status": run.status,
            }
        if run.status == STATUS_RUNNING:
            raise HTTPException(
                status_code=409,
                detail=(
                    f"dataset run {dataset_run_id} is already running; "
                    f"no second worker will be started"
                ),
            )
        if run.status == executor_mod.STATUS_FAILED:
            raise HTTPException(
                status_code=409,
                detail=(
                    f"dataset run {dataset_run_id} is FAILED and cannot be "
                    f"resumed"
                ),
            )

        # CREATED or PAUSED: if a plan was ever started (fingerprint set),
        # make sure the persisted plan still matches before resuming.
        stored_fingerprint = run.data.get("plan_fingerprint")
        if stored_fingerprint is not None:
            plan = _load_plan_or_none(results_root, dataset_run_id)
            if plan is None:
                raise HTTPException(
                    status_code=400,
                    detail="plan.json is missing; cannot resume this run",
                )
            if executor_mod.plan_fingerprint(plan) != stored_fingerprint:
                raise HTTPException(
                    status_code=400,
                    detail=(
                        f"plan.json for dataset run {dataset_run_id} differs "
                        f"from the plan it started with; refusing to resume"
                    ),
                )

        reserved, owner = lock.try_reserve(DATASET, dataset_run_id)
        if not reserved:
            kind, owner_id = owner
            raise HTTPException(
                status_code=409,
                detail=(
                    f"the shared testbed is already in use by {kind} "
                    f"'{owner_id}'; the run cannot resume now"
                ),
            )

        _spawn(dataset_run_id)
        loaded = dataset_run_mod.load_dataset_run(
            results_root, dataset_run_id
        )
        return status_payload(loaded, _read_finalization(loaded))

    @router.get("/dataset-runs/{dataset_run_id}/results",
                response_model=DatasetRunResultsResponse,
                summary="Lightweight results summary",
                responses={404: {"description": "Dataset run not found"},
                           500: {"description": "Persisted dataset run state "
                                               "is corrupt"}})
    def get_dataset_run_results(dataset_run_id: str):
        run = _load_run(results_root, dataset_run_id)
        finalization = _read_finalization(run)
        plan = _load_plan_or_none(results_root, dataset_run_id)
        return results_payload(run, plan, finalization)

    @router.get("/dataset-runs/{dataset_run_id}/download",
                summary="Download a completed dataset run as a ZIP archive",
                responses={
                    404: {"description": "Dataset run not found"},
                    409: {"description": "Dataset run is not a finalized, "
                                        "completed dataset (running, paused, "
                                        "failed, or not yet finalized)"},
                    422: {"description": "A final dataset artifact is missing "
                                        "or unreadable"},
                })
    def download_dataset_run(dataset_run_id: str):
        """Return the final dataset archive for a COMPLETED run.

        Only a run whose engine status and artifact finalization are both
        COMPLETED can be downloaded.  The archive is built from the four final
        artifacts on disk (features.parquet, metadata.jsonl, manifest.json,
        README.txt) into a temporary file and streamed back in chunks so the
        full ZIP is never held in memory; the temporary file is removed after
        streaming.  Source artifacts are never modified or deleted.
        """
        run = _load_run(results_root, dataset_run_id)
        finalization = _read_finalization(run)

        if run.status != STATUS_COMPLETED:
            raise HTTPException(
                status_code=409,
                detail=(
                    f"dataset run {dataset_run_id} is not a completed dataset "
                    f"(status {run.status}); only finalized COMPLETED runs "
                    f"can be downloaded"
                ),
            )
        if finalization is None or finalization.get("status") != "COMPLETED":
            raise HTTPException(
                status_code=409,
                detail=(
                    f"dataset run {dataset_run_id} is not finalized yet; "
                    f"artifacts are not ready for download"
                ),
            )

        # Every included file is validated to exist and stay inside this run's
        # directory before any archive is built (path-traversal guard).
        try:
            artifacts_mod.export_artifact_paths(run)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc))

        zip_path = None
        try:
            fd, zip_path = tempfile.mkstemp(
                prefix=f"{dataset_run_id}-", suffix=".zip"
            )
            os.close(fd)
            artifacts_mod.build_dataset_zip(run, zip_path)
        except Exception as exc:
            if zip_path is not None:
                try:
                    os.remove(zip_path)
                except OSError:
                    pass
            raise HTTPException(
                status_code=422,
                detail=f"final dataset artifacts could not be bundled: {exc}",
            )

        def _stream_archive():
            try:
                with open(zip_path, "rb") as fh:
                    while True:
                        chunk = fh.read(64 * 1024)
                        if not chunk:
                            return
                        yield chunk
            finally:
                try:
                    os.remove(zip_path)
                except OSError:
                    pass

        return StreamingResponse(
            _stream_archive(),
            media_type="application/zip",
            headers={
                "Content-Disposition": (
                    f'attachment; filename="{dataset_run_id}.zip"'
                )
            },
        )

    return router