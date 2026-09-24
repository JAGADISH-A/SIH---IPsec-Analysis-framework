"""Generic repeated-experiment runner (repurposed Modules 3/4 engine).

Orchestrates any repeated-experiment run: one committed sample per logical
sequence, retry-within-budget, durable attempt markers, crash recovery, plan
fingerprint pinning, stale-environment guard, and the exactly-once topology
teardown lifecycle.

The engine is application-agnostic.  It owns only the reliability machinery
(attempt budget, commit invariants, plan pinning, crash recovery, stale guard,
cleanup ordering, terminal teardown).  The per-attempt pipeline, cleanup hook,
optional artifact collector, topology-reuse manager and plan loader/validator
are injected by the caller.

Usage::

    from . import experiment_runner as engine_mod

    reuse_manager = reuse_mod.TopologyReuseManager(log=log)
    run = engine_mod.execute_repeated_run(
        results_root, run_id,
        load_plan_fn=my_load_plan,
        run_attempt_fn=my_run_attempt,
        cleanup_fn=my_cleanup,
        validate_plan_fn=my_validate_plan,   # optional
        collector_fn=my_collect,              # optional
        run_options=engine_mod.RunOptions(duration=30, port=20000),
        reuse_manager=reuse_manager,
        teardown_fn=my_teardown,
        log=log,
    )

Persistence follows the Module 1 DatasetRun state model and atomic writers:

* successful samples  -> ``<run>/experiments/<experiment_id>/``
* failed/interrupted  -> ``<run>/failures/<experiment_id>/``
* in-flight scratch   -> ``<run>/staging/tmp/<experiment_id>/``

Every attempt performs cleanup before the next one starts.  Executions are
strictly sequential.  No experiment is executed by unit tests; the pipeline
is injected (``run_attempt_fn``).
"""

import copy
import hashlib
import json
import re
import shutil
from dataclasses import dataclass
from pathlib import Path

from . import capture as capture_mod
from . import dataset as dataset_mod
from . import dataset_run as dataset_run_mod
from .traffic import DEFAULT_DURATION, DEFAULT_PORT

# ── outcome / status constants ─────────────────────────────────────────────

OUTCOME_SUCCESS = "SUCCESS"
OUTCOME_FAILED = "FAILED"
OUTCOME_INTERRUPTED = "INTERRUPTED"
VALID_OUTCOMES = {OUTCOME_SUCCESS, OUTCOME_FAILED, OUTCOME_INTERRUPTED}

STATUS_RUNNING = "RUNNING"
STATUS_PAUSED = "PAUSED"
STATUS_COMPLETED = "COMPLETED"
STATUS_FAILED = "FAILED"

DEFAULT_ATTEMPTS_PER_SEQUENCE = 5

# ── persistence layout ─────────────────────────────────────────────────────

STAGING_TMP_SUBDIR = "tmp"
EXPERIMENTS_SUBDIR = "experiments"
FAILURES_SUBDIR = "failures"

# ── experiment id protocol ─────────────────────────────────────────────────

EXPERIMENT_ID_RE = re.compile(r"\A(.+)-exp-(\d+)-attempt-(\d+)\Z")


def experiment_id_for(run_id, seq, attempt):
    """Unique, traceable id for one physical attempt."""
    return f"{run_id}-exp-{seq:04d}-attempt-{attempt:02d}"


def parse_experiment_id(experiment_id):
    """Return (run_id, sequence, attempt) or None if not ours."""
    match = EXPERIMENT_ID_RE.fullmatch(experiment_id)
    if match is None:
        return None
    return match.group(1), int(match.group(2)), int(match.group(3))


# ── plan helpers ───────────────────────────────────────────────────────────

def plan_fingerprint(plan):
    """Stable content hash of a plan's target and ordered samples.

    Used to pin the exact plan a run started with so a resume cannot silently
    switch to a different (re-generated or hand-edited) plan.
    """
    canonical = json.dumps(
        {
            "samples": plan["samples"],
            "target_samples": plan["target_samples"],
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def validate_repeated_plan(plan):
    """Generic structural validation for any repeated-experiment plan.

    Checks the protocol fields (target_samples, samples list, contiguous
    unique sequences 1..target).  Application-specific validation (posture,
    IPsec configuration, traffic profiles) should be supplied via
    ``validate_plan_fn``.
    """
    if not isinstance(plan, dict):
        raise ValueError("plan must be a dict")
    samples = plan.get("samples")
    if not isinstance(samples, list) or not samples:
        raise ValueError("plan must contain a non-empty 'samples' list")

    target = plan.get("target_samples")
    if isinstance(target, bool) or not isinstance(target, int) or target <= 0:
        raise ValueError(f"invalid plan target_samples: {target!r}")
    if len(samples) != target:
        raise ValueError(
            f"plan samples length ({len(samples)}) differs from "
            f"target_samples ({target})"
        )

    for sample in samples:
        if not isinstance(sample, dict):
            raise ValueError("plan samples must be dicts")
        seq = sample.get("sequence")
        if isinstance(seq, bool) or not isinstance(seq, int) or not (1 <= seq <= target):
            raise ValueError(f"invalid plan sequence: {seq!r}")

    sequences = [s.get("sequence") for s in samples]
    if sorted(sequences) != list(range(1, target + 1)):
        raise ValueError("plan sequences must be contiguous 1..target")
    if len(set(sequences)) != len(sequences):
        raise ValueError("plan sequences must be unique")
    return True


# ── run state helpers ──────────────────────────────────────────────────────

def committed_sequences(run):
    """Set of sequences that already have a committed successful sample."""
    committed = set()
    for run_id in run.data["committed_run_ids"]:
        parsed = parse_experiment_id(run_id)
        if parsed is not None:
            committed.add(parsed[1])
    return committed


def next_sequence_to_run(run, target_samples):
    """First sequence without a committed sample, or None when complete."""
    committed = committed_sequences(run)
    for seq in range(1, target_samples + 1):
        if seq not in committed:
            return seq
    return None


def validate_runtime_state(run, target_samples):
    """Engine-level consistency checks on committed_run_ids / successful_samples.

    These enforce the success/commit invariants that Module 1 deliberately
    leaves open at the schema level.  A run that the executor manages must
    always satisfy:

    * ``successful_samples <= target_samples``
    * ``len(committed_run_ids) == successful_samples``
    * each committed id is this run's experiment id, its sequence is within
      ``1..target_samples``, and no sequence is committed twice

    Raises ValueError when an inconsistency is found.
    """
    data = run.data
    successful = data["successful_samples"]
    committed = data["committed_run_ids"]

    if successful > target_samples:
        raise ValueError(
            f"state inconsistent: successful_samples ({successful}) exceeds "
            f"target_samples ({target_samples})"
        )
    if len(committed) != successful:
        raise ValueError(
            f"state inconsistent: successful_samples={successful} but "
            f"committed_run_ids has {len(committed)} entries"
        )

    committed_seqs = set()
    for exp_id in committed:
        parsed = parse_experiment_id(exp_id)
        if parsed is None:
            raise ValueError(
                f"state inconsistent: committed_run_ids entry '{exp_id}' is "
                f"not an experiment id"
            )
        commit_run_id, seq, _attempt = parsed
        if commit_run_id != run.id:
            raise ValueError(
                f"state inconsistent: committed_run_ids entry '{exp_id}' "
                f"belongs to run '{commit_run_id}'"
            )
        if not (1 <= seq <= target_samples):
            raise ValueError(
                f"state inconsistent: committed_run_ids entry '{exp_id}' has "
                f"sequence {seq} outside 1..{target_samples}"
            )
        if seq in committed_seqs:
            raise ValueError(
                f"state inconsistent: sequence {seq} committed more than once"
            )
        committed_seqs.add(seq)
    return True


def _ensure_executor_state_fields(run):
    """Back-fill engine-owned state fields missing from older state files."""
    data = run.data
    defaults = {
        "attempts_per_sequence": {},
        "attempt_in_progress": None,
        "plan_fingerprint": None,
        "stale_sequence": None,
        "stale_experiment": None,
    }
    missing = {key: value for key, value in defaults.items() if key not in data}
    if not missing:
        return
    data.update(missing)
    run._persist()


# ── internal helpers ───────────────────────────────────────────────────────

def _attempt_count(run, seq):
    """Number of physical attempts that have started for ``seq``."""
    return run.data["attempts_per_sequence"].get(str(seq), 0)


def _record_attempt_start(run, seq, attempt, experiment_id, config,
                          profile, posture):
    """Durably mark that a physical attempt is about to start.

    This is the durable "attempt N has started" record: it persists the
    attempt number (budget slot) and the ``attempt_in_progress`` marker that
    SIGKILL recovery relies on.  The marker is cleared only when the outcome
    is recorded, so an attempt number is never silently reused after a crash.
    """
    per_seq = dict(run.data["attempts_per_sequence"])
    per_seq[str(seq)] = attempt
    return run.update(
        attempts_per_sequence=per_seq,
        attempt_in_progress={
            "sequence": seq,
            "attempt": attempt,
            "experiment_id": experiment_id,
        },
        current_sequence=seq,
        current_experiment=experiment_id,
        current_configuration=config,
        current_traffic_profile=profile,
        current_security_posture=posture,
        status=STATUS_RUNNING,
    )


def _mark_stale(run, stale_sequence, stale_experiment, message):
    """Record that an attempt's environment could not be cleaned up."""
    return run.update(
        stale_sequence=stale_sequence,
        stale_experiment=stale_experiment,
        error=message,
    )


def _cleanup_attempt(run, experiment_id, sample, tmp_dir, cleanup_fn,
                     fail_dir=None, log=None, skip_destroy=False):
    """Run cleanup, and if it raises, record it safely.

    ``skip_destroy=True`` preserves the containerlab topology for the next
    same-mode sample (Module 10 reuse).

    A cleanup failure NEVER changes the attempt's outcome.  It is recorded
    separately (``cleanup_error.log`` when a failure directory exists) and in
    the run state as a stale-environment marker so the next attempt re-cleans
    before starting.
    """
    log = log or (lambda msg: None)
    try:
        cleanup_fn(experiment_id, sample, tmp_dir, skip_destroy=skip_destroy)
        return True
    except Exception as exc:
        message = (
            f"cleanup failed for {experiment_id} "
            f"({type(exc).__name__}: {exc})"
        )
        if fail_dir is not None:
            try:
                (Path(fail_dir) / "cleanup_error.log").write_text(
                    message, encoding="utf-8"
                )
            except OSError:
                pass
        _mark_stale(run, sample["sequence"], experiment_id, message)
        log(f"[seq {sample['sequence']}] {message}")
        return False


def _stale_guard(run, samples_by_seq, cleanup_fn, log):
    """Re-clean a stale environment before starting any new attempt.

    Returns True when it is safe to start the next attempt.  If the stale
    environment cannot be re-cleaned the run is PAUSED so no attempt starts
    blindly into a potentially contaminated testbed.
    """
    stale_seq = run.data.get("stale_sequence")
    stale_exp = run.data.get("stale_experiment")
    if stale_seq is None or stale_exp is None:
        return True
    sample = samples_by_seq.get(stale_seq)
    if sample is None:
        raise ValueError(
            f"stale_sequence {stale_seq} has no sample in the plan"
        )
    tmp_dir = run.directory / STAGING_TMP_SUBDIR / stale_exp
    log(f"[seq {stale_seq}] stale environment for {stale_exp}: re-cleaning")
    try:
        cleanup_fn(stale_exp, sample, tmp_dir)
    except Exception as exc:
        run.update(
            status=STATUS_PAUSED,
            error=(
                f"stale environment {stale_exp} could not be re-cleaned "
                f"({type(exc).__name__}: {exc}); refusing to continue"
            ),
        )
        log(f"[seq {stale_seq}] stale cleanup failed -> run PAUSED")
        return False
    run.update(stale_sequence=None, stale_experiment=None, error=None)
    log(f"[seq {stale_seq}] stale environment re-cleaned")
    return True


def _recover_orphaned_attempt(run, sample, seq, experiment_id, cleanup_fn, log):
    """Clean up the environment of an attempt killed before its outcome.

    Called on resume when ``attempt_in_progress`` still points at an attempt
    whose outcome was never recorded (SIGKILL / abrupt process death).  The
    attempt already consumed its budget slot; its number is never reused.
    """
    tmp_dir = run.directory / STAGING_TMP_SUBDIR / experiment_id
    log(f"[seq {seq}] cleaning up orphaned attempt {experiment_id}")
    try:
        cleanup_fn(experiment_id, sample, tmp_dir)
    except Exception as exc:
        run.update(
            status=STATUS_PAUSED,
            error=(
                f"could not clean up orphaned attempt {experiment_id} "
                f"({type(exc).__name__}: {exc}); environment may be unsafe"
            ),
        )
        return False
    return True


# ── artifact persistence (generic) ─────────────────────────────────────────

def persist_successful_sample(run, experiment_id, outcome):
    """Store one committed sample under <run>/experiments/<experiment_id>/."""
    exp_dir = run.directory / EXPERIMENTS_SUBDIR / experiment_id
    exp_dir.mkdir(parents=True, exist_ok=True)
    dataset_run_mod._atomic_write_json(exp_dir / "metadata.json", outcome["metadata"])
    dataset_run_mod._atomic_write_json(exp_dir / "features.json", outcome["features"])
    if outcome.get("traffic_log"):
        (exp_dir / "traffic.log").write_text(outcome["traffic_log"], encoding="utf-8")
    if outcome.get("pcap_path"):
        shutil.copy2(outcome["pcap_path"], exp_dir / "capture.pcap")
    return exp_dir


def persist_failure(run, experiment_id, sample, attempt, outcome):
    """Store a debug record for a failed/interrupted attempt."""
    fail_dir = run.directory / FAILURES_SUBDIR / experiment_id
    fail_dir.mkdir(parents=True, exist_ok=True)
    record = {
        "run_id": run.id,
        "dataset_run_id": run.id,
        "experiment_id": experiment_id,
        "sequence": sample.get("sequence"),
        "attempt": attempt,
        "status": outcome["status"],
        "reason": outcome.get("reason"),
        "error": outcome.get("error"),
        "traffic_profile": sample.get("traffic_profile"),
        "security_posture": sample.get("security_posture"),
        "configuration_id": sample.get("configuration_id"),
        "ipsec_configuration": sample.get("ipsec_configuration"),
        "timestamp": dataset_mod.utcnow_iso(),
    }
    dataset_run_mod._atomic_write_json(fail_dir / "failure.json", record)
    if outcome.get("error"):
        (fail_dir / "error.log").write_text(outcome["error"], encoding="utf-8")
    return fail_dir


def _preserve_partial_artifacts(tmp_dir, fail_dir):
    """Copy any partial capture/logs left by a failed attempt into failures/."""
    source = Path(tmp_dir)
    if not source.is_dir():
        return
    dest_dir = Path(fail_dir) / "partial"
    try:
        dest_dir.mkdir(parents=True, exist_ok=True)
    except OSError:
        return
    for entry in source.iterdir():
        if entry.is_file():
            try:
                shutil.copy2(entry, dest_dir / entry.name)
            except OSError:
                pass


def _record_interruption(run, experiment_id, sample, attempt, error):
    outcome = {
        "status": OUTCOME_INTERRUPTED,
        "experiment_id": experiment_id,
        "reason": "KeyboardInterrupt",
        "error": error or "interrupted before completion",
    }
    persist_failure(run, experiment_id, sample, attempt, outcome)
    return outcome


# ── RunOptions (traffic/capture parameterization) ──────────────────────────

@dataclass(frozen=True)
class RunOptions:
    """Run-level runtime knobs applied to every trial of a repeated run.

    ``duration`` / ``port`` / ``capture_filter`` are merged into each sample's
    ``traffic`` dict (per-sample overrides win), so the injected
    ``run_attempt_fn`` receives them without a signature change.  Defaults
    preserve the historical dataset behaviours (30 s, port 20000) while the
    capture default is the testbed-wide canonical filter (IKE negotiation +
    ESP data [+ AH], see :data:`controller.capture.DEFAULT_CAPTURE_FILTER`);
    an ESP-only capture remains available via an explicit override.
    """

    duration: float = float(DEFAULT_DURATION)
    port: int = DEFAULT_PORT
    capture_filter: str = capture_mod.DEFAULT_CAPTURE_FILTER

    def traffic_overrides(self):
        """Return the three traffic-capture overrides as a plain dict."""
        return {
            "duration": float(self.duration),
            "port": self.port,
            "capture_filter": self.capture_filter,
        }


def _apply_run_options(sample, run_options):
    """Return a deep copy of ``sample`` with run-level traffic knobs merged.

    Per-sample keys already present in ``sample["traffic"]`` win over the
    run-level defaults (setdefault semantics).
    """
    merged = copy.deepcopy(sample)
    traffic = merged.setdefault("traffic", {})
    for key, value in run_options.traffic_overrides().items():
        traffic.setdefault(key, value)
    return merged


# ── sequence runner ────────────────────────────────────────────────────────

def _run_sequence(run, sample, samples_by_seq, results_root, run_attempt_fn,
                  cleanup_fn, max_attempts, collector_fn=None, log=None,
                  reuse_manager=None, run_options=None):
    """Run one logical sequence to completion.

    Returns "COMMITTED" after a successful commit, "PAUSED" on a signal
    interruption, stale-environment exhaustion, or an un-cleanable orphaned
    attempt, or "EXHAUSTED" when the total attempt budget for the sequence is
    used up (the run has been marked FAILED).

    ``reuse_manager`` is the persistent topology-reuse manager for the
    invocation; it is forwarded to ``run_attempt_fn`` so that consecutive
    successful samples can reuse an already-deployed topology in place.

    ``run_options`` optionally supplies run-level traffic/capture knobs that
    are merged into each attempt sample before calling ``run_attempt_fn``.

    When ``collector_fn`` is provided (Module 5), a successful attempt is only
    committed after its artifacts have been staged; an artifact persistence
    failure turns the attempt into a FAILED attempt (never a fabricated
    success), so a sample is never counted successful if its required artifacts
    cannot be safely persisted.

    Attempt-budget semantics
    ------------------------
    ``max_attempts`` is a TOTAL budget per logical sequence, cumulative across
    restarts/resumes, tracked durably in ``attempts_per_sequence`` and counted
    when an attempt STARTS.  A failed attempt, a returned-INTERRUPTED attempt
    and a killed attempt all consume budget slots.  A real KeyboardInterrupt
    pauses the run regardless of the budget.  Success is never fabricated.

    Fatal outcomes
    --------------
    A FAILED outcome carrying ``fatal: True`` (a non-retryable infrastructure
    failure, e.g. the topology cannot be deployed) marks the run FAILED with
    the actual error and returns "EXHAUSTED" immediately - the remaining
    per-sequence attempt budget is never burned on the same doomed deployment.
    """
    seq = sample["sequence"]
    config = sample.get("ipsec_configuration") or {}
    profile = sample.get("traffic_profile")
    posture = sample.get("security_posture")

    attempts_done = _attempt_count(run, seq)
    in_flight = run.data.get("attempt_in_progress")
    if in_flight is not None and in_flight.get("sequence") == seq:
        attempts_done = max(attempts_done, in_flight["attempt"])
        orphan_exp = in_flight["experiment_id"]
        if not _recover_orphaned_attempt(
            run, sample, seq, orphan_exp, cleanup_fn, log
        ):
            return "PAUSED"

    if attempts_done >= max_attempts:
        run.update(
            status=STATUS_FAILED,
            error=(
                f"sequence {seq} has reached its total attempt budget "
                f"({max_attempts}); pass a larger max_attempts_per_sequence "
                f"to retry"
            ),
        )
        log(f"[seq {seq}] attempt budget already exhausted -> run FAILED")
        return "EXHAUSTED"

    attempt = attempts_done
    while True:
        attempt += 1
        experiment_id = experiment_id_for(run.id, seq, attempt)
        tmp_dir = run.directory / STAGING_TMP_SUBDIR / experiment_id

        if not _stale_guard(run, samples_by_seq, cleanup_fn, log):
            return "PAUSED"

        _record_attempt_start(
            run, seq, attempt, experiment_id, config, profile, posture
        )
        log(f"[seq {seq}] attempt {attempt}/{max_attempts} "
            f"experiment={experiment_id}")

        interrupted_by_signal = False
        attempt_sample = (
            _apply_run_options(sample, run_options) if run_options else sample
        )
        try:
            outcome = run_attempt_fn(
                experiment_id, attempt_sample, tmp_dir, results_root,
                run_id=run.id, log=log, reuse=reuse_manager,
            )
        except KeyboardInterrupt:
            interrupted_by_signal = True
            outcome = _record_interruption(
                run, experiment_id, sample, attempt, "interrupted by signal"
            )
        except Exception as exc:
            outcome = {
                "status": OUTCOME_FAILED,
                "experiment_id": experiment_id,
                "reason": type(exc).__name__,
                "error": str(exc),
            }

        if outcome.get("status") not in VALID_OUTCOMES:
            raise ValueError(
                f"attempt runner returned invalid outcome: {outcome!r}"
            )

        if outcome["status"] == OUTCOME_SUCCESS:
            try:
                persist_successful_sample(run, experiment_id, outcome)
                if collector_fn is not None:
                    collector_fn(
                        run, experiment_id, attempt, sample, outcome,
                        log=log,
                    )
            except Exception as exc:
                outcome = {
                    "status": OUTCOME_FAILED,
                    "experiment_id": experiment_id,
                    "reason": "ArtifactError",
                    "error": (
                        f"successful sample could not be persisted "
                        f"({type(exc).__name__}: {exc})"
                    ),
                }
            else:
                run.update(
                    attempted_runs=run.data["attempted_runs"] + 1,
                    successful_samples=run.data["successful_samples"] + 1,
                    committed_run_ids=[
                        *run.data["committed_run_ids"], experiment_id
                    ],
                    attempt_in_progress=None,
                    current_sequence=seq,
                    current_experiment=experiment_id,
                    current_configuration=config,
                    current_traffic_profile=profile,
                    current_security_posture=posture,
                )
                _cleanup_attempt(
                    run, experiment_id, sample, tmp_dir, cleanup_fn, log=log,
                    skip_destroy=(reuse_manager is not None),
                )
                log(f"[seq {seq}] committed {experiment_id}")
                return "COMMITTED"

        fail_dir = persist_failure(run, experiment_id, sample, attempt, outcome)
        _preserve_partial_artifacts(tmp_dir, fail_dir)
        _cleanup_attempt(
            run, experiment_id, sample, tmp_dir, cleanup_fn,
            fail_dir=fail_dir, log=log,
            skip_destroy=(reuse_manager is not None),
        )

        if outcome["status"] == OUTCOME_INTERRUPTED:
            run.update(
                attempted_runs=run.data["attempted_runs"] + 1,
                interrupted_samples=run.data["interrupted_samples"] + 1,
                attempt_in_progress=None,
                current_sequence=seq,
                current_experiment=experiment_id,
                current_configuration=config,
                current_traffic_profile=profile,
                current_security_posture=posture,
            )
            log(f"[seq {seq}] attempt {attempt} INTERRUPTED: "
                f"{outcome.get('error')}")
        else:
            run.update(
                attempted_runs=run.data["attempted_runs"] + 1,
                failed_samples=run.data["failed_samples"] + 1,
                attempt_in_progress=None,
                current_sequence=seq,
                current_experiment=experiment_id,
                current_configuration=config,
                current_traffic_profile=profile,
                current_security_posture=posture,
            )
            log(f"[seq {seq}] attempt {attempt} FAILED: {outcome.get('error')}")

        if outcome.get("fatal"):
            reason = outcome.get("reason", "InfrastructureError")
            error = outcome.get("error") or (
                "the testbed topology could not be deployed"
            )
            run.update(
                status=STATUS_FAILED,
                error=(
                    f"fatal {reason}: {error}"
                ),
            )
            log(
                f"[seq {seq}] fatal infrastructure failure "
                f"({reason}) -> run FAILED without further retries"
            )
            return "EXHAUSTED"

        if interrupted_by_signal:
            run.update(
                status=STATUS_PAUSED,
                error=f"paused during sequence {seq} attempt {attempt}",
            )
            log(f"[seq {seq}] paused after interrupted attempt {attempt}")
            return "PAUSED"

        if attempt >= max_attempts:
            run.update(
                status=STATUS_FAILED,
                error=(
                    f"sequence {seq} exhausted its total attempt budget "
                    f"({max_attempts}); pass a larger "
                    f"max_attempts_per_sequence to retry"
                ),
            )
            log(f"[seq {seq}] giving up after {max_attempts} attempts "
                f"-> run FAILED")
            return "EXHAUSTED"


# ── top-level execution ────────────────────────────────────────────────────

def execute_repeated_run(results_root, run_id, *,
                         load_plan_fn,
                         run_attempt_fn,
                         cleanup_fn,
                         validate_plan_fn=None,
                         max_attempts_per_sequence=DEFAULT_ATTEMPTS_PER_SEQUENCE,
                         collector_fn=None,
                         run_options=None,
                         reuse_manager=None,
                         teardown_fn=None,
                         log=None):
    """Execute any repeated-experiment run until it is complete or unrecoverable.

    The engine owns ONLY the reliability machinery.  The application supplies:

    * ``load_plan_fn(results_root, run_id)`` -- loads and validates the plan
      (raises on missing/corrupt/divergent plans).
    * ``run_attempt_fn(experiment_id, sample, tmp_dir, results_root, ...)``
      -- one physical attempt; returns an outcome dict (SUCCESS/FAILED/INTERRUPTED).
    * ``cleanup_fn``         -- best-effort per-attempt environment cleanup.
    * ``validate_plan_fn``   -- optional extra per-application plan checks.
    * ``collector_fn``       -- optional artifact collector at the successful-commit
      boundary: ``collector_fn(run, experiment_id, attempt, sample, outcome, log=None)``.
    * ``run_options``        -- optional ``RunOptions`` traffic/capture knobs.
    * ``reuse_manager``      -- opaque topology-reuse manager forwarded to
      every attempt (None = no reuse).
    * ``teardown_fn``        -- optional terminal-state teardown
      ``(reuse_manager, log)``.

    Terminal states are COMPLETED (all sequences committed) or FAILED (budget
    exhausted or incomplete).  A real KeyboardInterrupt pauses the run so a
    later invocation resumes from the first uncommitted sequence.

    Returns the (persisted) run.
    """
    log = log or (lambda msg: None)
    if isinstance(max_attempts_per_sequence, bool) or not isinstance(
        max_attempts_per_sequence, int
    ):
        raise ValueError("max_attempts_per_sequence must be an integer")
    if max_attempts_per_sequence <= 0:
        raise ValueError("max_attempts_per_sequence must be > 0")

    run = dataset_run_mod.load_dataset_run(results_root, run_id)
    _ensure_executor_state_fields(run)
    validate_runtime_state(run, run.target_samples)

    if run.status == STATUS_COMPLETED:
        return run
    if run.status == STATUS_FAILED:
        raise ValueError(
            f"run '{run_id}' is FAILED and cannot be resumed"
        )

    plan = load_plan_fn(results_root, run_id)
    validate_repeated_plan(plan)
    if validate_plan_fn is not None:
        validate_plan_fn(plan)
    target = plan["target_samples"]
    if target != run.target_samples:
        raise ValueError(
            f"plan target ({target}) differs from run target "
            f"({run.target_samples})"
        )
    samples_by_seq = {s["sequence"]: s for s in plan["samples"]}

    fingerprint = plan_fingerprint(plan)
    if run.data.get("plan_fingerprint") is None:
        run.update(status=STATUS_RUNNING, plan_fingerprint=fingerprint)
    else:
        if run.data["plan_fingerprint"] != fingerprint:
            raise ValueError(
                "stored plan.json differs from the plan this run started with; "
                "refusing to resume with a different plan"
            )
        if run.status != STATUS_RUNNING:
            run.update(status=STATUS_RUNNING)
    log(f"run {run_id}: target={target} "
        f"already committed={len(committed_sequences(run))}")

    while True:
        seq = next_sequence_to_run(run, target)
        if seq is None:
            break
        result = _run_sequence(
            run, samples_by_seq[seq], samples_by_seq, results_root,
            run_attempt_fn, cleanup_fn, max_attempts_per_sequence,
            collector_fn=collector_fn, log=log, reuse_manager=reuse_manager,
            run_options=run_options,
        )
        if result == "EXHAUSTED":
            if teardown_fn is not None:
                teardown_fn(reuse_manager, log)
            return run
        if result == "PAUSED":
            return run

    if run.data["successful_samples"] != target:
        run.update(
            status=STATUS_FAILED,
            error=(
                f"run incomplete: successful_samples="
                f"{run.data['successful_samples']} != target={target}"
            ),
        )
        if teardown_fn is not None:
            teardown_fn(reuse_manager, log)
        return run

    validate_runtime_state(run, target)
    run.update(status=STATUS_COMPLETED)
    if teardown_fn is not None:
        teardown_fn(reuse_manager, log)
    log(f"run {run_id} COMPLETED: "
        f"successful={run.data['successful_samples']} "
        f"failed={run.data['failed_samples']} "
        f"interrupted={run.data['interrupted_samples']}")
    return run
