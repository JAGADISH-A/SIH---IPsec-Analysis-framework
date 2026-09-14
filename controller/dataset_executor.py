"""Dataset execution engine and success-based allocator (Module 3).

Consumes a Module 2 plan (``results/datasets/<id>/staging/plan.json``) and
executes every logical sample slot against the real testbed pipeline
(``campaign.execute_trial_pipeline``), preserving each slot's traffic profile,
security posture and IPsec configuration.

Concepts
--------
* Logical sequence  -- a row of the plan.  Exactly ONE successful committed
  sample per sequence (invariant).
* Physical attempt   -- one execution of the pipeline for a sequence.  A
  sequence may need many attempts; only a successful attempt commits it.
* Success            -- the full pipeline completes (deploy -> load ->
  initiate -> verify IPsec -> connectivity PASS -> capture -> traffic PASS ->
  features with ESP packets).  Nothing shorter counts as a sample.
* Retry              -- recoverable FAILED/INTERRUPTED attempts retry the
  SAME sequence with the same traffic profile and posture, within a total
  attempt budget per logical sequence (``max_attempts_per_sequence``, default
  5).  The budget counts attempts that STARTED (``state["attempts_per_sequence"]``)
  and is cumulative across restarts and resumes; interrupting or crashing an
  attempt never reuses its attempt number.  Exhausting the budget marks the
  run FAILED, never COMPLETED.  A real KeyboardInterrupt pauses the run
  (status PAUSED) so a later invocation resumes from the first uncommitted
  sequence; the same budget on resume may now be exhausted (the operator may
  explicitly pass a larger ``max_attempts_per_sequence`` to continue).

Hardening (Module 4)
--------------------
* Every attempt is marked in state (``attempt_in_progress``) BEFORE it starts
  and that marker is only cleared once the outcome is recorded, so SIGKILL or
  an abrupt process death leaves a durable record of "an attempt started but
  never finished".  Recovery never fabricates success: only a persisted
  ``committed_run_ids`` entry counts.  An uncommitted started attempt is
  retried with a NEW attempt number.
* The plan a run starts with is fingerprinted (``plan_fingerprint``) and a
  resume refuses to run if ``plan.json`` changed, is corrupt or is missing.
* A failed cleanup marks the environment stale (``stale_sequence`` /
  ``stale_experiment``); the next attempt re-cleans before starting and pauses
  if the re-clean fails.  A cleanup failure never turns a failed sample into a
  successful one.

Persistence follows the Module 1 DatasetRun state model and atomic writers:

* successful samples  -> ``<run>/experiments/<experiment_id>/``
* failed/interrupted  -> ``<run>/failures/<experiment_id>/``
* in-flight scratch   -> ``<run>/staging/tmp/<experiment_id>/``

Every attempt performs cleanup before the next one starts.  Executions are
strictly sequential (the shared Containerlab/StrongSwan environment is used by
one attempt at a time).  No experiment is executed by the unit tests; the
pipeline is injected (``run_attempt`` by default).
"""

import hashlib
import json
import re
import shutil
from pathlib import Path

from . import campaign as campaign_mod
from . import dataset as dataset_mod
from . import dataset_run as dataset_run_mod
from . import reuse as reuse_mod
from .dataset_planner import (
    PLAN_FILENAME,
    POSTURE_ORDER,
    validate_traffic_profile,
)
from .traffic import DEFAULT_DURATION, DEFAULT_PORT
from .validate import validate_config

OUTCOME_SUCCESS = "SUCCESS"
OUTCOME_FAILED = "FAILED"
OUTCOME_INTERRUPTED = "INTERRUPTED"
VALID_OUTCOMES = {OUTCOME_SUCCESS, OUTCOME_FAILED, OUTCOME_INTERRUPTED}

STATUS_RUNNING = "RUNNING"
STATUS_PAUSED = "PAUSED"
STATUS_COMPLETED = "COMPLETED"
STATUS_FAILED = "FAILED"

DEFAULT_ATTEMPTS_PER_SEQUENCE = 5

STAGING_TMP_SUBDIR = "tmp"
EXPERIMENTS_SUBDIR = "experiments"
FAILURES_SUBDIR = "failures"

# Experiment ids look like "<dataset_run_id>-exp-0012-attempt-03".
EXPERIMENT_ID_RE = re.compile(r"\A(.+)-exp-(\d+)-attempt-(\d+)\Z")


def experiment_id_for(dataset_run_id, seq, attempt):
    """Unique, traceable id for one physical attempt."""
    return f"{dataset_run_id}-exp-{seq:04d}-attempt-{attempt:02d}"


def parse_experiment_id(experiment_id):
    """Return (dataset_run_id, sequence, attempt) or None if not ours."""
    match = EXPERIMENT_ID_RE.fullmatch(experiment_id)
    if match is None:
        return None
    return match.group(1), int(match.group(2)), int(match.group(3))


def validate_plan(plan):
    """Structural/protocol validation of a Module 2 plan."""
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
        for key in (
            "sequence", "traffic_profile", "security_posture",
            "configuration_id", "ipsec_configuration",
        ):
            if key not in sample:
                raise ValueError(f"plan sample missing '{key}'")
        seq = sample["sequence"]
        if isinstance(seq, bool) or not isinstance(seq, int) or not (1 <= seq <= target):
            raise ValueError(f"invalid plan sequence: {seq!r}")
        validate_traffic_profile(sample["traffic_profile"])
        if sample["security_posture"] not in POSTURE_ORDER:
            raise ValueError(
                f"invalid security_posture '{sample['security_posture']}'"
            )
        if not isinstance(sample["configuration_id"], str) or not sample["configuration_id"]:
            raise ValueError("plan sample configuration_id must be a non-empty string")
        validate_config(sample["ipsec_configuration"])

    sequences = [s["sequence"] for s in samples]
    if sorted(sequences) != list(range(1, target + 1)):
        raise ValueError("plan sequences must be contiguous 1..target")
    if len(set(sequences)) != len(sequences):
        raise ValueError("plan sequences must be unique")

    if "traffic_quota" in plan:
        from collections import Counter
        observed = Counter(s["traffic_profile"] for s in samples)
        expected = plan["traffic_quota"]
        for profile, count in expected.items():
            if observed.get(profile, 0) != count:
                raise ValueError("plan traffic_quota does not match its samples")
    return True


def load_plan(results_root, dataset_run_id):
    """Load and validate the plan stored by Module 2 under staging/."""
    run_dir = dataset_run_mod.run_directory(results_root, dataset_run_id)
    plan_path = run_dir / "staging" / PLAN_FILENAME
    if not plan_path.exists():
        raise FileNotFoundError(f"plan not found: {plan_path}")
    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    validate_plan(plan)
    return plan


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
    """Executor-level consistency checks beyond the Module 1 schema.

    These enforce the success/commit invariants that Module 1 deliberately
    leaves open at the schema level (``committed_run_ids`` and
    ``successful_samples`` may be updated independently there).  A
    DatasetRun that the executor manages must always satisfy:

    * ``successful_samples <= target_samples``
    * ``len(committed_run_ids) == successful_samples`` (exactly one committed
      experiment id per successful sample)
    * each committed id is this run's experiment id, its sequence is within
      ``1..target_samples``, and no sequence is committed twice

    Raises ValueError when an inconsistency is found instead of guessing or
    silently repairing the state.
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
                f"not a dataset experiment id"
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


def _ensure_executor_state_fields(run):
    """Back-fill executor-owned state fields missing from older state files."""
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

    A cleanup failure NEVER changes the attempt's outcome (a failed sample
    stays failed; a committed success stays committed).  It is recorded
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


def run_attempt(experiment_id, sample, tmp_dir, results_root, run_id=None, log=None,
                reuse=None):
    """Execute one physical attempt with the real testbed pipeline.

    ``reuse`` is the persistent per-dataset-run ``TopologyReuseManager``
    (Module 10).  When ``None`` (the default) the attempt's pipeline performs
    the historical full fresh deployment for the sample.

    Returns an outcome dict:

      {"status": "SUCCESS", ..., "metadata", "features", "traffic_log",
       "pcap_path", "connectivity", "ipsec"}
      {"status": "FAILED",  "experiment_id", "reason", "error"}
      {"status": "INTERRUPTED", "experiment_id", "reason", "error"}

    Any pipeline exception maps to FAILED, never to success.
    """
    log = log or (lambda msg: None)
    config = dict(sample["ipsec_configuration"])
    config["traffic"] = {
        "profile": sample["traffic_profile"],
        "duration": float(DEFAULT_DURATION),
        "port": DEFAULT_PORT,
        "capture_filter": "esp",
    }
    validate_config(config)

    try:
        artifacts = campaign_mod.execute_trial_pipeline(
            experiment_id, config, config["traffic"], tmp_dir,
            run_id=run_id, log=log, reuse=reuse,
        )
    except Exception as exc:
        return {
            "status": OUTCOME_FAILED,
            "experiment_id": experiment_id,
            "reason": type(exc).__name__,
            "error": str(exc),
        }
    outcome = {
        "status": OUTCOME_SUCCESS,
        "experiment_id": experiment_id,
        **artifacts,
    }
    outcome["status"] = OUTCOME_SUCCESS
    outcome["experiment_id"] = experiment_id
    return outcome


def cleanup_attempt(experiment_id, sample, tmp_dir, runtime_ctx=None,
                    skip_destroy=False):
    """Shared best-effort cleanup for one attempt's resources.

    ``skip_destroy=True`` preserves the containerlab topology for reuse.
    """
    if runtime_ctx is None:
        runtime_ctx = {"source_container": None, "destination_container": None}
    mode = sample["ipsec_configuration"]["mode"]
    campaign_mod.cleanup_experiment(runtime_ctx, mode, tmp_dir,
                                    skip_destroy=skip_destroy)


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
        "dataset_run_id": run.id,
        "experiment_id": experiment_id,
        "sequence": sample["sequence"],
        "attempt": attempt,
        "status": outcome["status"],
        "reason": outcome.get("reason"),
        "error": outcome.get("error"),
        "traffic_profile": sample["traffic_profile"],
        "security_posture": sample["security_posture"],
        "configuration_id": sample.get("configuration_id"),
        "ipsec_configuration": sample["ipsec_configuration"],
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


def _run_sequence(run, sample, samples_by_seq, results_root, run_attempt_fn,
                  cleanup_fn, max_attempts, collector_fn=None, log=None,
                  reuse_manager=None):
    """Run one logical sequence to completion.

    Returns "COMMITTED" after a successful commit, "PAUSED" on a signal
    interruption, stale-environment exhaustion, or an un-cleanable orphaned
    attempt, or "EXHAUSTED" when the total attempt budget for the sequence is
    used up (the run has been marked FAILED).

    ``reuse_manager`` is the persistent Module-10 topology-reuse manager for
    the dataset-run invocation; it is forwarded to ``run_attempt_fn`` so that
    consecutive successful samples can reuse an already-deployed topology in
    place.  When ``None`` every attempt performs the historical full fresh
    deployment.

    When ``collector_fn`` is provided (Module 5), a successful attempt is only
    committed after its dataset artifacts have been staged; an artifact
    persistence failure turns the attempt into a FAILED attempt (never a
    fabricated success), so a sample is never counted successful if its
    required artifacts cannot be safely persisted.

    Attempt-budget semantics
    ------------------------
    ``max_attempts`` is a TOTAL budget per logical sequence, cumulative across
    restarts/resumes, tracked durably in ``attempts_per_sequence`` and counted
    when an attempt STARTS.  A failed attempt, a returned-INTERRUPTED attempt
    and a killed attempt all consume budget slots.  A real KeyboardInterrupt
    pauses the run regardless of the budget; resuming with the SAME budget
    after the slot count reached it fails (the operator may pass a larger
    ``max_attempts_per_sequence`` to continue).  Success is never fabricated:
    only a committed sample counts.
    """
    seq = sample["sequence"]
    config = sample["ipsec_configuration"]
    profile = sample["traffic_profile"]
    posture = sample["security_posture"]

    attempts_done = _attempt_count(run, seq)
    in_flight = run.data.get("attempt_in_progress")
    if in_flight is not None and in_flight.get("sequence") == seq:
        # The previous process died (SIGKILL/abrupt exit) while this attempt
        # was running and never recorded an outcome.  The attempt consumes its
        # budget slot and its number is never reused.
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
            f"posture={posture} traffic={profile} "
            f"config={config['esp']['encryption']} ({experiment_id})")

        interrupted_by_signal = False
        try:
            outcome = run_attempt_fn(
                experiment_id, sample, tmp_dir, results_root,
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


def _teardown_run_topology(reuse_manager, log=None):
    """Destroy the topology kept alive for Module-10 reuse, exactly once.

    Called when a dataset run reaches a terminal state (COMPLETED / FAILED /
    EXHAUSTED).  A PAUSED run intentionally keeps the topology alive so a
    resume can reuse it.  Best-effort and idempotent.
    """
    identity = None
    if reuse_manager is not None:
        identity = reuse_manager.stats().get("last_topology_identity")
    if identity is None:
        return
    log = log or (lambda msg: None)
    log(f"final teardown: destroying {identity} topology")
    try:
        campaign_mod.destroy(identity)
    except Exception as exc:
        log(f"final teardown warning ({type(exc).__name__}: {exc})")


def execute_dataset_run(results_root, dataset_run_id, *,
                        run_attempt_fn=run_attempt,
                        cleanup_fn=cleanup_attempt,
                        max_attempts_per_sequence=DEFAULT_ATTEMPTS_PER_SEQUENCE,
                        collector_fn=None,
                        log=None):
    """Execute a dataset run until it is complete (or unrecoverable).

    ``run_attempt_fn(experiment_id, sample, tmp_dir, results_root, ...)``
    returns an outcome dict; ``cleanup_fn(experiment_id, sample, tmp_dir)``
    performs teardown.  Both are dependency-injected for unit testing.

    ``collector_fn(run, experiment_id, attempt, sample, outcome, log=None)``
    is the Module 5 artifact collector.  When provided it runs at the
    successful-commit boundary and a sample is only committed once its
    artifacts are safely staged; a persistence failure marks the attempt
    FAILED instead of committing a fabricated success.

    A single ``TopologyReuseManager`` is created for this invocation and
    threaded to every attempt (Module 10).  Consecutive same-mode samples can
    then reuse the deployed containerlab topology in place; a fresh invocation
    or resume starts with no prior identity, so the first sample is always a
    full fresh deployment.

    Returns the (persisted) DatasetRun.
    """
    log = log or (lambda msg: None)
    if isinstance(max_attempts_per_sequence, bool) or not isinstance(
        max_attempts_per_sequence, int
    ):
        raise ValueError("max_attempts_per_sequence must be an integer")
    if max_attempts_per_sequence <= 0:
        raise ValueError("max_attempts_per_sequence must be > 0")

    run = dataset_run_mod.load_dataset_run(results_root, dataset_run_id)
    _ensure_executor_state_fields(run)
    validate_runtime_state(run, run.target_samples)

    if run.status == STATUS_COMPLETED:
        return run
    if run.status == STATUS_FAILED:
        raise ValueError(
            f"dataset run '{dataset_run_id}' is FAILED and cannot be resumed"
        )

    plan = load_plan(results_root, dataset_run_id)
    target = plan["target_samples"]
    if target != run.target_samples:
        raise ValueError(
            f"plan target ({target}) differs from dataset run target "
            f"({run.target_samples})"
        )
    samples_by_seq = {s["sequence"]: s for s in plan["samples"]}

    fingerprint = plan_fingerprint(plan)
    if run.data.get("plan_fingerprint") is None:
        run.update(status=STATUS_RUNNING, plan_fingerprint=fingerprint)
    else:
        if run.data["plan_fingerprint"] != fingerprint:
            raise ValueError(
                "stored plan.json differs from the plan this dataset run "
                "started with; refusing to resume with a different plan"
            )
        if run.status != STATUS_RUNNING:
            run.update(status=STATUS_RUNNING)
    log(f"dataset run {dataset_run_id}: target={target} "
        f"already committed={len(committed_sequences(run))}")

    # ONE persistent reuse manager for this dataset-run invocation.  A new
    # invocation (including a resume) starts with _prev_identity=None, so the
    # first sample after any resume performs a full fresh deployment.  The
    # manager is never persisted to disk.
    reuse_manager = reuse_mod.TopologyReuseManager(log=log)

    while True:
        seq = next_sequence_to_run(run, target)
        if seq is None:
            break
        result = _run_sequence(
            run, samples_by_seq[seq], samples_by_seq, results_root,
            run_attempt_fn, cleanup_fn, max_attempts_per_sequence,
            collector_fn=collector_fn, log=log, reuse_manager=reuse_manager,
        )
        if result == "EXHAUSTED":
            _teardown_run_topology(reuse_manager, log)
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
        _teardown_run_topology(reuse_manager, log)
        return run

    validate_runtime_state(run, target)
    run.update(status=STATUS_COMPLETED)
    _teardown_run_topology(reuse_manager, log)
    log(f"dataset run {dataset_run_id} COMPLETED: "
        f"successful={run.data['successful_samples']} "
        f"failed={run.data['failed_samples']} "
        f"interrupted={run.data['interrupted_samples']}")
    return run


def main(argv=None):
    import argparse

    parser = argparse.ArgumentParser(
        description="Execute a dataset run to completion using its staging plan"
    )
    parser.add_argument("dataset_run_id")
    parser.add_argument(
        "--results-root", default=dataset_mod.DEFAULT_RESULTS_ROOT,
        help="directory under which dataset runs are stored",
    )
    parser.add_argument(
        "--max-attempts-per-sequence", type=int,
        default=DEFAULT_ATTEMPTS_PER_SEQUENCE,
    )
    args = parser.parse_args(argv)

    from .dataset_artifacts import collect_successful_sample

    run = execute_dataset_run(
        args.results_root, args.dataset_run_id,
        max_attempts_per_sequence=args.max_attempts_per_sequence,
        collector_fn=collect_successful_sample,
    )
    print(
        f"dataset run {args.dataset_run_id}: status={run.status} "
        f"successful={run.data['successful_samples']} "
        f"attempted={run.data['attempted_runs']} "
        f"failed={run.data['failed_samples']} "
        f"interrupted={run.data['interrupted_samples']}"
    )
    return 0 if run.status == STATUS_COMPLETED else 1


if __name__ == "__main__":
    raise SystemExit(main())