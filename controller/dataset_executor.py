"""Dataset execution adapter and API-compatible facade (Modules 3/4).

The orchestration engine now lives in :mod:`controller.experiment_runner` as a
generic repeated-experiment runner.  This module is the *dataset application* of
that engine:

* ``run_attempt``     -- adapts a single attempt to the real IPsec testbed
  pipeline (``campaign.execute_trial_pipeline``).  Traffic/capture inputs are
  parameterized: per-sample ``sample["traffic"]`` overrides win, falling back
  to the historical defaults (30 s / port 20000 / ESP-only capture).
* ``cleanup_attempt`` -- adapts ``campaign.cleanup_experiment``.
* ``_teardown_run_topology`` -- Module-10 exactly-once topology teardown.
* ``load_plan`` / ``validate_plan`` -- Module-2 dataset plan loading and the
  strict dataset plan validation (posture / ipsec / traffic / quota).
* ``execute_dataset_run`` -- wires the above into the generic engine with a
  per-invocation ``TopologyReuseManager``.

Feature extraction, Parquet materialization, the UI and the legacy dataset
tooling are deliberately untouched; the generic engine keeps emitting the same
artifact contract (``metadata.json`` / ``features.json`` / traffic + capture
evidence per committed sample).
"""

import json
from pathlib import Path

from . import campaign as campaign_mod
from . import capture as capture_mod
from . import dataset as dataset_mod
from . import dataset_run as dataset_run_mod
from . import experiment_runner as _engine
from . import reuse as reuse_mod
from .dataset_planner import (
    PLAN_FILENAME,
    POSTURE_ORDER,
    validate_traffic_profile,
)
from .traffic import DEFAULT_DURATION, DEFAULT_PORT
from .validate import validate_config

# ── re-exports (API / artifact / CLI / test compatibility) ─────────────────
# The generic engine owns these; re-export so existing import sites are
# unaffected.

OUTCOME_SUCCESS = _engine.OUTCOME_SUCCESS
OUTCOME_FAILED = _engine.OUTCOME_FAILED
OUTCOME_INTERRUPTED = _engine.OUTCOME_INTERRUPTED
VALID_OUTCOMES = _engine.VALID_OUTCOMES

STATUS_RUNNING = _engine.STATUS_RUNNING
STATUS_PAUSED = _engine.STATUS_PAUSED
STATUS_COMPLETED = _engine.STATUS_COMPLETED
STATUS_FAILED = _engine.STATUS_FAILED

DEFAULT_ATTEMPTS_PER_SEQUENCE = _engine.DEFAULT_ATTEMPTS_PER_SEQUENCE

STAGING_TMP_SUBDIR = _engine.STAGING_TMP_SUBDIR
EXPERIMENTS_SUBDIR = _engine.EXPERIMENTS_SUBDIR
FAILURES_SUBDIR = _engine.FAILURES_SUBDIR

EXPERIMENT_ID_RE = _engine.EXPERIMENT_ID_RE

experiment_id_for = _engine.experiment_id_for
parse_experiment_id = _engine.parse_experiment_id
plan_fingerprint = _engine.plan_fingerprint
committed_sequences = _engine.committed_sequences
next_sequence_to_run = _engine.next_sequence_to_run
validate_runtime_state = _engine.validate_runtime_state
RunOptions = _engine.RunOptions
execute_repeated_run = _engine.execute_repeated_run

# Historical dataset capture default, kept for CLI --help text.  The value now
# comes from the capture layer's single canonical constant (IKE + ESP [+ AH]);
# an ESP-only capture remains available as an explicit override.
DEFAULT_CAPTURE_FILTER = capture_mod.DEFAULT_CAPTURE_FILTER


# ── dataset-specific plan loading / validation ─────────────────────────────

def validate_plan(plan):
    """Strict Module-2 dataset plan validation.

    Validates the generic protocol (sequences, target, unique) plus the
    dataset-specific constraints: security_posture, configuration_id,
    ipsec_configuration, traffic_profile, and traffic_quota consistency.
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
    """Load and validate the dataset plan stored by Module 2 under staging/."""
    run_dir = dataset_run_mod.run_directory(results_root, dataset_run_id)
    plan_path = run_dir / "staging" / PLAN_FILENAME
    if not plan_path.exists():
        raise FileNotFoundError(f"plan not found: {plan_path}")
    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    validate_plan(plan)
    return plan


# ── dataset-specific adapters ──────────────────────────────────────────────

def run_attempt(experiment_id, sample, tmp_dir, results_root, run_id=None,
                log=None, reuse=None):
    """Execute one physical attempt with the real testbed pipeline.

    ``reuse`` is the persistent per-dataset-run ``TopologyReuseManager``
    (Module 10).  When ``None`` (the default) the attempt's pipeline performs
    the historical full fresh deployment for the sample.

    Traffic/capture inputs are parameterized: per-sample ``sample["traffic"]``
    keys (``duration``, ``port``, ``capture_filter``) win, falling back to the
    historical defaults (30 s / port 20000) and the canonical testbed-wide
    capture filter (IKE negotiation + ESP data [+ AH]).

    Returns an outcome dict:

      {"status": "SUCCESS", ..., "metadata", "features", "traffic_log",
       "pcap_path", "connectivity", "ipsec"}
      {"status": "FAILED",  "experiment_id", "reason", "error"}
      {"status": "INTERRUPTED", "experiment_id", "reason", "error"}

    Any pipeline exception maps to FAILED, never to success.
    """
    log = log or (lambda msg: None)
    config = dict(sample["ipsec_configuration"])
    traffic = dict(sample.get("traffic") or {})
    traffic.setdefault("profile", sample["traffic_profile"])
    traffic.setdefault("duration", float(DEFAULT_DURATION))
    traffic.setdefault("port", DEFAULT_PORT)
    traffic.setdefault("capture_filter", DEFAULT_CAPTURE_FILTER)
    config["traffic"] = traffic
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


# ── top-level dataset execution ────────────────────────────────────────────

def execute_dataset_run(results_root, dataset_run_id, *,
                        run_attempt_fn=run_attempt,
                        cleanup_fn=cleanup_attempt,
                        max_attempts_per_sequence=DEFAULT_ATTEMPTS_PER_SEQUENCE,
                        collector_fn=None,
                        run_options=None,
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

    ``run_options`` (optional ``RunOptions``) applies run-level traffic/capture
    knobs to every attempt; per-sample ``sample["traffic"]`` overrides win.
    When ``None`` the historical defaults (30 s / port 20000) and the
    canonical capture filter are used, preserving behaviour with the campaign
    path (IKE negotiation + ESP data [+ AH] are captured together).

    A single ``TopologyReuseManager`` is created for this invocation and
    threaded to every attempt (Module 10).  Consecutive same-mode samples can
    then reuse the deployed containerlab topology in place; a fresh invocation
    or resume starts with no prior identity, so the first sample is always a
    full fresh deployment.

    Returns the (persisted) DatasetRun.
    """
    log = log or (lambda msg: None)
    reuse_manager = reuse_mod.TopologyReuseManager(log=log)
    return _engine.execute_repeated_run(
        results_root, dataset_run_id,
        load_plan_fn=load_plan,
        run_attempt_fn=run_attempt_fn,
        cleanup_fn=cleanup_fn,
        validate_plan_fn=validate_plan,
        max_attempts_per_sequence=max_attempts_per_sequence,
        collector_fn=collector_fn,
        run_options=run_options,
        reuse_manager=reuse_manager,
        teardown_fn=_teardown_run_topology,
        log=log,
    )


# ── CLI ────────────────────────────────────────────────────────────────────

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
    parser.add_argument(
        "--duration", type=float, default=None,
        help="per-attempt traffic duration in seconds (default: 30)",
    )
    parser.add_argument(
        "--port", type=int, default=None,
        help="per-attempt traffic destination port (default: 20000)",
    )
    parser.add_argument(
        "--capture-filter", default=None,
        help=f"per-attempt pcap capture filter (default: {DEFAULT_CAPTURE_FILTER})",
    )
    args = parser.parse_args(argv)

    from .dataset_artifacts import collect_successful_sample

    run_options = None
    if args.duration is not None or args.port is not None or args.capture_filter is not None:
        run_options = RunOptions(
            duration=(
                args.duration
                if args.duration is not None
                else float(DEFAULT_DURATION)
            ),
            port=args.port if args.port is not None else DEFAULT_PORT,
            capture_filter=(
                args.capture_filter
                if args.capture_filter is not None
                else DEFAULT_CAPTURE_FILTER
            ),
        )

    run = execute_dataset_run(
        args.results_root, args.dataset_run_id,
        max_attempts_per_sequence=args.max_attempts_per_sequence,
        collector_fn=collect_successful_sample,
        run_options=run_options,
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
