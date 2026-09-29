"""Monotonic per-stage timing recorder for the dataset execution path (Module 8).

Module 8 is a PROFILING-ONLY deliverable.  This module provides a lightweight,
purely additive instrumentation layer used to measure where wall-clock time
goes inside one dataset sample attempt.  It deliberately:

* never changes execution behaviour or dataset semantics,
* never persists anything inside a run directory (run-dir subdirectories are
  schema-whitelisted by ``dataset_run.SUB_DIRECTORIES``; a timing sidecar
  therefore lives under ``results_root/timings/<dataset_run_id>.json``),
* only reads its own recorded durations -- nothing downstream depends on the
  numbers,
* uses ``time.monotonic`` so timings never count wall-clock shifts (clock
  step/NTP) as experiment time.

Stage names mirror the shared pipeline in ``campaign.execute_trial_pipeline``:

  "topology"        reset_and_deploy (destroy + deploy of the containerlab
                    topology for this attempt),
  "configs"         load_generated_configs (deployed configs are loaded),
  "ipsec_init"      initiate_ipsec,
  "ipsec_verify"    verify_ipsec (IKE ESTABLISHED / CHILD INSTALLED / mode),
  "observation"     ensure_live_observation (XDP monitor ready on this mode's
                     passive sensor: clab-ipsec-sensor for tunnel,
                     clab-ipsec-transport-sensor for transport),
  "connectivity"    test_connectivity (PASS gate, before capture),
  "capture"         start_capture + stop_capture + copy_capture,
  "traffic"         start_receiver / wait_receiver / run_sender / stop_receiver
                    (includes the nominal traffic duration),
  "features"        extract_features,
  "persist"         dataset executor artifact persistence (success path),
  "cleanup"         campaign.cleanup_experiment best-effort teardown,
  "total"           whole-attempt wall clock (monotonic, may be greater than
                    the sum of stages only because of inter-stage scheduling).

Aggregation helper ``summarize`` collapses a sequence of per-sample timing
dicts into per-stage totals/means plus a poll-free execution total, which the
profiling report and ``profilingsummary`` CLI print.

Tests inject a fake clock so no test depends on real wall time.
"""

import contextlib
import json
import time
from pathlib import Path


class TimingRecorder:
    """Record monotonic stage durations for one dataset sample attempt.

    ``clock`` defaults to ``time.monotonic``; tests substitute a fake clock.
    ``begin``/``end`` are idempotent-per-stage: a missing or repeated ``end``
    never raises, and a stage that never began is simply absent from
    ``snapshot`` (it is not fabricated as a zero).  A stage that began but
    never ended (a SIGKILL / abrupt teardown) is recorded as ``"interrupted"``
    so the profiling report can tell a killed attempt from a completed one.
    """

    def __init__(self, clock=None):
        self._clock = clock or time.monotonic
        self._starts = {}
        self._durations = {}
        self._order = []
        self._interrupted = []
        self._started = False

    # -- lifecycle ---------------------------------------------------------
    def begin_sample(self):
        self._sample_start = self._clock()

    def end_sample(self):
        self._durations["total"] = self._clock() - self._sample_start

    # -- stages ------------------------------------------------------------
    def begin(self, stage):
        if stage in self._starts:
            return
        self._starts[stage] = self._clock()
        if stage not in self._order:
            self._order.append(stage)

    def end(self, stage):
        start = self._starts.pop(stage, None)
        if start is None:
            return
        self._durations[stage] = round(self._clock() - start, 6)

    def interrupt(self, stage):
        """Mark a stage that began but was killed before ``end``."""
        if stage in self._starts:
            self._starts.pop(stage)
            self._interrupted.append(stage)

    # -- reporting ---------------------------------------------------------
    def stages(self):
        """Stage names in the order they were begun (never ``total``)."""
        return [name for name in self._order if name != "total"]

    def snapshot(self):
        """Structured view: ordered stage durations + interrupted markers.

        Monotonic seconds, ``None`` for a stage that ended with ``interrupt``
        (kept present so a missing stage is distinguishable from an
        interrupted one).  ``total`` is included when ``end_sample`` ran.
        """
        out = []
        for stage in self._order:
            if stage == "total":
                continue
            if stage in self._interrupted:
                out.append({"stage": stage, "seconds": None,
                            "interrupted": True})
            else:
                out.append({"stage": stage,
                            "seconds": self._durations.get(stage),
                            "interrupted": False})
        if "total" in self._durations:
            out.append({"stage": "total",
                        "seconds": self._durations["total"],
                        "interrupted": False})
        return out

    def to_dict(self, run_id=None, experiment_id=None, sequence=None,
                status=None, reason=None, error=None):
        return {
            "run_id": run_id,
            "experiment_id": experiment_id,
            "sequence": sequence,
            "status": status,
            "stage_timings": self.snapshot(),
            "total_seconds": self._durations.get("total"),
            "interrupted_stages": list(self._interrupted),
            "reason": reason,
            "error": error,
        }


@contextlib.contextmanager
def stage(recorder, name):
    """Context-manager wrapper around one pipeline stage for ``TimingRecorder``.

    Additive profiling seam: when ``recorder`` is ``None`` this is a pure
    no-op (``yield`` immediately) so an uninstrumented run is byte-for-byte
    unchanged.  Otherwise ``begin`` runs on entry, ``end`` on clean exit and
    ``interrupt`` on an exception propagating through the ``with`` block
    (the exception is always re-raised unchanged).
    """
    if recorder is None:
        yield
        return
    recorder.begin(name)
    try:
        yield
    except BaseException:
        recorder.interrupt(name)
        raise
    recorder.end(name)


def summarize(per_sample):
    """Collapse per-sample timing dicts into per-stage totals and means.

    ``per_sample`` is a list of ``TimingRecorder.to_dict`` outputs (the same
    JSON shape that is persisted under ``results_root/timings/``).  Only
    complete (non-interrupted, non-None) stage durations contribute to
    totals/means; interrupted stages are listed separately.  Returns an
    inspectable summary dict (no stdout parsing needed):

      {"sample_count": N,
       "stage_totals":   {"topology": 12.3, ...},
       "stage_means":    {"topology": 6.15, ...},
       "stage_counts":   {"topology": N, ...},
       "interrupted":    [{"run_id","experiment_id","stage"}, ...],
       "total_seconds":   summed ``total`` across committed samples,
       "execution_seconds": sum of ``total`` (poll-free; GET/polling of
                            dataset-run/experiment status is never counted)}

    Durations are monotonic seconds.  No stage is ever invented: a stage
    missing from a sample simply does not contribute and is not a zero.
    """
    totals = {}
    counts = {}
    interrupted = []
    total_secs = 0.0
    for sample in per_sample:
        for entry in sample.get("stage_timings", []):
            stage = entry["stage"]
            secs = entry.get("seconds")
            if stage == "total":
                if secs is not None:
                    total_secs += float(secs)
                continue
            if entry.get("interrupted"):
                interrupted.append({
                    "run_id": sample.get("run_id"),
                    "experiment_id": sample.get("experiment_id"),
                    "stage": stage,
                })
                continue
            if secs is None:
                continue
            totals.setdefault(stage, 0.0)
            counts.setdefault(stage, 0)
            totals[stage] += float(secs)
            counts[stage] += 1

    means = {stage: totals[stage] / counts[stage] for stage in totals}
    return {
        "sample_count": len(per_sample),
        "stage_totals": totals,
        "stage_means": means,
        "stage_counts": counts,
        "interrupted": interrupted,
        "total_seconds": total_secs,
        "execution_seconds": total_secs,
    }


def timings_root(results_root):
    """Parent directory for per-run timing artifacts (additive sidecar)."""
    return Path(results_root) / "timings"


def timings_path_for_run(results_root, dataset_run_id):
    return timings_root(results_root) / f"{dataset_run_id}.json"


def write_timings_for_run(results_root, dataset_run_id, per_sample,
                          log=None):
    """Atomically persist one sample's timing dict + a summarize() summary.

    Best-effort and additive: a failure to write timing artifacts NEVER
    affects the dataset run outcome.  Nothing touches the run directory
    (whitelisted layout) -- the sidecar lives under
    ``results_root/timings/``.
    """
    log = log or (lambda msg: None)
    run_path = timings_path_for_run(results_root, dataset_run_id)
    try:
        run_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "dataset_run_id": dataset_run_id,
            "samples": per_sample,
            "summary": summarize(per_sample),
        }
        tmp = run_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        tmp.replace(str(run_path))
    except Exception as exc:
        try:
            log(f"timings sidecar not written ({type(exc).__name__}: {exc})")
        except Exception:
            pass
        return None
    return run_path
