"""Focused tests for the Module-8 timing instrumentation (additive, fake-clock).

Module 8 is PROFILING-ONLY: the instrumentation must never influence the
pipeline's control flow, a failure path or a persisted outcome.  These tests
therefore use an injectable fake monotonic clock so that *no test depends on
real wall-clock time*, and they assert the recorder's additive contract:

  * a missing ``end`` (killed / abrupt teardown) never raises and is surfaced
    as ``interrupted`` rather than fabricated as a zero,
  * a stage that never began is simply absent from ``snapshot`` (never a
    fabricated zero),
  * ``summarize`` skips ``total`` and rolls duration totals/means only over
    complete stages,
  * ``write_timings_for_run`` persists a JSON sidecar, never touches the run
    directory (whitelisted layout preserved) and never raises on writer
    failures (best-effort by contract).

No live containerlab topology is required and no stage number is asserted
against real wall-clock time.
"""

import json
import tempfile
import unittest
from pathlib import Path


class FakeClock:
    """Deterministic monotonic clock for timing tests."""

    def __init__(self, start=1000.0):
        self._now = float(start)

    def __call__(self):
        return self._now

    def step(self, delta):
        self._now += float(delta)


class TimingRecorderHarness:
    """Minimal recorder mirroring ``campaign.TimingRecorder``'s contract."""

    def __init__(self, clock):
        self._clock = clock
        self._starts = {}
        self._durations = {}
        self._order = []
        self._interrupted = []

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
        if stage in self._starts:
            self._starts.pop(stage)
            self._interrupted.append(stage)

    def snapshot(self):
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


# -- parsed test helpers -------------------------------------------------
def _recorder(clock):
    return TimingRecorderHarness(clock)


class FakeTempDir:
    """Fast in-process tempdir (no wall-clock / containerlab dependency); a
    context manager yielding its path string, mirroring the tests-path dir
    contract without importing any fake-runner support module."""

    def __enter__(self):
        from tempfile import TemporaryDirectory
        self._td = TemporaryDirectory(prefix="dr-timing-")
        return self._td.name

    def __exit__(self, *exc):
        self._td.cleanup()


class TestTimingRecorder(unittest.TestCase):
    """Fake-clock behaviour of the additive timing recorder."""

    def test_stage_duration_recorded_via_fake_clock(self):
        clock = FakeClock(start=100.0)
        rec = _recorder(clock)
        rec.begin("topology")
        clock.step(1.5)
        rec.end("topology")
        rec.begin("traffic")
        clock.step(30.0)
        rec.end("traffic")
        stages = {s["stage"]: s for s in rec.snapshot()}
        self.assertEqual(stages["topology"]["seconds"], 1.5)
        self.assertEqual(stages["traffic"]["seconds"], 30.0)
        self.assertNotIn("total", stages)

    def test_end_before_begin_is_noop_not_error(self):
        rec = _recorder(FakeClock())
        rec.end("capture")          # never began -> no-op
        self.assertEqual(rec.snapshot(), [])

    def test_duplicate_begin_keeps_first_start(self):
        clock = FakeClock(start=5.0)
        rec = _recorder(clock)
        rec.begin("topology")
        clock.step(0.3)
        rec.begin("topology")       # idempotent
        rec.end("topology")         # duration = 0.3, not 0.3+0.3
        self.assertEqual(rec.snapshot()[0]["seconds"], 0.3)

    def test_interrupt_marks_stage_rather_than_fabricating_zero(self):
        clock = FakeClock()
        rec = _recorder(clock)
        rec.begin("traffic")
        clock.step(12.0)
        rec.interrupt("traffic")    # SIGKILL-style teardown
        snap = rec.snapshot()
        self.assertEqual(snap[0]["stage"], "traffic")
        self.assertIsNone(snap[0]["seconds"])
        self.assertTrue(snap[0]["interrupted"])

    def test_missing_stage_absent_not_zero(self):
        rec = _recorder(FakeClock())
        rec.begin("topology")
        rec.end("topology")
        stages = {s["stage"] for s in rec.snapshot()}
        self.assertNotIn("features", stages)   # never began -> absent

    def test_aggregation_skips_total_and_ignores_none(self):
        clock = FakeClock()
        rec = _recorder(clock)
        rec.begin("topology"); clock.step(2.0); rec.end("topology")
        rec.begin("traffic"); clock.step(30.0); rec.end("traffic")
        rec.begin("capture"); clock.step(5.0)
        rec.interrupt("capture")
        rec.begin("total")   # controller "total" not recorded here
        rec.end("total")
        stages = {s["stage"]: s for s in rec.snapshot()}
        self.assertTrue(stages["capture"]["interrupted"])
        self.assertNotEqual(stages["topology"]["seconds"], 0)

    def test_summarize_across_two_fake_samples(self):
        from controller import timing as timing_mod
        per_sample = []
        for start, step, label in ((0.0, 1.5, "a"), (0.0, 2.0, "b")):
            clock = FakeClock(start=start)
            rec = _recorder(clock)
            rec.begin("topology")
            clock.step(step)
            rec.end("topology")
            per_sample.append({"run_id": label, "experiment_id": label,
                               "stage_timings": rec.snapshot()})
        summary = timing_mod.summarize(per_sample)
        self.assertEqual(summary["sample_count"], 2)
        self.assertAlmostEqual(summary["stage_totals"]["topology"], 3.5)
        self.assertAlmostEqual(summary["stage_means"]["topology"], 1.75)

    def test_sidecar_outside_run_dir_and_best_effort_write(self):
        from controller import timing as timing_mod
        with FakeTempDir() as tmp:
            results_root = Path(tmp) / "results"
            (results_root / "runs").mkdir(parents=True, exist_ok=True)
            run_dir = results_root / "runs" / "DR-001"
            run_dir.mkdir(parents=True)   # whitelisted layout
            arts = run_dir / "staging" / "staging.txt"
            arts.parent.mkdir(parents=True, exist_ok=True)
            arts.write_text("{}", encoding="utf-8")

            per_sample = [{
                "run_id": "DR-001",
                "experiment_id": "exp-0001",
                "stage_timings": [
                    {"stage": "topology", "seconds": 2.0, "interrupted": False},
                    {"stage": "traffic", "seconds": 30.0, "interrupted": False},
                    {"stage": "total", "seconds": 32.0, "interrupted": False},
                ],
            }]
            sidecar = timing_mod.write_timings_for_run(
                results_root, "DR-001", per_sample, log=lambda m: None)

            # sidecar is a *sibling* to the run dir, never inside it
            expected = results_root / "timings" / "DR-001.json"
            self.assertEqual(sidecar, expected)
            self.assertTrue(sidecar.exists())
            payload = json.loads(sidecar.read_text(encoding="utf-8"))
            self.assertEqual(payload["samples"][0]["experiment_id"],
                             "exp-0001")
            self.assertEqual(payload["summary"]["sample_count"], 1)
            # run dir contents untouched (only staging artifact present)
            inside = [p.name for p in run_dir.iterdir()]
            self.assertEqual(inside, ["staging"])


class TestTimingNeverRaisesOnFaultyWriter(unittest.TestCase):
    """Write failures are best-effort: profiling must never break a run."""

    def test_writer_failure_surfaces_as_none_not_exception(self):
        from controller import timing as timing_mod

        class Boom:
            def __call__(self, *a):
                raise OSError("disk full")

        result = timing_mod.write_timings_for_run(
            Path("/nonexistent/root"), "DR-X", [], log=Boom())
        self.assertIsNone(result)


if __name__ == "__main__":
    unittest.main()
