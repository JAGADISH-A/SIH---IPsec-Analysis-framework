"""Generic repeated-experiment runner tests.

Run with::

    .venv/bin/python -m controller.test_experiment_runner

or::

    .venv/bin/python -m unittest controller.test_experiment_runner

Uses a temporary directory; never touches the production results directory.
The real testbed pipeline is replaced with fakes via dependency injection.
"""

import tempfile
import unittest
from collections import Counter
from pathlib import Path

from controller.dataset_run import create_dataset_run
from controller.experiment_runner import (
    RunOptions,
    OUTCOME_FAILED,
    OUTCOME_INTERRUPTED,
    OUTCOME_SUCCESS,
    STATUS_COMPLETED,
    STATUS_FAILED,
    STATUS_PAUSED,
    STATUS_RUNNING,
    _apply_run_options,
    committed_sequences,
    experiment_id_for,
    next_sequence_to_run,
    parse_experiment_id,
    plan_fingerprint,
    validate_repeated_plan,
    execute_repeated_run,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_generic_plan(target):
    """Minimal plan dict with generic samples (no IPsec-specific keys)."""
    samples = [
        {
            "sequence": i,
            "traffic_profile": f"generic-{i}",
            "configuration_id": f"cfg-{i}",
            "ipsec_configuration": {"mode": "tunnel"},
            "security_posture": "test",
        }
        for i in range(1, target + 1)
    ]
    return {"target_samples": target, "samples": samples}


class _FakeRunner:
    """Injectably replays a scripted sequence of attempt outcomes.

    ``script`` maps (sequence, attempt) to one of ``"SUCCESS"``,
    ``"FAILED"``, ``"INTERRUPTED"``, ``"KeyboardInterrupt"``.
    """

    def __init__(self, script=None, default="SUCCESS"):
        self.script = script or {}
        self.default = default
        self.calls = []
        self.reuse_seen = []

    def __call__(self, experiment_id, sample, tmp_dir, results_root,
                 run_id=None, log=None, reuse=None):
        parsed = parse_experiment_id(experiment_id)
        self.reuse_seen.append(reuse)
        seq, attempt = parsed[1], parsed[2]
        self.calls.append(
            (seq, attempt, experiment_id, sample["traffic_profile"])
        )
        kind = self.script.get((seq, attempt), self.default)
        tmp = Path(tmp_dir)
        tmp.mkdir(parents=True, exist_ok=True)

        if kind == "KeyboardInterrupt":
            raise KeyboardInterrupt()
        if kind == "FATAL":
            return {
                "status": OUTCOME_FAILED,
                "experiment_id": experiment_id,
                "reason": "FatalTopologyError",
                "error": "lab cannot deploy: host bridge unavailable",
                "fatal": True,
            }
        if kind == OUTCOME_FAILED:
            (tmp / "partial.log").write_text("partial", encoding="utf-8")
            return {
                "status": OUTCOME_FAILED,
                "experiment_id": experiment_id,
                "reason": "SyntheticError",
                "error": "synthetic failure",
            }
        if kind == OUTCOME_INTERRUPTED:
            return {
                "status": OUTCOME_INTERRUPTED,
                "experiment_id": experiment_id,
                "reason": "SyntheticInterrupt",
                "error": "synthetic interrupt",
            }

        pcap = tmp / "capture.pcap"
        pcap.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 48)
        return {
            "status": OUTCOME_SUCCESS,
            "experiment_id": experiment_id,
            "metadata": {
                "experiment_id": experiment_id,
                "sequence": seq,
                "security_posture": sample.get("security_posture"),
                "traffic_profile": sample["traffic_profile"],
                "status": "PASS",
            },
            "features": {"packet_count": 100},
            "traffic_log": f"STATS profile={sample['traffic_profile']}\n",
            "pcap_path": str(pcap),
            "connectivity": {"status": "PASS"},
        }


class _FakeCleanup:
    def __call__(self, experiment_id, sample, tmp_dir, skip_destroy=False):
        if tmp_dir is not None:
            import shutil
            shutil.rmtree(Path(tmp_dir), ignore_errors=True)


class _CollectingRunner:
    """Captures sample traffic dicts for each call."""

    def __init__(self, default="SUCCESS", script=None):
        self.script = script or {}
        self.default = default
        self.seen_samples = []

    def __call__(self, experiment_id, sample, tmp_dir, results_root,
                 run_id=None, log=None, reuse=None):
        self.seen_samples.append(dict(sample))
        parsed = parse_experiment_id(experiment_id)
        seq, attempt = parsed[1], parsed[2]
        kind = self.script.get((seq, attempt), self.default)
        tmp = Path(tmp_dir)
        tmp.mkdir(parents=True, exist_ok=True)

        if kind == "KeyboardInterrupt":
            raise KeyboardInterrupt()
        if kind == OUTCOME_FAILED:
            return {
                "status": OUTCOME_FAILED,
                "experiment_id": experiment_id,
                "reason": "SyntheticError",
                "error": "synthetic failure",
            }

        pcap = tmp / "capture.pcap"
        pcap.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 48)
        return {
            "status": OUTCOME_SUCCESS,
            "experiment_id": experiment_id,
            "metadata": {
                "experiment_id": experiment_id,
                "sequence": seq,
                "traffic_profile": sample.get("traffic_profile"),
                "security_posture": sample.get("security_posture"),
                "status": "PASS",
            },
            "features": {"packet_count": 100},
            "traffic_log": f"STATS\n",
            "pcap_path": str(pcap),
            "connectivity": {"status": "PASS"},
        }


# ---------------------------------------------------------------------------
# RunOptions tests
# ---------------------------------------------------------------------------

class TestRunOptions(unittest.TestCase):
    def test_defaults_match_canonical(self):
        from controller.capture import DEFAULT_CAPTURE_FILTER

        opts = RunOptions()
        self.assertEqual(opts.duration, 30.0)
        self.assertEqual(opts.port, 20000)
        self.assertEqual(opts.capture_filter, DEFAULT_CAPTURE_FILTER)

    def test_traffic_overrides_returns_dict(self):
        opts = RunOptions(duration=15, port=8080, capture_filter="udp port 500")
        self.assertEqual(opts.traffic_overrides(), {
            "duration": 15.0,
            "port": 8080,
            "capture_filter": "udp port 500",
        })


# ---------------------------------------------------------------------------
# _apply_run_options tests
# ---------------------------------------------------------------------------

class TestApplyRunOptions(unittest.TestCase):
    def test_sample_wins_over_run_options(self):
        sample = {
            "traffic_profile": "voip",
            "sequence": 1,
            "traffic": {"duration": 10, "port": 9999},
        }
        opts = RunOptions(duration=45, port=40000, capture_filter="esp or ah")
        merged = _apply_run_options(sample, opts)
        self.assertEqual(merged["traffic"], {
            "duration": 10,
            "port": 9999,
            "capture_filter": "esp or ah",
        })
        self.assertIsNot(merged, sample, "must be a deep copy")

    def test_no_traffic_key_creates_it(self):
        sample = {"traffic_profile": "voip", "sequence": 1}
        opts = RunOptions(duration=15, port=8080, capture_filter="esp")
        merged = _apply_run_options(sample, opts)
        self.assertEqual(merged["traffic"], {
            "duration": 15.0,
            "port": 8080,
            "capture_filter": "esp",
        })
        self.assertNotIn("traffic", sample)

    def test_none_run_options_returns_sample(self):
        sample = {"traffic_profile": "voip", "sequence": 1}
        # _apply_run_options is only called when run_options is not None;
        # but the function itself should still deep-copy.
        opts = RunOptions()
        merged = _apply_run_options(sample, opts)
        self.assertIsNot(merged, sample)


# ---------------------------------------------------------------------------
# validate_repeated_plan tests
# ---------------------------------------------------------------------------

class TestGenericPlanValidation(unittest.TestCase):
    def test_valid_plan(self):
        self.assertTrue(validate_repeated_plan(_make_generic_plan(3)))

    def test_rejects_non_dict(self):
        with self.assertRaises(ValueError):
            validate_repeated_plan("not a dict")

    def test_rejects_empty_samples(self):
        with self.assertRaises(ValueError):
            validate_repeated_plan({"target_samples": 1, "samples": []})

    def test_rejects_target_mismatch(self):
        plan = _make_generic_plan(2)
        plan["samples"].append(plan["samples"][0])
        with self.assertRaises(ValueError):
            validate_repeated_plan(plan)

    def test_rejects_non_contiguous_sequences(self):
        plan = _make_generic_plan(3)
        plan["samples"][1]["sequence"] = 3
        with self.assertRaises(ValueError):
            validate_repeated_plan(plan)

    def test_rejects_duplicate_sequences(self):
        plan = _make_generic_plan(3)
        plan["samples"][1]["sequence"] = 1
        with self.assertRaises(ValueError):
            validate_repeated_plan(plan)


# ---------------------------------------------------------------------------
# Generic engine tests
# ---------------------------------------------------------------------------

class TestGenericEngine(unittest.TestCase):
    def test_ipsec_free_plan_completes(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = 3
            run = create_dataset_run(tmp, target_samples=target)
            plan = _make_generic_plan(target)
            runner = _FakeRunner()
            completed = execute_repeated_run(
                tmp, run.id,
                load_plan_fn=lambda rr, rid: plan,
                run_attempt_fn=runner,
                cleanup_fn=_FakeCleanup(),
            )
            self.assertEqual(completed.status, STATUS_COMPLETED)
            self.assertEqual(completed.data["successful_samples"], target)
            self.assertEqual(len(runner.calls), target)
            self.assertEqual(committed_sequences(completed), {1, 2, 3})

    def test_custom_validate_plan_fn_called(self):
        called = []
        with tempfile.TemporaryDirectory() as tmp:
            run = create_dataset_run(tmp, target_samples=1)
            plan = _make_generic_plan(1)
            execute_repeated_run(
                tmp, run.id,
                load_plan_fn=lambda rr, rid: plan,
                run_attempt_fn=_FakeRunner(),
                cleanup_fn=_FakeCleanup(),
                validate_plan_fn=lambda p: called.append(p),
            )
            self.assertEqual(len(called), 1)

    def test_teardown_fn_called_on_completed(self):
        import unittest.mock as mock
        teardown_calls = []
        with tempfile.TemporaryDirectory() as tmp:
            run = create_dataset_run(tmp, target_samples=2)
            plan = _make_generic_plan(2)
            mgr = object()
            execute_repeated_run(
                tmp, run.id,
                load_plan_fn=lambda rr, rid: plan,
                run_attempt_fn=_FakeRunner(),
                cleanup_fn=_FakeCleanup(),
                reuse_manager=mgr,
                teardown_fn=lambda rm, log: teardown_calls.append(rm),
            )
            self.assertEqual(len(teardown_calls), 1)
            self.assertIs(teardown_calls[0], mgr)

    def test_teardown_fn_not_called_on_pause(self):
        teardown_calls = []
        with tempfile.TemporaryDirectory() as tmp:
            run = create_dataset_run(tmp, target_samples=2)
            plan = _make_generic_plan(2)
            runner = _FakeRunner(script={(1, 1): "KeyboardInterrupt"})
            paused = execute_repeated_run(
                tmp, run.id,
                load_plan_fn=lambda rr, rid: plan,
                run_attempt_fn=runner,
                cleanup_fn=_FakeCleanup(),
                teardown_fn=lambda rm, log: teardown_calls.append(rm),
            )
            self.assertEqual(paused.status, STATUS_PAUSED)
            self.assertEqual(committed_sequences(paused), set())
            self.assertEqual(len(teardown_calls), 0)

    def test_resume_after_pause_completes(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = 3
            run = create_dataset_run(tmp, target_samples=target)
            plan = _make_generic_plan(target)

            first_runner = _FakeRunner(script={(3, 1): "KeyboardInterrupt"})
            paused = execute_repeated_run(
                tmp, run.id,
                load_plan_fn=lambda rr, rid: plan,
                run_attempt_fn=first_runner,
                cleanup_fn=_FakeCleanup(),
            )
            self.assertEqual(paused.status, STATUS_PAUSED)
            self.assertEqual(committed_sequences(paused), {1, 2})

            second_runner = _FakeRunner(default="SUCCESS")
            completed = execute_repeated_run(
                tmp, run.id,
                load_plan_fn=lambda rr, rid: plan,
                run_attempt_fn=second_runner,
                cleanup_fn=_FakeCleanup(),
            )
            self.assertEqual(completed.status, STATUS_COMPLETED)
            self.assertEqual(committed_sequences(completed), {1, 2, 3})

    def test_max_attempts_exhaustion_marks_failed(self):
        with tempfile.TemporaryDirectory() as tmp:
            run = create_dataset_run(tmp, target_samples=1)
            plan = _make_generic_plan(1)
            runner = _FakeRunner(default="FAILED")
            failed = execute_repeated_run(
                tmp, run.id,
                load_plan_fn=lambda rr, rid: plan,
                run_attempt_fn=runner,
                cleanup_fn=_FakeCleanup(),
                max_attempts_per_sequence=2,
            )
            self.assertEqual(failed.status, STATUS_FAILED)
            self.assertEqual(failed.data["successful_samples"], 0)

    def test_fatal_outcome_stops_run_after_one_attempt(self):
        teardown_calls = []
        with tempfile.TemporaryDirectory() as tmp:
            run = create_dataset_run(tmp, target_samples=2)
            plan = _make_generic_plan(2)
            runner = _FakeRunner(script={(1, 1): "FATAL"})
            failed = execute_repeated_run(
                tmp, run.id,
                load_plan_fn=lambda rr, rid: plan,
                run_attempt_fn=runner,
                cleanup_fn=_FakeCleanup(),
                max_attempts_per_sequence=5,
                teardown_fn=lambda rm, log: teardown_calls.append(rm),
            )
            self.assertEqual(failed.status, STATUS_FAILED)
            # Fatal failure: exactly ONE attempt for sequence 1; the engine
            # must NOT burn the remaining 4 attempts on the same doomed
            # deployment, and sequence 2 must never start.
            self.assertEqual(len(runner.calls), 1)
            self.assertEqual(failed.data["failed_samples"], 1)
            self.assertEqual(failed.data["attempted_runs"], 1)
            self.assertEqual(committed_sequences(failed), set())
            self.assertIn("FatalTopologyError", failed.data["error"])
            self.assertIn("host bridge unavailable", failed.data["error"])
            self.assertEqual(len(teardown_calls), 1)

    def test_rejects_invalid_max_attempts(self):
        with tempfile.TemporaryDirectory() as tmp:
            run = create_dataset_run(tmp, target_samples=1)
            plan = _make_generic_plan(1)
            with self.assertRaises(ValueError):
                execute_repeated_run(
                    tmp, run.id,
                    load_plan_fn=lambda rr, rid: plan,
                    run_attempt_fn=_FakeRunner(),
                    cleanup_fn=_FakeCleanup(),
                    max_attempts_per_sequence=False,
                )


# ---------------------------------------------------------------------------
# RunOptions end-to-end flow
# ---------------------------------------------------------------------------

class TestRunOptionsEndToEnd(unittest.TestCase):
    def test_run_options_flow_into_attempt_samples(self):
        with tempfile.TemporaryDirectory() as tmp:
            run = create_dataset_run(tmp, target_samples=3)
            plan = _make_generic_plan(3)
            runner = _CollectingRunner()
            opts = RunOptions(duration=45, port=40000, capture_filter="esp or ah")
            execute_repeated_run(
                tmp, run.id,
                load_plan_fn=lambda rr, rid: plan,
                run_attempt_fn=runner,
                cleanup_fn=_FakeCleanup(),
                run_options=opts,
            )
            self.assertEqual(len(runner.seen_samples), 3)
            for sample in runner.seen_samples:
                self.assertIn("traffic", sample)
                self.assertEqual(sample["traffic"]["duration"], 45.0)
                self.assertEqual(sample["traffic"]["port"], 40000)
                self.assertEqual(sample["traffic"]["capture_filter"], "esp or ah")
                # profile is a plan-level identity field; the dataset adapter
                # merges it when building the pipeline traffic dict.
                self.assertNotIn("profile", sample["traffic"])

    def test_per_sample_traffic_overrides_win(self):
        with tempfile.TemporaryDirectory() as tmp:
            run = create_dataset_run(tmp, target_samples=2)
            plan = _make_generic_plan(2)
            plan["samples"][0]["traffic"] = {"duration": 10, "port": 9999}
            plan["samples"][1]["traffic"] = {"capture_filter": "udp port 500"}
            runner = _CollectingRunner()
            opts = RunOptions(duration=45, port=40000, capture_filter="esp or ah")
            execute_repeated_run(
                tmp, run.id,
                load_plan_fn=lambda rr, rid: plan,
                run_attempt_fn=runner,
                cleanup_fn=_FakeCleanup(),
                run_options=opts,
            )
            s0, s1 = runner.seen_samples
            # sample 0: duration and port overridden, capture_filter from run_options
            self.assertEqual(s0["traffic"]["duration"], 10)
            self.assertEqual(s0["traffic"]["port"], 9999)
            self.assertEqual(s0["traffic"]["capture_filter"], "esp or ah")
            # sample 1: capture_filter overridden, duration/port from run_options
            self.assertEqual(s1["traffic"]["duration"], 45.0)
            self.assertEqual(s1["traffic"]["port"], 40000)
            self.assertEqual(s1["traffic"]["capture_filter"], "udp port 500")

    def test_no_run_options_means_default_traffic(self):
        with tempfile.TemporaryDirectory() as tmp:
            run = create_dataset_run(tmp, target_samples=1)
            plan = _make_generic_plan(1)
            runner = _CollectingRunner()
            execute_repeated_run(
                tmp, run.id,
                load_plan_fn=lambda rr, rid: plan,
                run_attempt_fn=runner,
                cleanup_fn=_FakeCleanup(),
                run_options=None,
            )
            self.assertEqual(len(runner.seen_samples), 1)
            sample = runner.seen_samples[0]
            self.assertNotIn("traffic", sample, "no traffic dict added when run_options is None")

    def test_run_options_experiment_ids_use_run_id(self):
        """Verify the generic engine's experiment ids follow the same pattern."""
        with tempfile.TemporaryDirectory() as tmp:
            run = create_dataset_run(tmp, target_samples=1)
            plan = _make_generic_plan(1)
            runner = _FakeRunner()
            completed = execute_repeated_run(
                tmp, run.id,
                load_plan_fn=lambda rr, rid: plan,
                run_attempt_fn=runner,
                cleanup_fn=_FakeCleanup(),
            )
            exp_ids = [cid for _, _, cid, _ in runner.calls]
            for exp_id in exp_ids:
                parsed = parse_experiment_id(exp_id)
                self.assertIsNotNone(parsed)
                self.assertEqual(parsed[0], run.id)


# ---------------------------------------------------------------------------
# Re-exports / backward compat via dataset_executor
# ---------------------------------------------------------------------------

class TestReExports(unittest.TestCase):
    """Ensure dataset_executor re-exports the generic engine symbols."""

    def test_outcomes_match(self):
        from controller.dataset_executor import OUTCOME_SUCCESS as de_success
        from controller.dataset_executor import OUTCOME_FAILED as de_failed
        from controller.dataset_executor import OUTCOME_INTERRUPTED as de_interrupted
        self.assertEqual(de_success, OUTCOME_SUCCESS)
        self.assertEqual(de_failed, OUTCOME_FAILED)
        self.assertEqual(de_interrupted, OUTCOME_INTERRUPTED)

    def test_statuses_match(self):
        from controller.dataset_executor import STATUS_RUNNING as de_running
        from controller.dataset_executor import STATUS_COMPLETED as de_completed
        from controller.dataset_executor import STATUS_FAILED as de_failed
        self.assertEqual(de_running, STATUS_RUNNING)
        self.assertEqual(de_completed, STATUS_COMPLETED)
        self.assertEqual(de_failed, STATUS_FAILED)

    def test_run_options_reexported(self):
        from controller.dataset_executor import RunOptions as DeRunOptions
        self.assertIs(DeRunOptions, RunOptions)


if __name__ == "__main__":
    unittest.main()
