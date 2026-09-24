"""Module 4 hardening tests: failure, interruption, crash and resume semantics.

Run either as:

    .venv/bin/python -m controller.test_dataset_hardening

or:

    .venv/bin/python -m unittest controller.test_dataset_hardening

Uses a temporary directory; never touches the production results directory.
The real testbed pipeline is replaced with fakes via dependency injection, so
no Containerlab/StrongSwan is required and no experiment is executed.
"""

import json
import tempfile
import unittest
from collections import Counter
from pathlib import Path

from controller.dataset_executor import (
    DEFAULT_ATTEMPTS_PER_SEQUENCE,
    OUTCOME_FAILED,
    OUTCOME_INTERRUPTED,
    OUTCOME_SUCCESS,
    STATUS_COMPLETED,
    STATUS_FAILED,
    STATUS_PAUSED,
    STATUS_RUNNING,
    committed_sequences,
    execute_dataset_run,
    experiment_id_for,
    parse_experiment_id,
    validate_runtime_state,
)
from controller.dataset_planner import (
    build_sample_plan,
    traffic_quota,
    write_sample_plan,
)
from controller.dataset_run import (
    create_dataset_run,
    load_dataset_run,
    validate_state,
)


class FakeRunner:
    """Injectable, scripted attempt runner.

    ``script`` maps ``(sequence, attempt)`` to one of ``"SUCCESS"``,
    ``"FAILED"``, ``"INTERRUPTED"``, ``"KeyboardInterrupt"`` or
    ``"SystemExit"``; anything else falls back to ``default``.  Attempt
    numbers come from the experiment id so replays stay aligned after resume.
    ``SystemExit`` simulates an abrupt process death (SIGKILL-style): it
    propagates out of the engine with the attempt already marked in-progress.
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
            (seq, attempt, experiment_id, sample["traffic_profile"],
             sample["security_posture"], sample["configuration_id"])
        )
        kind = self.script.get((seq, attempt), self.default)
        tmp = Path(tmp_dir)
        tmp.mkdir(parents=True, exist_ok=True)

        if kind == "KeyboardInterrupt":
            raise KeyboardInterrupt()
        if kind == "SystemExit":
            raise SystemExit("simulated abrupt process death")
        if kind == OUTCOME_FAILED:
            (tmp / "partial.log").write_text("partial capture", encoding="utf-8")
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
                "security_posture": sample["security_posture"],
                "traffic_profile": sample["traffic_profile"],
                "status": "PASS",
            },
            "features": {"packet_count": 100},
            "traffic_log": f"STATS profile={sample['traffic_profile']}\n",
            "pcap_path": str(pcap),
            "connectivity": {"status": "PASS"},
            "ipsec": {"ike_sa": "ESTABLISHED", "child_sa": "INSTALLED"},
        }


class FakeCleanup:
    """Injectable cleanup.  ``fail_on`` is a set of experiment ids whose
    cleanup should raise; ``fail_once`` makes exactly ONE cleanup raise.
    """

    def __init__(self, fail_on=None, fail_once=None):
        self.fail_on = set(fail_on or [])
        self.fail_once = fail_once if isinstance(fail_once, set) else set(fail_once or [])
        self.calls = []
        self.failures = []

    def __call__(self, experiment_id, sample, tmp_dir, runtime_ctx=None,
                         skip_destroy=False):
        self.calls.append((experiment_id, sample["sequence"]))
        if experiment_id in self.fail_once or experiment_id in self.fail_on:
            if experiment_id in self.fail_once:
                self.fail_once.discard(experiment_id)
                self.failures.append(experiment_id)
                raise RuntimeError(f"cleanup failed for {experiment_id}")
            self.failures.append(experiment_id)
            raise RuntimeError(f"cleanup failed for {experiment_id}")
        if tmp_dir is not None:
            import shutil
            shutil.rmtree(Path(tmp_dir), ignore_errors=True)


def make_run_and_plan(tmp, target=3):
    run = create_dataset_run(tmp, target_samples=target)
    plan = build_sample_plan(target)
    write_sample_plan(tmp, run.id, plan)
    return run, plan


def reload(tmp, run):
    return load_dataset_run(tmp, run.id)


class TestGracefulInterruption(unittest.TestCase):
    def test_keyboard_interrupt_pauses_and_resumes(self):
        with tempfile.TemporaryDirectory() as tmp:
            run, plan = make_run_and_plan(tmp, target=3)
            first = FakeRunner(script={(2, 1): "KeyboardInterrupt"})
            paused = execute_dataset_run(
                tmp, run.id, run_attempt_fn=first, cleanup_fn=FakeCleanup(),
            )
            self.assertEqual(paused.status, STATUS_PAUSED)
            self.assertEqual(paused.successful_samples, 1)
            self.assertEqual(paused.interrupted_samples, 1)
            self.assertEqual(committed_sequences(paused), {1})
            self.assertEqual(paused.data["current_sequence"], 2)
            self.assertEqual(
                parse_experiment_id(paused.data["current_experiment"]),
                (run.id, 2, 1),
            )
            # no fabrication: seq 2 must NOT be committed by the interrupt
            self.assertNotIn(
                experiment_id_for(run.id, 2, 1),
                paused.data["committed_run_ids"],
            )

            second = FakeRunner()  # seq 2 attempt 2 + seq 3 succeed
            completed = execute_dataset_run(
                tmp, run.id, run_attempt_fn=second, cleanup_fn=FakeCleanup(),
            )
            self.assertEqual(completed.status, STATUS_COMPLETED)
            self.assertEqual(committed_sequences(completed), {1, 2, 3})
            self.assertEqual(len(completed.data["committed_run_ids"]), 3)
            self.assertEqual(completed.successful_samples, 3)
            self.assertEqual(
                parse_experiment_id(completed.data["committed_run_ids"][1]),
                (run.id, 2, 2),
            )
            self.assertEqual([c[0] for c in second.calls], [2, 3])

    def test_returned_interrupted_outcome_retries_in_same_run(self):
        with tempfile.TemporaryDirectory() as tmp:
            run, _ = make_run_and_plan(tmp, target=1)
            runner = FakeRunner(script={(1, 1): OUTCOME_INTERRUPTED})
            completed = execute_dataset_run(
                tmp, run.id, run_attempt_fn=runner, cleanup_fn=FakeCleanup(),
            )
            self.assertEqual(completed.status, STATUS_COMPLETED)
            self.assertEqual(completed.interrupted_samples, 1)
            self.assertEqual(completed.successful_samples, 1)
            self.assertEqual(committed_sequences(completed), {1})

    def test_failed_sequence_resumes(self):
        with tempfile.TemporaryDirectory() as tmp:
            run, _ = make_run_and_plan(tmp, target=3)
            runner = FakeRunner(script={(2, 1): OUTCOME_FAILED})
            completed = execute_dataset_run(
                tmp, run.id, run_attempt_fn=runner, cleanup_fn=FakeCleanup(),
            )
            self.assertEqual(completed.status, STATUS_COMPLETED)
            self.assertEqual(completed.failed_samples, 1)
            self.assertEqual(completed.successful_samples, 3)
            self.assertEqual(committed_sequences(completed), {1, 2, 3})


class TestAbruptTermination(unittest.TestCase):
    def _run_and_die(self, tmp, run, script, cleanup=None):
        runner = FakeRunner(script=script)
        with self.assertRaises(SystemExit):
            execute_dataset_run(
                tmp, run.id, run_attempt_fn=runner,
                cleanup_fn=cleanup or FakeCleanup(),
            )
        return runner

    def test_sigkill_style_restart_retries_with_new_attempt_number(self):
        with tempfile.TemporaryDirectory() as tmp:
            run, _ = make_run_and_plan(tmp, target=3)
            first = self._run_and_die(tmp, run, {(2, 1): "SystemExit"})

            # State left behind: seq1 committed, seq2 attempt 1 marked
            # in-progress, NOT committed.
            stalled = reload(tmp, run)
            self.assertEqual(stalled.status, STATUS_RUNNING)
            self.assertEqual(committed_sequences(stalled), {1})
            marker = stalled.data["attempt_in_progress"]
            self.assertEqual(marker["sequence"], 2)
            self.assertEqual(marker["attempt"], 1)
            self.assertEqual(
                marker["experiment_id"], experiment_id_for(run.id, 2, 1)
            )
            self.assertEqual(stalled.data["attempts_per_sequence"]["2"], 1)
            self.assertEqual(stalled.successful_samples, 1)

            # Restart: seq 2 must be retried at attempt 02 (never reusing 01).
            second = FakeRunner()
            completed = execute_dataset_run(
                tmp, run.id, run_attempt_fn=second, cleanup_fn=FakeCleanup(),
            )
            self.assertEqual(completed.status, STATUS_COMPLETED)
            self.assertEqual(committed_sequences(completed), {1, 2, 3})
            self.assertEqual(completed.successful_samples, 3)
            seq2_commits = [
                c for c in completed.data["committed_run_ids"]
                if parse_experiment_id(c)[1] == 2
            ]
            self.assertEqual(len(seq2_commits), 1)
            self.assertEqual(
                parse_experiment_id(seq2_commits[0])[2], 2
            )
            # the orphaned attempt number survives in the durable budget
            self.assertEqual(completed.data["attempts_per_sequence"]["2"], 2)
            self.assertIsNone(completed.data["attempt_in_progress"])

    def test_incomplete_current_attempt_is_never_committed(self):
        with tempfile.TemporaryDirectory() as tmp:
            run, _ = make_run_and_plan(tmp, target=1)
            self._run_and_die(tmp, run, {(1, 1): "SystemExit"})
            stalled = reload(tmp, run)
            self.assertEqual(stalled.successful_samples, 0)
            self.assertEqual(stalled.data["committed_run_ids"], [])
            self.assertEqual(stalled.attempted_runs, 0)
            # the started-but-unknown attempt consumed a budget slot
            self.assertEqual(stalled.data["attempts_per_sequence"]["1"], 1)

    def test_no_success_from_died_attempt_files(self):
        # Even leftover artifacts under experiments/ never fabricate success.
        with tempfile.TemporaryDirectory() as tmp:
            run, _ = make_run_and_plan(tmp, target=1)
            runner = FakeRunner(script={(1, 1): "SystemExit"})
            # Fake a pipeline that died right AFTER writing its artifacts but
            # before the engine could record a commit.
            orig = runner
            first_call = True

            def dying(experiment_id, sample, tmp_dir, results_root,
                      run_id=None, log=None, reuse=None):
                orig(experiment_id, sample, tmp_dir, results_root,
                     run_id=run_id, log=log)
                return {
                    "status": OUTCOME_SUCCESS,
                    "experiment_id": experiment_id,
                    "metadata": {"experiment_id": experiment_id},
                    "features": {"packet_count": 5},
                    "traffic_log": "STATS\n",
                    "pcap_path": str(Path(tmp_dir) / "x.pcap"),
                }

            with self.assertRaises(SystemExit):
                execute_dataset_run(
                    tmp, run.id, run_attempt_fn=dying,
                    cleanup_fn=FakeCleanup(),
                )
            stalled = reload(tmp, run)
            self.assertEqual(stalled.successful_samples, 0)
            self.assertEqual(stalled.data["committed_run_ids"], [])
            self.assertEqual(stalled.status, STATUS_RUNNING)


class TestResumeAndDuplicatePrevention(unittest.TestCase):
    def test_committed_sequences_are_skipped_on_resume(self):
        with tempfile.TemporaryDirectory() as tmp:
            run, _ = make_run_and_plan(tmp, target=3)
            execute_dataset_run(
                tmp, run.id, run_attempt_fn=FakeRunner(
                    script={(3, 1): "KeyboardInterrupt"}
                ),
                cleanup_fn=FakeCleanup(),
            )
            # Resume must not re-run committed sequences 1 and 2.
            # A runner that fails everything except seq 3 proves they are
            # skipped rather than executed-and-failed.
            second = FakeRunner(
                script={
                    (1, 1): OUTCOME_FAILED, (1, 2): OUTCOME_FAILED,
                    (2, 1): OUTCOME_FAILED, (2, 2): OUTCOME_FAILED,
                }
            )
            completed = execute_dataset_run(
                tmp, run.id, run_attempt_fn=second, cleanup_fn=FakeCleanup(),
            )
            self.assertEqual(completed.status, STATUS_COMPLETED)
            self.assertEqual(
                [c[0] for c in second.calls], [3]
            )
            self.assertEqual(len(completed.data["committed_run_ids"]), 3)

    def test_duplicate_resume_does_not_duplicate_samples(self):
        with tempfile.TemporaryDirectory() as tmp:
            run, _ = make_run_and_plan(tmp, target=3)
            execute_dataset_run(
                tmp, run.id, run_attempt_fn=FakeRunner(),
                cleanup_fn=FakeCleanup(),
            )
            again = execute_dataset_run(
                tmp, run.id, run_attempt_fn=FakeRunner(script={}),
                cleanup_fn=FakeCleanup(),
            )
            self.assertEqual(again.status, STATUS_COMPLETED)
            self.assertEqual(len(again.data["committed_run_ids"]), 3)

    def test_failed_then_resume_after_commit(self):
        with tempfile.TemporaryDirectory() as tmp:
            run, _ = make_run_and_plan(tmp, target=3)
            first = FakeRunner(script={(2, 1): OUTCOME_FAILED, (3, 1): "KeyboardInterrupt"})
            paused = execute_dataset_run(
                tmp, run.id, run_attempt_fn=first, cleanup_fn=FakeCleanup(),
            )
            self.assertEqual(paused.status, STATUS_PAUSED)
            self.assertEqual(committed_sequences(paused), {1, 2})
            second = FakeRunner()
            completed = execute_dataset_run(
                tmp, run.id, run_attempt_fn=second, cleanup_fn=FakeCleanup(),
            )
            self.assertEqual(committed_sequences(completed), {1, 2, 3})
            self.assertEqual(completed.successful_samples, 3)
            self.assertEqual(len(completed.data["committed_run_ids"]), 3)


class TestReuseManagerLifetime(unittest.TestCase):
    """Module-10: the topology-reuse manager lives EXACTLY one
    execute_dataset_run() invocation.  A manager is threaded through every
    attempt of a run and a resumed run gets a brand-new one so its first
    sample always starts from a clean topology."""

    def test_single_run_forwards_one_manager_to_all_attempts(self):
        with tempfile.TemporaryDirectory() as tmp:
            run, _ = make_run_and_plan(tmp, target=3)
            runner = FakeRunner()
            execute_dataset_run(
                tmp, run.id, run_attempt_fn=runner, cleanup_fn=FakeCleanup(),
            )
            self.assertEqual(len(runner.reuse_seen), 3)
            self.assertEqual(len({id(m) for m in runner.reuse_seen}), 1)
            self.assertTrue(all(m is not None for m in runner.reuse_seen))

    def test_retry_uses_same_manager_not_a_new_one(self):
        with tempfile.TemporaryDirectory() as tmp:
            run, _ = make_run_and_plan(tmp, target=1)
            runner = FakeRunner(script={(1, 1): OUTCOME_FAILED})
            execute_dataset_run(
                tmp, run.id, run_attempt_fn=runner, cleanup_fn=FakeCleanup(),
            )
            self.assertEqual(len(runner.reuse_seen), 2)
            self.assertIs(runner.reuse_seen[0], runner.reuse_seen[1])

    def test_resume_gets_a_fresh_manager(self):
        with tempfile.TemporaryDirectory() as tmp:
            run, _ = make_run_and_plan(tmp, target=2)
            first = FakeRunner(script={(2, 1): "KeyboardInterrupt"})
            paused = execute_dataset_run(
                tmp, run.id, run_attempt_fn=first, cleanup_fn=FakeCleanup(),
            )
            self.assertEqual(paused.status, STATUS_PAUSED)
            self.assertEqual(len({id(m) for m in first.reuse_seen}), 1)

            second = FakeRunner()
            completed = execute_dataset_run(
                tmp, run.id, run_attempt_fn=second, cleanup_fn=FakeCleanup(),
            )
            self.assertEqual(completed.status, STATUS_COMPLETED)
            self.assertEqual(len(second.reuse_seen), 1)
            self.assertIsNot(second.reuse_seen[0], first.reuse_seen[0])


class TestStateConsistency(unittest.TestCase):
    def test_completed_state_is_consistent(self):
        with tempfile.TemporaryDirectory() as tmp:
            run, _ = make_run_and_plan(tmp, target=3)
            completed = execute_dataset_run(
                tmp, run.id, run_attempt_fn=FakeRunner(),
                cleanup_fn=FakeCleanup(),
            )
            self.assertEqual(completed.status, STATUS_COMPLETED)
            self.assertEqual(completed.successful_samples, 3)
            self.assertEqual(len(completed.data["committed_run_ids"]), 3)
            self.assertEqual(committed_sequences(completed), {1, 2, 3})
            validate_state(completed.data)
            validate_runtime_state(completed, 3)

    def test_complete_cannot_occur_below_target(self):
        with tempfile.TemporaryDirectory() as tmp:
            run, _ = make_run_and_plan(tmp, target=3)
            executed = execute_dataset_run(
                tmp, run.id,
                run_attempt_fn=FakeRunner(default=OUTCOME_FAILED),
                cleanup_fn=FakeCleanup(),
                max_attempts_per_sequence=1,
            )
            self.assertEqual(executed.status, STATUS_FAILED)
            self.assertNotEqual(executed.status, STATUS_COMPLETED)
            self.assertLess(executed.successful_samples, 3)
            self.assertEqual(committed_sequences(executed), set())

    def test_state_inconsistency_detected_on_load(self):
        with tempfile.TemporaryDirectory() as tmp:
            run, _ = make_run_and_plan(tmp, target=3)
            # Corrupt state on disk: successful_samples=2 but only one commit.
            state = dict(run.data)
            state["status"] = STATUS_RUNNING
            state["successful_samples"] = 2
            state["attempted_runs"] = 2
            state["committed_run_ids"] = [experiment_id_for(run.id, 1, 1)]
            state["error"] = None
            validate_state(state)  # schema-level checks still pass
            state_path = run.directory / "state.json"
            state_path.write_text(json.dumps(state, indent=2), encoding="utf-8")

            with self.assertRaises(ValueError):
                execute_dataset_run(
                    tmp, run.id, run_attempt_fn=FakeRunner(),
                    cleanup_fn=FakeCleanup(),
                )

    def test_committed_vector_out_of_range_detected(self):
        with tempfile.TemporaryDirectory() as tmp:
            run, _ = make_run_and_plan(tmp, target=1)
            state = dict(run.data)
            state["status"] = STATUS_RUNNING
            state["successful_samples"] = 1
            state["attempted_runs"] = 1
            state["committed_run_ids"] = [experiment_id_for(run.id, 9, 1)]
            (run.directory / "state.json").write_text(
                json.dumps(state, indent=2), encoding="utf-8"
            )
            with self.assertRaises(ValueError):
                execute_dataset_run(
                    tmp, run.id, run_attempt_fn=FakeRunner(),
                    cleanup_fn=FakeCleanup(),
                )


class TestAttemptNumbering(unittest.TestCase):
    def test_attempt_numbers_monotonic(self):
        with tempfile.TemporaryDirectory() as tmp:
            run, _ = make_run_and_plan(tmp, target=2)
            runner = FakeRunner(script={(1, 1): OUTCOME_FAILED})
            execute_dataset_run(
                tmp, run.id, run_attempt_fn=runner, cleanup_fn=FakeCleanup(),
            )
            per_seq = {}
            for seq, attempt, _e, _p, _po, _c in runner.calls:
                per_seq.setdefault(seq, []).append(attempt)
            for seq, attempts in per_seq.items():
                self.assertEqual(attempts, sorted(attempts))
                self.assertEqual(len(attempts), len(set(attempts)))
                self.assertEqual(
                    attempts, list(range(1, len(attempts) + 1))
                )

    def test_attempt_numbers_survive_restart(self):
        with tempfile.TemporaryDirectory() as tmp:
            run, _ = make_run_and_plan(tmp, target=2)
            with self.assertRaises(SystemExit):
                execute_dataset_run(
                    tmp, run.id,
                    run_attempt_fn=FakeRunner(script={(2, 1): "SystemExit"}),
                    cleanup_fn=FakeCleanup(),
                )
            second = FakeRunner()
            execute_dataset_run(
                tmp, run.id, run_attempt_fn=second, cleanup_fn=FakeCleanup(),
            )
            seq2_attempts = [a for s, a, *_ in second.calls if s == 2]
            self.assertEqual(seq2_attempts, [2])
            # no attempt number reused across the restart: seq1 started once,
            # seq2 started at attempt 1 (killed) then attempt 2
            data = reload(tmp, run).data
            self.assertEqual(
                data["attempts_per_sequence"], {"1": 1, "2": 2}
            )

    def test_in_flight_marker_cleared_after_normal_completion(self):
        with tempfile.TemporaryDirectory() as tmp:
            run, _ = make_run_and_plan(tmp, target=1)
            completed = execute_dataset_run(
                tmp, run.id, run_attempt_fn=FakeRunner(),
                cleanup_fn=FakeCleanup(),
            )
            self.assertIsNone(completed.data["attempt_in_progress"])


class TestImmutableRequirements(unittest.TestCase):
    def test_retry_preserves_traffic_profile(self):
        with tempfile.TemporaryDirectory() as tmp:
            run, plan = make_run_and_plan(tmp, target=3)
            runner = FakeRunner(
                script={(2, 1): OUTCOME_FAILED, (2, 2): OUTCOME_INTERRUPTED}
            )
            execute_dataset_run(
                tmp, run.id, run_attempt_fn=runner, cleanup_fn=FakeCleanup(),
            )
            for seq, _a, _e, profile, _p, _c in runner.calls:
                self.assertEqual(
                    profile, plan["samples"][seq - 1]["traffic_profile"]
                )

    def test_retry_preserves_security_posture(self):
        with tempfile.TemporaryDirectory() as tmp:
            run, plan = make_run_and_plan(tmp, target=3)
            runner = FakeRunner(
                script={(2, 1): OUTCOME_FAILED, (2, 2): OUTCOME_INTERRUPTED}
            )
            execute_dataset_run(
                tmp, run.id, run_attempt_fn=runner, cleanup_fn=FakeCleanup(),
            )
            for seq, _a, _e, _p, posture, _c in runner.calls:
                self.assertEqual(
                    posture, plan["samples"][seq - 1]["security_posture"]
                )

    def test_retry_preserves_ipsec_configuration(self):
        with tempfile.TemporaryDirectory() as tmp:
            run, plan = make_run_and_plan(tmp, target=3)
            runner = FakeRunner(
                script={(2, 1): OUTCOME_FAILED, (2, 2): OUTCOME_INTERRUPTED}
            )
            execute_dataset_run(
                tmp, run.id, run_attempt_fn=runner, cleanup_fn=FakeCleanup(),
            )
            for seq, _a, _e, _p, _po, config_id in runner.calls:
                self.assertEqual(
                    config_id,
                    plan["samples"][seq - 1]["configuration_id"],
                )

    def test_failed_attempt_never_becomes_successful(self):
        with tempfile.TemporaryDirectory() as tmp:
            run, _ = make_run_and_plan(tmp, target=1)
            runner = FakeRunner(script={(1, 1): OUTCOME_FAILED})
            executed = execute_dataset_run(
                tmp, run.id, run_attempt_fn=runner, cleanup_fn=FakeCleanup(),
            )
            self.assertEqual(executed.failed_samples, 1)
            self.assertEqual(executed.successful_samples, 1)
            failed_exp = experiment_id_for(run.id, 1, 1)
            self.assertNotIn(failed_exp, executed.data["committed_run_ids"])

    def test_interrupted_attempt_never_becomes_successful(self):
        with tempfile.TemporaryDirectory() as tmp:
            run, _ = make_run_and_plan(tmp, target=1)
            runner = FakeRunner(script={(1, 1): OUTCOME_INTERRUPTED})
            executed = execute_dataset_run(
                tmp, run.id, run_attempt_fn=runner, cleanup_fn=FakeCleanup(),
            )
            self.assertEqual(executed.interrupted_samples, 1)
            self.assertEqual(executed.successful_samples, 1)
            interrupted_exp = experiment_id_for(run.id, 1, 1)
            self.assertNotIn(interrupted_exp, executed.data["committed_run_ids"])


class TestCleanupFailurePolicy(unittest.TestCase):
    def test_cleanup_executes_before_retry(self):
        with tempfile.TemporaryDirectory() as tmp:
            run, _ = make_run_and_plan(tmp, target=1)
            events = []

            def tracing_runner(experiment_id, sample, tmp_dir, results_root,
                               run_id=None, log=None, reuse=None):
                parsed = parse_experiment_id(experiment_id)
                if parsed[2] == 1:
                    events.append(("start", experiment_id))
                    return {
                        "status": OUTCOME_FAILED,
                        "experiment_id": experiment_id,
                        "reason": "x", "error": "x",
                    }
                events.append(("start", experiment_id))
                Path(tmp_dir).mkdir(parents=True, exist_ok=True)
                pcap = Path(tmp_dir) / "c.pcap"
                pcap.write_bytes(b"\x00" * 4)
                return {
                    "status": OUTCOME_SUCCESS,
                    "experiment_id": experiment_id,
                    "metadata": {"experiment_id": experiment_id},
                    "features": {"packet_count": 1},
                    "traffic_log": "S\n",
                    "pcap_path": str(pcap),
                }

            def tracing_cleanup(experiment_id, sample, tmp_dir, runtime_ctx=None,
                                skip_destroy=False):
                events.append(("cleanup", experiment_id))
                if tmp_dir is not None:
                    import shutil
                    shutil.rmtree(Path(tmp_dir), ignore_errors=True)

            execute_dataset_run(
                tmp, run.id, run_attempt_fn=tracing_runner,
                cleanup_fn=tracing_cleanup,
            )
            exp1 = experiment_id_for(run.id, 1, 1)
            exp2 = experiment_id_for(run.id, 1, 2)
            self.assertEqual(
                events,
                [("start", exp1), ("cleanup", exp1),
                 ("start", exp2), ("cleanup", exp2)],
            )

    def test_cleanup_failure_keeps_sample_failed_and_pauses(self):
        with tempfile.TemporaryDirectory() as tmp:
            run, _ = make_run_and_plan(tmp, target=1)
            runner = FakeRunner(script={(1, 1): OUTCOME_FAILED})
            # cleanup always fails -> failed sample stays failed, no retry
            cleanup = FakeCleanup(fail_on={experiment_id_for(run.id, 1, 1)})
            executed = execute_dataset_run(
                tmp, run.id, run_attempt_fn=runner, cleanup_fn=cleanup,
            )
            self.assertEqual(executed.status, STATUS_PAUSED)
            self.assertEqual(executed.failed_samples, 1)
            self.assertEqual(executed.successful_samples, 0)
            self.assertEqual(executed.data["committed_run_ids"], [])
            self.assertEqual(executed.data["stale_sequence"], 1)
            self.assertEqual(
                executed.data["stale_experiment"],
                experiment_id_for(run.id, 1, 1),
            )
            self.assertIn("cleanup failed", executed.data["error"])
            # cleanup_error recorded separately next to the failure record
            err = (
                run.directory / "failures" / experiment_id_for(run.id, 1, 1)
                / "cleanup_error.log"
            )
            self.assertTrue(err.is_file())
            # no blind continuation: the retry attempt never started
            self.assertEqual([c[0] for c in runner.calls], [1])

    def test_stale_environment_prevents_blind_continuation(self):
        with tempfile.TemporaryDirectory() as tmp:
            run, _ = make_run_and_plan(tmp, target=1)
            runner = FakeRunner(script={(1, 1): OUTCOME_FAILED})
            exp1 = experiment_id_for(run.id, 1, 1)
            cleanup = FakeCleanup(fail_on={exp1})
            executed = execute_dataset_run(
                tmp, run.id, run_attempt_fn=runner, cleanup_fn=cleanup,
            )
            # on resume the stale guard re-cleans; it keeps failing -> PAUSED
            second_runner = FakeRunner()
            resumed = execute_dataset_run(
                tmp, run.id, run_attempt_fn=second_runner, cleanup_fn=cleanup,
            )
            self.assertEqual(resumed.status, STATUS_PAUSED)
            self.assertEqual([c for c in second_runner.calls], [])
            self.assertIn("stale environment", resumed.data["error"])

    def test_cleanup_failure_after_success_does_not_lose_sample(self):
        with tempfile.TemporaryDirectory() as tmp:
            run, _ = make_run_and_plan(tmp, target=2)
            exp1 = experiment_id_for(run.id, 1, 1)
            cleanup = FakeCleanup(fail_once={exp1})
            executed = execute_dataset_run(
                tmp, run.id, run_attempt_fn=FakeRunner(), cleanup_fn=cleanup,
            )
            # seq 1 succeeded, its cleanup failed once; the stale guard
            # re-cleaned before seq 2, so the run still completes.
            self.assertEqual(executed.status, STATUS_COMPLETED)
            self.assertEqual(executed.successful_samples, 2)
            self.assertEqual(committed_sequences(executed), {1, 2})
            self.assertIsNone(executed.data["stale_sequence"])
            self.assertIn(exp1, cleanup.failures)


class TestPlanImmutability(unittest.TestCase):
    def test_missing_plan_safe_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            run = create_dataset_run(tmp, target_samples=3)
            with self.assertRaises(FileNotFoundError):
                execute_dataset_run(
                    tmp, run.id, run_attempt_fn=FakeRunner(),
                    cleanup_fn=FakeCleanup(),
                )

    def test_corrupted_plan_safe_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            run, _ = make_run_and_plan(tmp, target=3)
            plan_path = run.directory / "staging" / "plan.json"
            plan_path.write_text("{ not valid json", encoding="utf-8")
            with self.assertRaises(ValueError):
                execute_dataset_run(
                    tmp, run.id, run_attempt_fn=FakeRunner(),
                    cleanup_fn=FakeCleanup(),
                )

    def test_changed_plan_rejected_on_resume(self):
        with tempfile.TemporaryDirectory() as tmp:
            run, plan = make_run_and_plan(tmp, target=3)
            execute_dataset_run(
                tmp, run.id,
                run_attempt_fn=FakeRunner(script={(2, 1): "KeyboardInterrupt"}),
                cleanup_fn=FakeCleanup(),
            )
            reloaded = reload(tmp, run)
            self.assertIsNotNone(reloaded.data["plan_fingerprint"])

            modified = build_sample_plan(3)
            # swap two profiles: still structurally valid, but different JSON
            modified["samples"][0]["traffic_profile"], modified["samples"][1]["traffic_profile"] = (
                modified["samples"][1]["traffic_profile"],
                modified["samples"][0]["traffic_profile"],
            )
            write_sample_plan(tmp, run.id, modified)
            with self.assertRaises(ValueError):
                execute_dataset_run(
                    tmp, run.id, run_attempt_fn=FakeRunner(),
                    cleanup_fn=FakeCleanup(),
                )

    def test_fingerprint_persisted_on_first_run(self):
        with tempfile.TemporaryDirectory() as tmp:
            run, _ = make_run_and_plan(tmp, target=1)
            execute_dataset_run(
                tmp, run.id,
                run_attempt_fn=FakeRunner(script={(1, 1): "KeyboardInterrupt"}),
                cleanup_fn=FakeCleanup(),
            )
            state = reload(tmp, run).data
            self.assertTrue(isinstance(state["plan_fingerprint"], str))
            self.assertEqual(state["target_samples"], 1)


class TestAttemptBudgetSemantics(unittest.TestCase):
    def test_interrupt_at_budget_pauses_not_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            run, _ = make_run_and_plan(tmp, target=1)
            runner = FakeRunner(
                script={(1, 1): OUTCOME_FAILED, (1, 2): OUTCOME_FAILED,
                        (1, 3): OUTCOME_FAILED, (1, 4): OUTCOME_FAILED,
                        (1, 5): "KeyboardInterrupt"}
            )
            paused = execute_dataset_run(
                tmp, run.id, run_attempt_fn=runner, cleanup_fn=FakeCleanup(),
                max_attempts_per_sequence=5,
            )
            self.assertEqual(paused.status, STATUS_PAUSED)
            self.assertEqual(paused.failed_samples, 4)
            self.assertEqual(paused.interrupted_samples, 1)
            self.assertEqual(paused.successful_samples, 0)
            self.assertEqual(paused.data["attempts_per_sequence"]["1"], 5)

    def test_resume_with_same_budget_exhausts(self):
        with tempfile.TemporaryDirectory() as tmp:
            run, _ = make_run_and_plan(tmp, target=1)
            execute_dataset_run(
                tmp, run.id,
                run_attempt_fn=FakeRunner(
                    script={(1, 1): OUTCOME_FAILED, (1, 2): OUTCOME_FAILED,
                            (1, 3): OUTCOME_FAILED, (1, 4): OUTCOME_FAILED,
                            (1, 5): "KeyboardInterrupt"}
                ),
                cleanup_fn=FakeCleanup(),
                max_attempts_per_sequence=5,
            )
            second = FakeRunner()
            exhausted = execute_dataset_run(
                tmp, run.id, run_attempt_fn=second, cleanup_fn=FakeCleanup(),
                max_attempts_per_sequence=5,
            )
            self.assertEqual(exhausted.status, STATUS_FAILED)
            self.assertNotEqual(exhausted.status, STATUS_COMPLETED)
            self.assertEqual([c for c in second.calls], [])
            with self.assertRaises(ValueError):
                execute_dataset_run(
                    tmp, run.id, run_attempt_fn=FakeRunner(),
                    cleanup_fn=FakeCleanup(),
                    max_attempts_per_sequence=5,
                )

    def test_resume_with_larger_budget_continues(self):
        with tempfile.TemporaryDirectory() as tmp:
            run, _ = make_run_and_plan(tmp, target=1)
            execute_dataset_run(
                tmp, run.id,
                run_attempt_fn=FakeRunner(
                    script={(1, 1): OUTCOME_FAILED, (1, 2): OUTCOME_FAILED,
                            (1, 3): OUTCOME_FAILED, (1, 4): OUTCOME_FAILED,
                            (1, 5): "KeyboardInterrupt"}
                ),
                cleanup_fn=FakeCleanup(),
                max_attempts_per_sequence=5,
            )
            second = FakeRunner()  # attempt 6 succeeds
            completed = execute_dataset_run(
                tmp, run.id, run_attempt_fn=second, cleanup_fn=FakeCleanup(),
                max_attempts_per_sequence=6,
            )
            self.assertEqual(completed.status, STATUS_COMPLETED)
            self.assertEqual(completed.successful_samples, 1)
            self.assertEqual([c[0] for c in second.calls], [1])
            seq1 = [a for s, a, *_ in second.calls if s == 1]
            self.assertEqual(seq1, [6])

    def test_returned_interrupt_at_budget_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            run, _ = make_run_and_plan(tmp, target=1)
            runner = FakeRunner(
                script={(1, 1): OUTCOME_FAILED, (1, 2): OUTCOME_FAILED,
                        (1, 3): OUTCOME_FAILED, (1, 4): OUTCOME_FAILED,
                        (1, 5): OUTCOME_INTERRUPTED}
            )
            executed = execute_dataset_run(
                tmp, run.id, run_attempt_fn=runner, cleanup_fn=FakeCleanup(),
                max_attempts_per_sequence=5,
            )
            self.assertEqual(executed.status, STATUS_FAILED)
            self.assertEqual(executed.interrupted_samples, 1)
            self.assertEqual(executed.successful_samples, 0)


class TestAllocationSemantics(unittest.TestCase):
    def test_target3_exactly_three_successes_despite_failures(self):
        with tempfile.TemporaryDirectory() as tmp:
            run, _ = make_run_and_plan(tmp, target=3)
            runner = FakeRunner(
                script={(1, 1): OUTCOME_FAILED, (1, 2): OUTCOME_FAILED,
                        (2, 1): OUTCOME_INTERRUPTED, (3, 1): OUTCOME_FAILED}
            )
            completed = execute_dataset_run(
                tmp, run.id, run_attempt_fn=runner, cleanup_fn=FakeCleanup(),
            )
            self.assertEqual(completed.status, STATUS_COMPLETED)
            self.assertEqual(completed.successful_samples, 3)
            self.assertEqual(committed_sequences(completed), {1, 2, 3})
            self.assertEqual(len(completed.data["committed_run_ids"]), 3)
            self.assertEqual(completed.attempted_runs, 7)

    def test_traffic_quotas_survive_failures(self):
        with tempfile.TemporaryDirectory() as tmp:
            run, plan = make_run_and_plan(tmp, target=6)
            runner = FakeRunner(
                script={(2, 1): OUTCOME_FAILED, (3, 1): OUTCOME_INTERRUPTED,
                        (4, 1): OUTCOME_FAILED, (5, 1): OUTCOME_FAILED}
            )
            completed = execute_dataset_run(
                tmp, run.id, run_attempt_fn=runner, cleanup_fn=FakeCleanup(),
            )
            self.assertEqual(completed.status, STATUS_COMPLETED)
            profiles = [
                plan["samples"][seq - 1]["traffic_profile"]
                for seq in sorted(committed_sequences(completed))
            ]
            self.assertEqual(Counter(profiles), traffic_quota(6))

    def test_posture_distribution_matches_successful_plan(self):
        with tempfile.TemporaryDirectory() as tmp:
            run, plan = make_run_and_plan(tmp, target=6)
            runner = FakeRunner(
                script={(1, 1): OUTCOME_FAILED, (3, 1): OUTCOME_INTERRUPTED,
                        (5, 1): OUTCOME_FAILED}
            )
            completed = execute_dataset_run(
                tmp, run.id, run_attempt_fn=runner, cleanup_fn=FakeCleanup(),
            )
            self.assertEqual(completed.status, STATUS_COMPLETED)
            committed = sorted(committed_sequences(completed))
            for seq in committed:
                exp_id = next(
                    e for e in completed.data["committed_run_ids"]
                    if parse_experiment_id(e)[1] == seq
                )
                meta = json.loads(
                    (run.directory / "experiments" / exp_id / "metadata.json")
                    .read_text(encoding="utf-8")
                )
                self.assertEqual(
                    meta["security_posture"],
                    plan["samples"][seq - 1]["security_posture"],
                )


if __name__ == "__main__":
    unittest.main(verbosity=2)