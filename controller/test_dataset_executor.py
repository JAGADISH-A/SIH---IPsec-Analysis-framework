"""Focused tests for the dataset execution engine (Module 3).

Run either as:

    .venv/bin/python -m controller.test_dataset_executor

or:

    .venv/bin/python -m unittest controller.test_dataset_executor

Uses a temporary directory; never touches the production results directory.
The real testbed pipeline is replaced with fakes via dependency injection, so
no Containerlab/StrongSwan is required and no experiment is executed.
"""

import json
import shutil
import tempfile
import unittest
from collections import Counter
from pathlib import Path
from unittest.mock import patch

from controller.dataset_executor import (
    DEFAULT_ATTEMPTS_PER_SEQUENCE,
    OUTCOME_FAILED,
    OUTCOME_INTERRUPTED,
    OUTCOME_SUCCESS,
    STATUS_COMPLETED,
    STATUS_FAILED,
    STATUS_PAUSED,
    STATUS_RUNNING,
    cleanup_attempt,
    committed_sequences,
    execute_dataset_run,
    experiment_id_for,
    load_plan,
    next_sequence_to_run,
    parse_experiment_id,
    run_attempt,
    validate_plan,
)
from controller.dataset_planner import build_sample_plan, traffic_quota, write_sample_plan
from controller.dataset_run import create_dataset_run, load_dataset_run, validate_state
from controller import campaign as campaign_mod
from controller.executor import reset_and_deploy


class FakeRunner:
    """Injectably replays a scripted sequence of attempt outcomes.

    ``script`` maps (sequence, attempt) to one of "SUCCESS", "FAILED",
    "INTERRUPTED", "KeyboardInterrupt"; anything else falls back to the
    run's ``default``.  Attempt numbers come from the experiment id so the
    replay stays aligned with the engine after resumes.
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
        call = (
            seq, attempt, experiment_id,
            sample["traffic_profile"], sample["security_posture"],
            sample["configuration_id"],
        )
        self.calls.append(call)

        kind = self.script.get((seq, attempt), self.default)
        tmp = Path(tmp_dir)
        tmp.mkdir(parents=True, exist_ok=True)

        if kind == "KeyboardInterrupt":
            raise KeyboardInterrupt()

        if kind == OUTCOME_FAILED:
            (tmp / "partial.log").write_text("partial failed capture", encoding="utf-8")
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
    def __init__(self):
        self.calls = []

    def __call__(self, experiment_id, sample, tmp_dir, runtime_ctx=None,
                         skip_destroy=False):
        self.calls.append((experiment_id, sample["sequence"]))
        if tmp_dir is not None:
            shutil.rmtree(Path(tmp_dir), ignore_errors=True)


def make_run_and_plan(tmp, target=3):
    run = create_dataset_run(tmp, target_samples=target)
    plan = build_sample_plan(target)
    write_sample_plan(tmp, run.id, plan)
    return run, plan


def run_to_completion(tmp, run, target, script=None, default="SUCCESS",
                      max_attempts=DEFAULT_ATTEMPTS_PER_SEQUENCE):
    runner = FakeRunner(script, default=default)
    cleanup = FakeCleanup()
    executed = execute_dataset_run(
        tmp, run.id,
        run_attempt_fn=runner,
        cleanup_fn=cleanup,
        max_attempts_per_sequence=max_attempts,
    )
    return executed, runner, cleanup


def reload(tmp, run):
    return load_dataset_run(tmp, run.id)


class TestExperimentIds(unittest.TestCase):
    def test_round_trip(self):
        dataset_run_id = "dataset-20260913-194300"
        exp_id = experiment_id_for(dataset_run_id, 12, 3)
        self.assertEqual(exp_id, "dataset-20260913-194300-exp-0012-attempt-03")
        self.assertEqual(
            parse_experiment_id(exp_id), (dataset_run_id, 12, 3)
        )

    def test_unrelated_id_not_parsed(self):
        self.assertIsNone(parse_experiment_id("some-campaign-exp-0001"))

    def test_committed_ids_are_traceable(self):
        with tempfile.TemporaryDirectory() as tmp:
            run, _ = make_run_and_plan(tmp, target=3)
            runner = FakeRunner()
            executed = execute_dataset_run(
                tmp, run.id, run_attempt_fn=runner, cleanup_fn=FakeCleanup(),
            )
            reloaded = reload(tmp, run)
            for committed in reloaded.data["committed_run_ids"]:
                parsed = parse_experiment_id(committed)
                self.assertIsNotNone(parsed)
                self.assertEqual(parsed[0], run.id)


class TestBasicExecution(unittest.TestCase):
    def test_one_successful_sample(self):
        with tempfile.TemporaryDirectory() as tmp:
            run, _ = make_run_and_plan(tmp, target=1)
            executed, runner, _ = run_to_completion(tmp, run, target=1)
            self.assertEqual(executed.status, STATUS_COMPLETED)
            self.assertEqual(executed.attempted_runs, 1)
            self.assertEqual(executed.successful_samples, 1)
            self.assertEqual(executed.failed_samples, 0)
            self.assertEqual(executed.interrupted_samples, 0)
            self.assertEqual(committed_sequences(executed), {1})
            exp_id = experiment_id_for(run.id, 1, 1)
            self.assertTrue((run.directory / "experiments" / exp_id).is_dir())

    def test_three_successes(self):
        with tempfile.TemporaryDirectory() as tmp:
            run, _ = make_run_and_plan(tmp, target=3)
            executed, runner, _ = run_to_completion(tmp, run, target=3)
            self.assertEqual(executed.status, STATUS_COMPLETED)
            self.assertEqual(executed.attempted_runs, 3)
            self.assertEqual(executed.successful_samples, 3)
            self.assertEqual(committed_sequences(executed), {1, 2, 3})

    def test_failure_then_recovery(self):
        with tempfile.TemporaryDirectory() as tmp:
            run, plan = make_run_and_plan(tmp, target=3)
            executed, runner, _ = run_to_completion(
                tmp, run, target=3, script={(2, 1): OUTCOME_FAILED}
            )
            self.assertEqual(executed.status, STATUS_COMPLETED)
            self.assertEqual(executed.attempted_runs, 4)
            self.assertEqual(executed.successful_samples, 3)
            self.assertEqual(executed.failed_samples, 1)
            self.assertEqual(committed_sequences(executed), {1, 2, 3})

    def test_interrupted_then_recovery(self):
        with tempfile.TemporaryDirectory() as tmp:
            run, _ = make_run_and_plan(tmp, target=3)
            executed, runner, _ = run_to_completion(
                tmp, run, target=3, script={(2, 1): OUTCOME_INTERRUPTED}
            )
            self.assertEqual(executed.status, STATUS_COMPLETED)
            self.assertEqual(executed.attempted_runs, 4)
            self.assertEqual(executed.successful_samples, 3)
            self.assertEqual(executed.interrupted_samples, 1)
            self.assertEqual(committed_sequences(executed), {1, 2, 3})

    def test_failed_attempt_does_not_increment_successful(self):
        with tempfile.TemporaryDirectory() as tmp:
            run, _ = make_run_and_plan(tmp, target=1)
            executed, _, _ = run_to_completion(
                tmp, run, target=1, script={(1, 1): OUTCOME_FAILED}
            )
            self.assertEqual(executed.successful_samples, 1)
            self.assertEqual(executed.failed_samples, 1)
            self.assertEqual(executed.attempted_runs, 2)

    def test_interrupted_attempt_does_not_increment_successful(self):
        with tempfile.TemporaryDirectory() as tmp:
            run, _ = make_run_and_plan(tmp, target=1)
            executed, _, _ = run_to_completion(
                tmp, run, target=1, script={(1, 1): OUTCOME_INTERRUPTED}
            )
            self.assertEqual(executed.successful_samples, 1)
            self.assertEqual(executed.interrupted_samples, 1)
            self.assertEqual(executed.attempted_runs, 2)

    def test_failed_attempt_does_not_commit_sequence(self):
        with tempfile.TemporaryDirectory() as tmp:
            run, _ = make_run_and_plan(tmp, target=3)
            executed, _, _ = run_to_completion(
                tmp, run, target=3, script={(2, 1): OUTCOME_FAILED}
            )
            committed = executed.data["committed_run_ids"]
            failed_exp = experiment_id_for(run.id, 2, 1)
            self.assertNotIn(failed_exp, committed)
            committed_seqs = [parse_experiment_id(e)[1] for e in committed]
            self.assertEqual(Counter(committed_seqs), Counter([1, 2, 3]))

    def test_interrupted_attempt_does_not_commit_sequence(self):
        with tempfile.TemporaryDirectory() as tmp:
            run, _ = make_run_and_plan(tmp, target=3)
            executed, _, _ = run_to_completion(
                tmp, run, target=3, script={(2, 1): OUTCOME_INTERRUPTED}
            )
            committed = executed.data["committed_run_ids"]
            interrupted_exp = experiment_id_for(run.id, 2, 1)
            self.assertNotIn(interrupted_exp, committed)

    def test_successful_never_exceeds_target(self):
        for target in (1, 3, 6):
            with tempfile.TemporaryDirectory() as tmp:
                run, _ = make_run_and_plan(tmp, target=target)
                executed, _, _ = run_to_completion(tmp, run, target=target)
                self.assertLessEqual(executed.successful_samples, target)
                self.assertEqual(executed.successful_samples, target)


class TestRetrySemantics(unittest.TestCase):
    def test_retry_keeps_same_sequence(self):
        with tempfile.TemporaryDirectory() as tmp:
            run, _ = make_run_and_plan(tmp, target=3)
            executed, runner, _ = run_to_completion(
                tmp, run, target=3, script={(2, 1): OUTCOME_FAILED}
            )
            sequences = [c[0] for c in runner.calls]
            self.assertEqual(sequences, [1, 2, 2, 3])

    def test_retry_preserves_traffic_profile(self):
        with tempfile.TemporaryDirectory() as tmp:
            run, plan = make_run_and_plan(tmp, target=3)
            executed, runner, _ = run_to_completion(
                tmp, run, target=3, script={(2, 1): OUTCOME_FAILED}
            )
            profiles = {}
            for seq, _attempt, _exp, profile, _posture, _cid in runner.calls:
                profiles.setdefault(seq, set()).add(profile)
            for seq, profile_set in profiles.items():
                self.assertEqual(
                    profile_set,
                    {plan["samples"][seq - 1]["traffic_profile"]},
                    msg=f"seq {seq} changed traffic profile across retries",
                )

    def test_retry_preserves_security_posture(self):
        with tempfile.TemporaryDirectory() as tmp:
            run, plan = make_run_and_plan(tmp, target=3)
            executed, runner, _ = run_to_completion(
                tmp, run, target=3, script={(2, 1): OUTCOME_FAILED}
            )
            postures = {}
            for seq, _attempt, _exp, _profile, posture, _cid in runner.calls:
                postures.setdefault(seq, set()).add(posture)
            for seq, posture_set in postures.items():
                self.assertEqual(
                    posture_set,
                    {plan["samples"][seq - 1]["security_posture"]},
                    msg=f"seq {seq} changed posture across retries",
                )

    def test_run_does_not_substitute_different_posture(self):
        with tempfile.TemporaryDirectory() as tmp:
            run, plan = make_run_and_plan(tmp, target=3)
            executed, runner, _ = run_to_completion(
                tmp, run, target=3,
                script={(2, 1): OUTCOME_FAILED, (2, 2): OUTCOME_FAILED},
            )
            for seq, committed_exp in enumerate(
                executed.data["committed_run_ids"], start=1
            ):
                pass
            committed_by_seq = {
                parse_experiment_id(e)[1]: e
                for e in executed.data["committed_run_ids"]
            }
            for seq, exp_id in committed_by_seq.items():
                meta_dir = run.directory / "experiments" / exp_id
                metadata = json.loads(
                    (meta_dir / "metadata.json").read_text(encoding="utf-8")
                )
                self.assertEqual(
                    metadata["security_posture"],
                    plan["samples"][seq - 1]["security_posture"],
                )

    def test_sequences_committed_at_most_once(self):
        with tempfile.TemporaryDirectory() as tmp:
            run, _ = make_run_and_plan(tmp, target=6)
            executed, runner, _ = run_to_completion(
                tmp, run, target=6,
                script={(3, 1): OUTCOME_FAILED, (3, 2): OUTCOME_FAILED,
                        (4, 1): OUTCOME_INTERRUPTED,
                        (5, 1): OUTCOME_FAILED, (5, 2): OUTCOME_FAILED},
            )
            committed = executed.data["committed_run_ids"]
            self.assertEqual(len(committed), len(set(committed)))
            committed_seqs = [parse_experiment_id(e)[1] for e in committed]
            self.assertEqual(Counter(committed_seqs), Counter(range(1, 7)))
            self.assertEqual(len(committed), executed.successful_samples)


class TestStatePersistence(unittest.TestCase):
    def test_state_persisted_after_successful_commit(self):
        with tempfile.TemporaryDirectory() as tmp:
            run, _ = make_run_and_plan(tmp, target=3)
            runner = FakeRunner()
            execute_dataset_run(
                tmp, run.id, run_attempt_fn=runner, cleanup_fn=FakeCleanup(),
            )
            reloaded = reload(tmp, run)
            self.assertEqual(reloaded.successful_samples, 3)
            self.assertEqual(len(reloaded.data["committed_run_ids"]), 3)
            self.assertEqual(reloaded.status, STATUS_COMPLETED)
            state = json.loads(
                (run.directory / "state.json").read_text(encoding="utf-8")
            )
            self.assertEqual(state["successful_samples"], 3)
            validate_state(state)

    def test_state_persisted_after_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            run, _ = make_run_and_plan(tmp, target=3)
            runner = FakeRunner(script={(2, 1): OUTCOME_FAILED})
            execute_dataset_run(
                tmp, run.id, run_attempt_fn=runner, cleanup_fn=FakeCleanup(),
            )
            reloaded = reload(tmp, run)
            self.assertEqual(reloaded.failed_samples, 1)
            self.assertEqual(reloaded.successful_samples, 3)
            failed_exp = experiment_id_for(run.id, 2, 1)
            failure_dir = run.directory / "failures" / failed_exp
            self.assertTrue((failure_dir / "failure.json").is_file())

    def test_state_persisted_after_interruption(self):
        with tempfile.TemporaryDirectory() as tmp:
            run, _ = make_run_and_plan(tmp, target=3)
            runner = FakeRunner(script={(2, 1): OUTCOME_INTERRUPTED})
            execute_dataset_run(
                tmp, run.id, run_attempt_fn=runner, cleanup_fn=FakeCleanup(),
            )
            reloaded = reload(tmp, run)
            self.assertEqual(reloaded.interrupted_samples, 1)
            self.assertEqual(reloaded.successful_samples, 3)

    def test_state_tracks_current_sequence(self):
        with tempfile.TemporaryDirectory() as tmp:
            run, _ = make_run_and_plan(tmp, target=3)
            runner = FakeRunner(script={(2, 1): OUTCOME_FAILED})
            execute_dataset_run(
                tmp, run.id, run_attempt_fn=runner, cleanup_fn=FakeCleanup(),
            )
            reloaded = reload(tmp, run)
            self.assertEqual(reloaded.data["current_sequence"], 3)
            self.assertIn(
                reloaded.data["current_security_posture"],
                ("STRONG", "GOOD", "MEDIUM", "WEAK", "WORST"),
            )
            self.assertEqual(reloaded.data["current_traffic_profile"], "messaging")
            last_exp = reloaded.data["current_experiment"]
            self.assertEqual(parse_experiment_id(last_exp)[1], 3)


class TestResumeAndDuplicateProtection(unittest.TestCase):
    def test_resume_after_termination(self):
        with tempfile.TemporaryDirectory() as tmp:
            run, _ = make_run_and_plan(tmp, target=3)
            first_runner = FakeRunner(script={(3, 1): "KeyboardInterrupt"})
            first_cleanup = FakeCleanup()
            paused = execute_dataset_run(
                tmp, run.id, run_attempt_fn=first_runner,
                cleanup_fn=first_cleanup,
            )
            self.assertEqual(paused.status, STATUS_PAUSED)
            self.assertEqual(paused.successful_samples, 2)
            self.assertEqual(paused.interrupted_samples, 1)
            self.assertEqual(committed_sequences(paused), {1, 2})

            resumed = reload(tmp, run)
            self.assertEqual(resumed.status, STATUS_PAUSED)
            self.assertEqual(resumed.data["current_sequence"], 3)

            second_runner = FakeRunner()  # seq 3 attempt 2 -> SUCCESS
            second_cleanup = FakeCleanup()
            completed = execute_dataset_run(
                tmp, run.id, run_attempt_fn=second_runner,
                cleanup_fn=second_cleanup,
            )
            self.assertEqual(completed.status, STATUS_COMPLETED)
            self.assertEqual(completed.successful_samples, 3)
            self.assertEqual(completed.interrupted_samples, 1)
            self.assertEqual(completed.attempted_runs, 4)
            self.assertEqual(committed_sequences(completed), {1, 2, 3})

            self.assertEqual([c[0] for c in first_runner.calls], [1, 2, 3])
            self.assertEqual([c[0] for c in second_runner.calls], [3])
            resumed_exp = experiment_id_for(run.id, 3, 2)
            self.assertIn(resumed_exp, completed.data["committed_run_ids"])

    def test_committed_sequences_not_repeated_on_resume(self):
        with tempfile.TemporaryDirectory() as tmp:
            run, _ = make_run_and_plan(tmp, target=3)
            first_runner = FakeRunner()
            first_cleanup = FakeCleanup()
            completed = execute_dataset_run(
                tmp, run.id, run_attempt_fn=first_runner,
                cleanup_fn=first_cleanup,
            )
            self.assertEqual(completed.status, STATUS_COMPLETED)

            before = first_runner.calls[:]
            second_runner = FakeRunner()
            second_cleanup = FakeCleanup()
            again = execute_dataset_run(
                tmp, run.id, run_attempt_fn=second_runner,
                cleanup_fn=second_cleanup,
            )
            self.assertEqual(again.status, STATUS_COMPLETED)
            self.assertEqual(second_runner.calls, [])
            self.assertEqual(second_cleanup.calls, [])
            self.assertEqual(len(committed_sequences(completed)), 3)

    def test_unclean_crash_does_not_fabricate_success(self):
        with tempfile.TemporaryDirectory() as tmp:
            run, _ = make_run_and_plan(tmp, target=3)
            first_runner = FakeRunner(script={(3, 1): "KeyboardInterrupt"})
            execute_dataset_run(
                tmp, run.id, run_attempt_fn=first_runner,
                cleanup_fn=FakeCleanup(),
            )
            reloaded = reload(tmp, run)
            self.assertEqual(reloaded.successful_samples, 2)
            self.assertEqual(committed_sequences(reloaded), {1, 2})


class TestCleanupAndIsolation(unittest.TestCase):
    def test_cleanup_runs_after_every_attempt(self):
        with tempfile.TemporaryDirectory() as tmp:
            run, _ = make_run_and_plan(tmp, target=3)
            runner = FakeRunner(
                script={(2, 1): OUTCOME_FAILED, (3, 1): OUTCOME_INTERRUPTED}
            )
            cleanup = FakeCleanup()
            executed = execute_dataset_run(
                tmp, run.id, run_attempt_fn=runner, cleanup_fn=cleanup,
            )
            self.assertEqual(executed.status, STATUS_COMPLETED)
            self.assertEqual(len(cleanup.calls), len(runner.calls))
            self.assertEqual(len(cleanup.calls), executed.attempted_runs)
            for (exp_id, seq) in cleanup.calls:
                self.assertEqual(parse_experiment_id(exp_id)[1], seq)

    def test_failed_attempt_isolated_from_successful_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            run, _ = make_run_and_plan(tmp, target=1)
            runner = FakeRunner(script={(1, 1): OUTCOME_FAILED})
            cleanup = FakeCleanup()
            executed = execute_dataset_run(
                tmp, run.id, run_attempt_fn=runner, cleanup_fn=cleanup,
            )
            self.assertEqual(executed.status, STATUS_COMPLETED)
            failed_exp = experiment_id_for(run.id, 1, 1)
            success_exp = experiment_id_for(run.id, 1, 2)
            self.assertTrue(
                (run.directory / "failures" / failed_exp / "failure.json").is_file()
            )
            self.assertFalse(
                (run.directory / "experiments" / failed_exp).exists()
            )
            success_dir = run.directory / "experiments" / success_exp
            self.assertTrue((success_dir / "metadata.json").is_file())
            self.assertTrue((success_dir / "features.json").is_file())
            self.assertTrue((success_dir / "capture.pcap").is_file())

    def test_partial_data_preserved_under_failures(self):
        with tempfile.TemporaryDirectory() as tmp:
            run, _ = make_run_and_plan(tmp, target=1)
            runner = FakeRunner(script={(1, 1): OUTCOME_FAILED})
            cleanup = FakeCleanup()
            executed = execute_dataset_run(
                tmp, run.id, run_attempt_fn=runner, cleanup_fn=cleanup,
            )
            failed_exp = experiment_id_for(run.id, 1, 1)
            partial = (
                run.directory / "failures" / failed_exp / "partial" / "partial.log"
            )
            self.assertTrue(partial.is_file())
            self.assertEqual(
                partial.read_text(encoding="utf-8"), "partial failed capture"
            )

    def test_no_leftover_staging_tmp_after_completion(self):
        with tempfile.TemporaryDirectory() as tmp:
            run, _ = make_run_and_plan(tmp, target=3)
            runner = FakeRunner(script={(2, 1): OUTCOME_FAILED})
            execute_dataset_run(
                tmp, run.id, run_attempt_fn=runner, cleanup_fn=FakeCleanup(),
            )
            staging_tmp = run.directory / "staging" / "tmp"
            if staging_tmp.exists():
                self.assertEqual(list(staging_tmp.iterdir()), [])


class TestSequentialOrdering(unittest.TestCase):
    def test_attempts_strictly_sequential(self):
        with tempfile.TemporaryDirectory() as tmp:
            run, _ = make_run_and_plan(tmp, target=6)
            runner = FakeRunner(
                script={(3, 1): OUTCOME_FAILED, (4, 1): OUTCOME_FAILED,
                        (4, 2): OUTCOME_FAILED, (5, 1): OUTCOME_INTERRUPTED}
            )
            cleanup = FakeCleanup()
            executed = execute_dataset_run(
                tmp, run.id, run_attempt_fn=runner, cleanup_fn=cleanup,
            )
            sequences = [c[0] for c in runner.calls]
            self.assertEqual(sequences, [1, 2, 3, 3, 4, 4, 4, 5, 5, 6])
            self.assertEqual(len(runner.calls), executed.attempted_runs)
            self.assertEqual(executed.status, STATUS_COMPLETED)
            self.assertEqual(executed.successful_samples, 6)


class TestTrafficQuotas(unittest.TestCase):
    def test_balanced_quotas_survive_failures(self):
        with tempfile.TemporaryDirectory() as tmp:
            run, plan = make_run_and_plan(tmp, target=6)
            runner = FakeRunner(
                script={(3, 1): OUTCOME_FAILED, (3, 2): OUTCOME_FAILED,
                        (4, 1): OUTCOME_INTERRUPTED,
                        (5, 1): OUTCOME_FAILED, (5, 2): OUTCOME_FAILED},
            )
            cleanup = FakeCleanup()
            executed = execute_dataset_run(
                tmp, run.id, run_attempt_fn=runner, cleanup_fn=cleanup,
            )
            self.assertEqual(executed.status, STATUS_COMPLETED)
            self.assertEqual(executed.attempted_runs, 11)
            self.assertEqual(executed.successful_samples, 6)
            self.assertEqual(executed.failed_samples, 4)
            self.assertEqual(executed.interrupted_samples, 1)

            committed = committed_sequences(executed)
            profiles = [
                plan["samples"][seq - 1]["traffic_profile"]
                for seq in sorted(committed)
            ]
            self.assertEqual(Counter(profiles), traffic_quota(6))
            for profile, count in traffic_quota(6).items():
                self.assertEqual(Counter(profiles)[profile], count)

    def test_failed_profile_still_reaches_quota(self):
        with tempfile.TemporaryDirectory() as tmp:
            run, plan = make_run_and_plan(tmp, target=6)
            runner = FakeRunner(script={(3, 1): OUTCOME_FAILED})
            cleanup = FakeCleanup()
            executed = execute_dataset_run(
                tmp, run.id, run_attempt_fn=runner, cleanup_fn=cleanup,
            )
            profiles = [
                plan["samples"][seq - 1]["traffic_profile"]
                for seq in sorted(committed_sequences(executed))
            ]
            self.assertEqual(Counter(profiles), traffic_quota(6))


class TestFailurePolicy(unittest.TestCase):
    def test_cannot_complete_below_target(self):
        with tempfile.TemporaryDirectory() as tmp:
            run, _ = make_run_and_plan(tmp, target=3)
            runner = FakeRunner(default=OUTCOME_FAILED)
            cleanup = FakeCleanup()
            executed = execute_dataset_run(
                tmp, run.id, run_attempt_fn=runner, cleanup_fn=cleanup,
                max_attempts_per_sequence=2,
            )
            self.assertEqual(executed.status, STATUS_FAILED)
            self.assertNotEqual(executed.status, STATUS_COMPLETED)
            self.assertLess(executed.successful_samples, 3)
            self.assertEqual(executed.failed_samples, 2)
            self.assertEqual(executed.attempted_runs, 2)
            self.assertIn("sequence 1", executed.data["error"])
            self.assertEqual(committed_sequences(executed), set())

    def test_exhausted_run_cannot_resume(self):
        with tempfile.TemporaryDirectory() as tmp:
            run, _ = make_run_and_plan(tmp, target=3)
            runner = FakeRunner(default=OUTCOME_FAILED)
            execute_dataset_run(
                tmp, run.id, run_attempt_fn=runner, cleanup_fn=FakeCleanup(),
                max_attempts_per_sequence=1,
            )
            with self.assertRaises(ValueError):
                execute_dataset_run(
                    tmp, run.id, run_attempt_fn=FakeRunner(),
                    cleanup_fn=FakeCleanup(),
                )

    def test_invalid_attempt_outcome_detected(self):
        with tempfile.TemporaryDirectory() as tmp:
            run, _ = make_run_and_plan(tmp, target=1)

            def bad_runner(experiment_id, sample, tmp_dir, results_root,
                           run_id=None, log=None, reuse=None):
                return {"status": "WEIRD", "experiment_id": experiment_id}

            with self.assertRaises(ValueError):
                execute_dataset_run(
                    tmp, run.id, run_attempt_fn=bad_runner,
                    cleanup_fn=FakeCleanup(),
                )

    def test_max_attempts_validation(self):
        with tempfile.TemporaryDirectory() as tmp:
            run, _ = make_run_and_plan(tmp, target=1)
            for bad in (0, -1, True, "3"):
                with self.subTest(value=bad):
                    with self.assertRaises(ValueError):
                        execute_dataset_run(
                            tmp, run.id, run_attempt_fn=FakeRunner(),
                            cleanup_fn=FakeCleanup(),
                            max_attempts_per_sequence=bad,
                        )


class TestExecutorReuse(unittest.TestCase):
    def test_default_runner_uses_campaign_pipeline(self):
        with tempfile.TemporaryDirectory() as tmp:
            run, plan = make_run_and_plan(tmp, target=1)
            sample = plan["samples"][0]
            exp_id = experiment_id_for(run.id, 1, 1)
            exp_tmp = Path(tmp) / "attempt-tmp"
            config_with_traffic = dict(sample["ipsec_configuration"])
            config_with_traffic["traffic"] = {
                "profile": sample["traffic_profile"],
                "duration": 30.0,
                "port": 20000,
                "capture_filter": "esp",
            }

            with patch("controller.campaign.execute_trial_pipeline") as mock_pipeline:
                mock_pipeline.return_value = {
                    "status": "PASS",
                    "experiment_id": exp_id,
                    "metadata": {"experiment_id": exp_id},
                    "features": {"packet_count": 1},
                    "traffic_log": "STATS\n",
                    "pcap_path": "/nonexistent/never-read.pcap",
                    "ipsec": {"ike_sa": "ESTABLISHED"},
                    "connectivity": {"status": "PASS"},
                    "runtime_ctx": {},
                    "capture_wan_ip": "192.168.100.1",
                }
                outcome = run_attempt(
                    exp_id, sample, exp_tmp, tmp, run_id=run.id, log=None,
                )
                self.assertEqual(outcome["status"], OUTCOME_SUCCESS)
                mock_pipeline.assert_called_once()
                called_cfg = mock_pipeline.call_args.args[1]
                self.assertEqual(
                    called_cfg["traffic"]["profile"], sample["traffic_profile"]
                )
                self.assertEqual(
                    called_cfg["esp"], sample["ipsec_configuration"]["esp"]
                )

    def test_default_runner_maps_fatal_topology_error(self):
        """A sudo/containerlab deploy failure must surface as a fatal FAILED
        outcome (never a retryable failure), so the engine fails the run fast
        instead of staying RUNNING or burning the attempt budget."""
        from controller.executor import FatalTopologyError
        with tempfile.TemporaryDirectory() as tmp:
            run, plan = make_run_and_plan(tmp, target=1)
            sample = plan["samples"][0]
            exp_id = experiment_id_for(run.id, 1, 1)
            exp_tmp = Path(tmp) / "attempt-tmp"

            with patch("controller.campaign.execute_trial_pipeline",
                       side_effect=FatalTopologyError(
                           "Command failed with exit code 1: "
                           "sudo: a password is required"
                       )):
                outcome = run_attempt(
                    exp_id, sample, exp_tmp, tmp, run_id=run.id, log=None,
                )
            self.assertEqual(outcome["status"], OUTCOME_FAILED)
            self.assertTrue(outcome.get("fatal"))
            self.assertEqual(outcome["reason"], "FatalTopologyError")
            self.assertIn("sudo: a password is required", outcome["error"])

    def test_default_cleanup_reuses_campaign_cleanup(self):
        with tempfile.TemporaryDirectory() as tmp:
            sample = {"ipsec_configuration": {"mode": "tunnel"}}
            with patch("controller.campaign.cleanup_experiment") as mock_clean:
                cleanup_attempt(experiment_id_for("ds-1", 1, 1), sample, None)
                mock_clean.assert_called_once()

    def test_execute_dataset_run_creates_one_manager_and_forwards_it(self):
        with tempfile.TemporaryDirectory() as tmp:
            run, _ = make_run_and_plan(tmp, target=3)
            runner = FakeRunner()
            execute_dataset_run(
                tmp, run.id, run_attempt_fn=runner, cleanup_fn=FakeCleanup(),
            )
            self.assertEqual(len(runner.reuse_seen), 3)
            self.assertTrue(all(m is not None for m in runner.reuse_seen))
            self.assertEqual(len({id(m) for m in runner.reuse_seen}), 1)

    def test_run_attempt_forwards_reuse_manager_to_pipeline(self):
        with tempfile.TemporaryDirectory() as tmp:
            run, plan = make_run_and_plan(tmp, target=1)
            sample = plan["samples"][0]
            exp_id = experiment_id_for(run.id, 1, 1)
            exp_tmp = Path(tmp) / "attempt-tmp"
            manager = object()
            config_with_traffic = dict(sample["ipsec_configuration"])
            config_with_traffic["traffic"] = {
                "profile": sample["traffic_profile"],
                "duration": 30.0,
                "port": 20000,
                "capture_filter": "esp",
            }

            with patch("controller.campaign.execute_trial_pipeline") as mock_pipeline:
                mock_pipeline.return_value = {
                    "status": "PASS",
                    "experiment_id": exp_id,
                    "metadata": {"experiment_id": exp_id},
                    "features": {"packet_count": 1},
                    "traffic_log": "STATS\n",
                    "pcap_path": "/nonexistent/never-read.pcap",
                    "ipsec": {"ike_sa": "ESTABLISHED"},
                    "connectivity": {"status": "PASS"},
                    "runtime_ctx": {},
                    "capture_wan_ip": "192.168.100.1",
                }
                run_attempt(
                    exp_id, sample, exp_tmp, tmp, run_id=run.id, log=None,
                    reuse=manager,
                )
                mock_pipeline.assert_called_once()
                self.assertIs(mock_pipeline.call_args.kwargs["reuse"], manager)

    def test_run_attempt_without_reuse_remains_backward_compatible(self):
        with tempfile.TemporaryDirectory() as tmp:
            run, plan = make_run_and_plan(tmp, target=1)
            sample = plan["samples"][0]
            exp_id = experiment_id_for(run.id, 1, 1)
            exp_tmp = Path(tmp) / "attempt-tmp"
            config_with_traffic = dict(sample["ipsec_configuration"])
            config_with_traffic["traffic"] = {
                "profile": sample["traffic_profile"],
                "duration": 30.0,
                "port": 20000,
                "capture_filter": "esp",
            }

            with patch("controller.campaign.execute_trial_pipeline") as mock_pipeline:
                mock_pipeline.return_value = {
                    "status": "PASS",
                    "experiment_id": exp_id,
                    "metadata": {"experiment_id": exp_id},
                    "features": {"packet_count": 1},
                    "traffic_log": "STATS\n",
                    "pcap_path": "/nonexistent/never-read.pcap",
                    "ipsec": {"ike_sa": "ESTABLISHED"},
                    "connectivity": {"status": "PASS"},
                    "runtime_ctx": {},
                    "capture_wan_ip": "192.168.100.1",
                }
                run_attempt(
                    exp_id, sample, exp_tmp, tmp, run_id=run.id, log=None,
                )
                mock_pipeline.assert_called_once()
                self.assertIsNone(mock_pipeline.call_args.kwargs["reuse"])


class TestPlanValidation(unittest.TestCase):
    def test_missing_plan_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            run = create_dataset_run(tmp, target_samples=3)
            with self.assertRaises(FileNotFoundError):
                load_plan(tmp, run.id)

    def test_plan_target_mismatch_detected(self):
        with tempfile.TemporaryDirectory() as tmp:
            run = create_dataset_run(tmp, target_samples=3)
            plan = build_sample_plan(6)
            write_sample_plan(tmp, run.id, plan)
            with self.assertRaises(ValueError):
                execute_dataset_run(
                    tmp, run.id, run_attempt_fn=FakeRunner(),
                    cleanup_fn=FakeCleanup(),
                )

    def test_malformed_plan_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            plan = build_sample_plan(3)
            plan["samples"][0].pop("sequence")
            with self.assertRaises(ValueError):
                validate_plan(plan)

    def test_duplicate_sequences_rejected(self):
        plan = build_sample_plan(3)
        plan["samples"][1]["sequence"] = 1
        with self.assertRaises(ValueError):
            validate_plan(plan)


class TopologyTrackingCleanup:
    """Records every cleanup request including its skip_destroy flag."""

    def __init__(self):
        self.calls = []

    def __call__(self, experiment_id, sample, tmp_dir, runtime_ctx=None,
                 skip_destroy=False):
        self.calls.append((experiment_id, skip_destroy))
        if tmp_dir is not None:
            import shutil
            shutil.rmtree(Path(tmp_dir), ignore_errors=True)


class TestTopologyLifecycle(unittest.TestCase):
    """Module-10: the dataset lifecycle keeps an already-deployed topology
    alive between same-mode samples and destroys it exactly once at the end.

    Verifies (1) every per-attempt cleanup inside a dataset run preserves the
    topology (skip_destroy=True), (2) the run's terminal COMPLETED / FAILED
    state destroys the topology exactly once, (3) a PAUSED run preserves it
    for resume, and (4) the deploy path clears both topologies on a fresh
    reset."""

    def test_dataset_cleanup_never_destroys_between_samples(self):
        with tempfile.TemporaryDirectory() as tmp:
            run, _ = make_run_and_plan(tmp, target=2)
            cleanup = TopologyTrackingCleanup()
            with patch("controller.campaign.destroy") as mock_destroy:
                executed = execute_dataset_run(
                    tmp, run.id, run_attempt_fn=FakeRunner(),
                    cleanup_fn=cleanup,
                )
                # cleanup is called after every commit but must keep the
                # topology alive for the next sample
                self.assertEqual(len(cleanup.calls), 2)
                self.assertTrue(all(
                    skip for _, skip in cleanup.calls
                ), "per-sample cleanup must preserve the topology")
                # per-sample cleanup NEVER destroys the topology
                self.assertEqual(mock_destroy.call_count, 0)
            self.assertEqual(committed_sequences(executed), {1, 2})

    def test_teardown_destroys_deployed_topology_exactly_once(self):
        from controller import reuse as reuse_mod
        from controller.dataset_executor import _teardown_run_topology
        manager = reuse_mod.TopologyReuseManager(log=lambda m: None)
        manager._prev_identity = "tunnel"
        with patch("controller.campaign.destroy") as mock_destroy:
            _teardown_run_topology(manager, log=lambda m: None)
            self.assertEqual(mock_destroy.call_count, 1)
            self.assertEqual(mock_destroy.call_args.args[0], "tunnel")

    def test_teardown_is_a_noop_without_a_deployed_identity(self):
        from controller import reuse as reuse_mod
        from controller.dataset_executor import _teardown_run_topology
        fresh = reuse_mod.TopologyReuseManager(log=lambda m: None)
        with patch("controller.campaign.destroy") as mock_destroy:
            _teardown_run_topology(fresh, log=lambda m: None)
            self.assertEqual(mock_destroy.call_count, 0)
            _teardown_run_topology(None, log=lambda m: None)
            self.assertEqual(mock_destroy.call_count, 0)

    def test_paused_run_preserves_topology_for_resume(self):
        with tempfile.TemporaryDirectory() as tmp:
            run, _ = make_run_and_plan(tmp, target=2)
            with patch("controller.campaign.destroy") as mock_destroy:
                paused = execute_dataset_run(
                    tmp, run.id,
                    run_attempt_fn=FakeRunner(script={(2, 1): "KeyboardInterrupt"}),
                    cleanup_fn=FakeCleanup(),
                )
                self.assertEqual(paused.status, STATUS_PAUSED)
                self.assertEqual(mock_destroy.call_count, 0)

    def test_cleanup_experiment_skip_destroy(self):
        with patch("controller.campaign.destroy") as mock_destroy:
            campaign_mod.cleanup_experiment(
                {"source_container": None, "destination_container": None},
                "tunnel", None, skip_destroy=True,
            )
            self.assertEqual(mock_destroy.call_count, 0)
            campaign_mod.cleanup_experiment(
                {"source_container": None, "destination_container": None},
                "tunnel", None, skip_destroy=False,
            )
            self.assertEqual(mock_destroy.call_count, 1)

    def test_reset_and_deploy_clears_both_topologies(self):
        # ``wait_for_ipsec_ready`` polls REAL containers, so mocking only
        # destroy/deploy made this test's result depend on whether the tunnel
        # lab happened to be running on the host. Stubbing it keeps the test
        # hermetic while still asserting the readiness gate was awaited.
        with patch("controller.executor.destroy") as mock_destroy, \
                patch("controller.executor.deploy") as mock_deploy, \
                patch(
                    "controller.executor.wait_for_ipsec_ready",
                    return_value=True,
                ) as mock_ready:
            reset_and_deploy("tunnel")
            # Every lab is torn down before the new one is deployed: the two
            # non-NAT topologies, plus the NAT deployment, which is a
            # separate lab whose nodes would otherwise keep answering ARP
            # for the addresses the new deployment is about to claim.
            self.assertEqual(mock_destroy.call_count, 3)
            self.assertEqual(
                [c.args for c in mock_destroy.call_args_list],
                [("tunnel",), ("transport",), ("transport",)],
            )
            self.assertIn("tunnel", mock_destroy.call_args_list[0].args)
            self.assertIn("transport", mock_destroy.call_args_list[1].args)
            self.assertIn("transport", mock_destroy.call_args_list[2].args)
            # The NAT lab teardown must remain explicitly NAT-scoped.
            self.assertTrue(mock_destroy.call_args_list[2].kwargs["nat"])
            self.assertFalse(mock_destroy.call_args_list[0].kwargs.get("nat", False))
            self.assertEqual(mock_deploy.call_args.args[0], "tunnel")
            mock_ready.assert_called_once_with("tunnel", nat=False)


class TestTrafficCaptureParameterization(unittest.TestCase):
    """Traffic/capture inputs are parameterized (RunOptions + per-sample
    overrides) while the legacy defaults stay byte-identical."""

    def _pipeline_artifacts(self):
        return {
            "status": "PASS",
            "experiment_id": "any",
            "metadata": {"experiment_id": "any"},
            "features": {"packet_count": 1},
            "traffic_log": "STATS\n",
            "pcap_path": "/nonexistent/never-read.pcap",
            "ipsec": {"ike_sa": "ESTABLISHED"},
            "connectivity": {"status": "PASS"},
            "runtime_ctx": {},
            "capture_wan_ip": "192.168.100.1",
        }

    def test_run_attempt_honors_sample_traffic_overrides(self):
        from controller.dataset_executor import RunOptions
        with tempfile.TemporaryDirectory() as tmp:
            run, plan = make_run_and_plan(tmp, target=1)
            sample = plan["samples"][0]
            sample["traffic"] = {
                "duration": 60,
                "port": 44444,
                "capture_filter": "udp port 500 or esp",
            }
            exp_id = experiment_id_for(run.id, 1, 1)
            exp_tmp = Path(tmp) / "attempt-tmp"
            with patch("controller.campaign.execute_trial_pipeline") as mock_pipeline:
                mock_pipeline.return_value = self._pipeline_artifacts()
                outcome = run_attempt(
                    exp_id, sample, exp_tmp, tmp, run_id=run.id, log=None,
                )
                self.assertEqual(outcome["status"], OUTCOME_SUCCESS)
                called_cfg = mock_pipeline.call_args.args[1]
                self.assertEqual(called_cfg["traffic"]["profile"], sample["traffic_profile"])
                self.assertEqual(called_cfg["traffic"]["duration"], 60)
                self.assertEqual(called_cfg["traffic"]["port"], 44444)
                self.assertEqual(called_cfg["traffic"]["capture_filter"], "udp port 500 or esp")

    def test_run_attempt_defaults_without_overrides(self):
        from controller.capture import DEFAULT_CAPTURE_FILTER

        with tempfile.TemporaryDirectory() as tmp:
            run, plan = make_run_and_plan(tmp, target=1)
            sample = plan["samples"][0]
            exp_id = experiment_id_for(run.id, 1, 1)
            exp_tmp = Path(tmp) / "attempt-tmp"
            with patch("controller.campaign.execute_trial_pipeline") as mock_pipeline:
                mock_pipeline.return_value = self._pipeline_artifacts()
                run_attempt(
                    exp_id, sample, exp_tmp, tmp, run_id=run.id, log=None,
                )
                called_cfg = mock_pipeline.call_args.args[1]
                self.assertEqual(called_cfg["traffic"], {
                    "profile": sample["traffic_profile"],
                    "duration": 30.0,
                    "port": 20000,
                    "capture_filter": DEFAULT_CAPTURE_FILTER,
                })

    def test_execute_dataset_run_forwards_run_options(self):
        from controller.dataset_executor import RunOptions
        seen = []

        def capturing_run_attempt(experiment_id, sample, tmp_dir, results_root,
                                  run_id=None, log=None, reuse=None):
            seen.append(dict(sample.get("traffic") or {}))
            pcap = Path(tmp_dir) / "capture.pcap"
            tmp_dir = Path(tmp_dir)
            tmp_dir.mkdir(parents=True, exist_ok=True)
            pcap.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 48)
            return {
                "status": OUTCOME_SUCCESS,
                "experiment_id": experiment_id,
                "metadata": {
                    "experiment_id": experiment_id,
                    "sequence": sample["sequence"],
                    "security_posture": sample["security_posture"],
                    "traffic_profile": sample["traffic_profile"],
                    "status": "PASS",
                },
                "features": {"packet_count": 1},
                "traffic_log": "STATS\n",
                "pcap_path": str(pcap),
                "connectivity": {"status": "PASS"},
                "ipsec": {"ike_sa": "ESTABLISHED", "child_sa": "INSTALLED"},
            }

        with tempfile.TemporaryDirectory() as tmp:
            run, _ = make_run_and_plan(tmp, target=2)
            opts = RunOptions(duration=45, port=40000, capture_filter="esp or ah")
            completed = execute_dataset_run(
                tmp, run.id,
                run_attempt_fn=capturing_run_attempt,
                cleanup_fn=FakeCleanup(),
                run_options=opts,
            )
            self.assertEqual(completed.status, STATUS_COMPLETED)
            self.assertEqual(len(seen), 2)
            for traffic in seen:
                self.assertEqual(traffic["duration"], 45.0)
                self.assertEqual(traffic["port"], 40000)
                self.assertEqual(traffic["capture_filter"], "esp or ah")


if __name__ == "__main__":
    unittest.main(verbosity=2)