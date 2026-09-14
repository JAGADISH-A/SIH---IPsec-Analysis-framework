"""Module 6 API tests for the Dataset Run endpoints.

Covers the 33 required behaviours:

* user-controlled sample count flows unchanged API -> DatasetRun -> planner
* target validation (integer, >0, no booleans/floats/strings, safety ceiling)
* success-based progress (never attempt-based)
* resume semantics (paused / completed / running / fingerprint)
* single-active-run and manual-experiment conflict protection
* delegation to Modules 1-5 (no re-implementation in the API)
* results endpoint (distributions, counts, never the full Parquet)

All execution is dependency-injected with a scripted fake runner; no real
Containerlab/StrongSwan is touched.  A scratch ``results`` directory is used
per test and removed afterwards.
"""

import json
import tempfile
import threading
import time
import unittest
from collections import Counter
from pathlib import Path
from unittest import mock

from fastapi import FastAPI
from fastapi.testclient import TestClient

from controller.dataset_api import create_dataset_router
from controller.dataset_artifacts import reference_feature_record
from controller.dataset_executor import parse_experiment_id
from controller.testbed_lock import EXPERIMENT, TestbedLock

OUTCOME_SUCCESS = "SUCCESS"
OUTCOME_FAILED = "FAILED"
OUTCOME_INTERRUPTED = "INTERRUPTED"
OUTCOME_PAUSE = "KeyboardInterrupt"


# ---------------------------------------------------------------------------
# Shared fixtures and helpers
# ---------------------------------------------------------------------------

def synthetic_features(packet_count=100):
    feats = reference_feature_record()
    feats["packet_count"] = packet_count
    feats["total_bytes"] = packet_count * 120
    return feats


class ScriptedRunner:
    """Scripted attempt runner (by (sequence, attempt) outcome table)."""

    PCAP_BYTES = b"\xd4\xc3\xb2\xa1" + b"\x00" * 48

    def __init__(self, results=None, default=OUTCOME_SUCCESS, gate=None):
        self.results = results or {}
        self.default = default
        self.gate = gate
        self.calls = []

    def __call__(self, experiment_id, sample, tmp_dir, results_root,
                 run_id=None, log=None, reuse=None):
        seq, attempt = sample["sequence"], parse_experiment_id(experiment_id)[2]
        self.calls.append((seq, attempt))
        if self.gate is not None:
            self.gate(seq, attempt)
        status = self.results.get((seq, attempt), self.default)
        tmp = Path(tmp_dir)
        tmp.mkdir(parents=True, exist_ok=True)
        if status == OUTCOME_PAUSE:
            raise KeyboardInterrupt()
        if status == OUTCOME_FAILED:
            return {"status": OUTCOME_FAILED, "experiment_id": experiment_id,
                    "reason": "Synthetic", "error": "synthetic failure"}
        if status == OUTCOME_INTERRUPTED:
            return {"status": OUTCOME_INTERRUPTED,
                    "experiment_id": experiment_id,
                    "reason": "Synthetic", "error": "synthetic interrupt"}
        pcap = tmp / "capture.pcap"
        pcap.write_bytes(self.PCAP_BYTES)
        return {
            "status": OUTCOME_SUCCESS,
            "experiment_id": experiment_id,
            "metadata": {"experiment_id": experiment_id, "status": "PASS"},
            "features": synthetic_features(packet_count=100 + seq),
            "traffic_log": "STATS OK\n",
            "pcap_path": str(pcap),
        }


class FakeCleanup:
    def __init__(self):
        self.calls = []

    def __call__(self, experiment_id, sample, tmp_dir, runtime_ctx=None,
                         skip_destroy=False):
        self.calls.append((experiment_id, sample["sequence"]))
        if tmp_dir is not None:
            import shutil
            shutil.rmtree(Path(tmp_dir), ignore_errors=True)


class HoldGate:
    """Blocks the runner at (sequence, attempt); release with ``event.set()``."""

    def __init__(self, hold):
        self.hold = hold
        self.event = threading.Event()

    def __call__(self, seq, attempt):
        if (seq, attempt) == self.hold:
            self.event.wait(timeout=60)


def make_app(tmp, *, runner=None, cleaner=None, lock=None, max_samples=1000,
             background=True):
    app = FastAPI()
    app.include_router(
        create_dataset_router(
            results_root=str(tmp),
            max_target_samples=max_samples,
            run_attempt_fn=runner or ScriptedRunner(),
            cleanup_fn=cleaner or FakeCleanup(),
            lock=lock or TestbedLock(),
            background=background,
        )
    )
    return app


def client_for(tmp, **kwargs):
    return TestClient(make_app(tmp, **kwargs))


def wait_status(client, run_id, status, timeout=300.0):
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        resp = client.get(f"/dataset-runs/{run_id}")
        if resp.status_code != 200:
            raise AssertionError(f"GET status failed: {resp.status_code} {resp.text}")
        last = resp.json()
        if last["status"] == status:
            return last
        time.sleep(0.02)
    raise AssertionError(
        f"run {run_id} never reached {status!r}; last was {last}"
    )


def wait_finalized(client, run_id, timeout=300.0):
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        resp = client.get(f"/dataset-runs/{run_id}")
        data = resp.json()
        fin = data.get("finalization") or {}
        if fin.get("status") == "COMPLETED":
            return data
        last = data
        time.sleep(0.02)
    raise AssertionError(
        f"run {run_id} never finalized; last was {last}"
    )


def post_target(client, target, expected_status=201):
    return client.post(
        "/dataset-runs", json={"target_samples": target}
    )


# ---------------------------------------------------------------------------
# Acceptance + input validation
# ---------------------------------------------------------------------------

class TestAcceptance(unittest.TestCase):
    def test_post_target_2_accepted(self):
        with tempfile.TemporaryDirectory() as tmp:
            client = client_for(tmp)
            resp = post_target(client, 2)
            self.assertEqual(resp.status_code, 201)
            data = resp.json()
            self.assertEqual(data["target_samples"], 2)
            self.assertTrue(data["dataset_run_id"].startswith("dataset-"))
            # wait for the background worker so temp dir teardown never races it
            wait_finalized(client, data["dataset_run_id"])

    def test_post_target_50_accepted(self):
        with tempfile.TemporaryDirectory() as tmp:
            client = client_for(tmp)
            resp = post_target(client, 50)
            self.assertEqual(resp.status_code, 201)
            self.assertEqual(resp.json()["target_samples"], 50)

    def test_post_target_500_accepted_if_below_maximum(self):
        with tempfile.TemporaryDirectory() as tmp:
            client = client_for(tmp, max_samples=1000)
            resp = post_target(client, 500)
            self.assertEqual(resp.status_code, 201)
            wait_finalized(client, resp.json()["dataset_run_id"])
            self.assertEqual(resp.json()["target_samples"], 500)

    def test_post_target_0_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            client = client_for(tmp)
            self.assertEqual(post_target(client, 0).status_code, 422)

    def test_post_negative_target_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            client = client_for(tmp)
            self.assertEqual(post_target(client, -1).status_code, 422)

    def test_post_boolean_target_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            client = client_for(tmp)
            self.assertEqual(post_target(client, True).status_code, 422)

    def test_post_non_integer_target_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            client = client_for(tmp)
            self.assertEqual(
                post_target(client, 1.5).status_code, 422
            )
            self.assertEqual(
                post_target(client, "500").status_code, 422
            )
            self.assertEqual(
                post_target(client, None).status_code, 422
            )

    def test_post_target_above_maximum_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            client = client_for(tmp, max_samples=1000)
            resp = post_target(client, 2000)
            self.assertEqual(resp.status_code, 422)
            self.assertIn("exceeds", resp.json()["detail"].lower())

    def test_maximum_boundary_is_accepted(self):
        with tempfile.TemporaryDirectory() as tmp:
            client = client_for(tmp, max_samples=1000)
            resp = post_target(client, 1000)
            self.assertEqual(resp.status_code, 201)
            # wait for the background worker so temp dir teardown never races it
            wait_finalized(client, resp.json()["dataset_run_id"], timeout=300)

    def test_settings_exposes_the_maximum(self):
        with tempfile.TemporaryDirectory() as tmp:
            client = client_for(tmp, max_samples=77)
            resp = client.get("/dataset-runs/settings")
            self.assertEqual(resp.status_code, 200)
            self.assertEqual(resp.json()["maximum_target_samples"], 77)


# ---------------------------------------------------------------------------
# Exact target flow API -> DatasetRun -> planner -> execution
# ---------------------------------------------------------------------------

class TestExactTargetFlow(unittest.TestCase):
    def test_requested_target_is_preserved_exactly(self):
        with tempfile.TemporaryDirectory() as tmp:
            client = client_for(tmp)
            run_id = post_target(client, 137).json()["dataset_run_id"]
            state = wait_finalized(client, run_id)
            self.assertEqual(state["target_samples"], 137)
            self.assertEqual(state["successful_samples"], 137)
            self.assertEqual(state["committed_samples"], 137)

    def test_dataset_run_target_samples_equals_request(self):
        with tempfile.TemporaryDirectory() as tmp:
            client = client_for(tmp)
            run_id = post_target(client, 137).json()["dataset_run_id"]
            state = wait_finalized(client, run_id)
            disk = json.loads(
                (Path(tmp) / "datasets" / run_id / "state.json").read_text()
            )
            self.assertEqual(state["target_samples"], 137)
            self.assertEqual(disk["target_samples"], 137)

    def test_planner_receives_exact_requested_target(self):
        from controller import dataset_planner as planner_mod
        real = planner_mod.build_sample_plan
        seen = []
        with tempfile.TemporaryDirectory() as tmp:
            client = client_for(tmp)
            with mock.patch(
                "controller.dataset_planner.build_sample_plan",
                side_effect=lambda n: (seen.append(n), real(n))[1],
            ):
                client = client_for(tmp)
                run_id = post_target(client, 137).json()["dataset_run_id"]
                wait_finalized(client, run_id)
            self.assertEqual(seen, [137])

    def test_plan_length_equals_requested_target(self):
        with tempfile.TemporaryDirectory() as tmp:
            gate = HoldGate((1, 1))
            client = client_for(tmp, runner=ScriptedRunner(gate=gate))
            run_id = post_target(client, 137).json()["dataset_run_id"]
            plan = json.loads(
                (Path(tmp) / "datasets" / run_id / "staging" / "plan.json"
                 ).read_text()
            )
            self.assertEqual(plan["target_samples"], 137)
            self.assertEqual(len(plan["samples"]), 137)
            gate.event.set()
            wait_finalized(client, run_id)

    def test_target500_flow_unchanged(self):
        with tempfile.TemporaryDirectory() as tmp:
            gate = HoldGate((1, 1))
            client = client_for(tmp, max_samples=1000,
                               runner=ScriptedRunner(gate=gate))
            resp = post_target(client, 500)
            self.assertEqual(resp.status_code, 201)
            run_id = resp.json()["dataset_run_id"]
            status = client.get(f"/dataset-runs/{run_id}").json()
            self.assertEqual(status["target_samples"], 500)
            plan = json.loads(
                (Path(tmp) / "datasets" / run_id / "staging" / "plan.json"
                 ).read_text()
            )
            self.assertEqual(plan["target_samples"], 500)
            self.assertEqual(len(plan["samples"]), 500)
            self.assertEqual(plan["traffic_quota"]["voip"], 84)
            gate.event.set()
            wait_finalized(client, run_id)

    def test_exact_two_successful_samples(self):
        # attempt 1 -> SUCCESS (seq 1)
        # attempt 2 -> FAILED (seq 2 attempt 1)
        # attempt 3 -> SUCCESS (seq 2 attempt 2)
        with tempfile.TemporaryDirectory() as tmp:
            results = {(2, 1): OUTCOME_FAILED}
            client = client_for(tmp, runner=ScriptedRunner(results=results))
            run_id = post_target(client, 2).json()["dataset_run_id"]
            state = wait_finalized(client, run_id)

            self.assertEqual(state["status"], "COMPLETED")
            self.assertEqual(state["target_samples"], 2)
            self.assertEqual(state["successful_samples"], 2)
            self.assertEqual(state["attempted_runs"], 3)
            self.assertEqual(state["failed_samples"], 1)
            self.assertEqual(state["interrupted_samples"], 0)
            self.assertEqual(state["committed_samples"], 2)
            self.assertEqual(
                state["progress_percentage"], 100.0
            )

            results = client.get(
                f"/dataset-runs/{run_id}/results"
            ).json()
            self.assertEqual(results["feature_row_count"], 2)
            self.assertEqual(results["metadata_record_count"], 2)
            self.assertEqual(results["finalization"]["status"], "COMPLETED")


# ---------------------------------------------------------------------------
# Progress (success-based)
# ---------------------------------------------------------------------------

class TestProgress(unittest.TestCase):
    def _progress_after_committing_n(self, tmp, target, n, results, hold):
        gate = HoldGate(hold)
        runner = ScriptedRunner(results=results, gate=gate)
        client = client_for(tmp, runner=runner)
        run_id = post_target(client, target).json()["dataset_run_id"]
        state = wait_status(client, run_id, "RUNNING")
        while state["successful_samples"] < n:
            state = client.get(f"/dataset-runs/{run_id}").json()
            time.sleep(0.01)
        return client, run_id, state, gate

    def test_progress_is_success_based_not_attempt_based(self):
        # target=500: no committed successes, 1 attempt started; still RUNNING.
        with tempfile.TemporaryDirectory() as tmp:
            client, run_id, state, gate = self._progress_after_committing_n(
                tmp, 500, 0, {}, (1, 1)
            )
            state = client.get(f"/dataset-runs/{run_id}").json()
            self.assertEqual(state["target_samples"], 500)
            self.assertEqual(state["successful_samples"], 0)
            self.assertEqual(state["current_sequence"], 1)
            self.assertEqual(state["progress_percentage"], 0.0)
            gate.event.set()
            wait_finalized(client, run_id)

    def test_progress_125_of_500_is_25_percent(self):
        with tempfile.TemporaryDirectory() as tmp:
            client, run_id, state, gate = self._progress_after_committing_n(
                tmp, 500, 124, {}, (125, 1)
            )
            state = client.get(f"/dataset-runs/{run_id}").json()
            self.assertEqual(state["successful_samples"], 124)
            self.assertAlmostEqual(state["progress_percentage"], 24.8, places=1)
            gate.event.set()
            wait_finalized(client, run_id)

    def test_progress_25_percent_at_125_of_500(self):
        with tempfile.TemporaryDirectory() as tmp:
            client, run_id, state, gate = self._progress_after_committing_n(
                tmp, 500, 125, {}, (126, 1)
            )
            state = client.get(f"/dataset-runs/{run_id}").json()
            self.assertEqual(state["successful_samples"], 125)
            self.assertEqual(state["progress_percentage"], 25.0)
            gate.event.set()
            wait_finalized(client, run_id)

    def test_failed_attempts_do_not_increase_progress(self):
        # seq1 success; seq2 attempt1 fails; seq2 attempt2 blocked.
        with tempfile.TemporaryDirectory() as tmp:
            client, run_id, state, gate = self._progress_after_committing_n(
                tmp, 2, 1, {(2, 1): OUTCOME_FAILED}, (2, 2)
            )
            state = client.get(f"/dataset-runs/{run_id}").json()
            self.assertEqual(state["successful_samples"], 1)
            self.assertEqual(state["failed_samples"], 1)
            self.assertEqual(state["attempted_runs"], 2)
            self.assertEqual(state["progress_percentage"], 50.0)
            gate.event.set()
            wait_finalized(client, run_id)

    def test_interrupted_attempts_do_not_increase_progress(self):
        # seq1 success; seq2 attempt1 interrupted; seq2 attempt2 blocked.
        with tempfile.TemporaryDirectory() as tmp:
            client, run_id, state, gate = self._progress_after_committing_n(
                tmp, 2, 1, {(2, 1): OUTCOME_INTERRUPTED}, (2, 2)
            )
            state = client.get(f"/dataset-runs/{run_id}").json()
            self.assertEqual(state["successful_samples"], 1)
            self.assertEqual(state["interrupted_samples"], 1)
            self.assertEqual(state["attempted_runs"], 2)
            self.assertEqual(state["progress_percentage"], 50.0)
            gate.event.set()
            wait_finalized(client, run_id)


# ---------------------------------------------------------------------------
# Status / 404 / persisted state
# ---------------------------------------------------------------------------

class TestStatus(unittest.TestCase):
    def test_unknown_dataset_run_404(self):
        with tempfile.TemporaryDirectory() as tmp:
            client = client_for(tmp)
            for path in (
                "/dataset-runs/dataset-does-not-exist",
                "/dataset-runs/../evil",
            ):
                resp = client.get(path)
                self.assertIn(resp.status_code, (404, 422))

    def test_get_existing_dataset_run_returns_persisted_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            client = client_for(tmp)
            run_id = post_target(client, 4).json()["dataset_run_id"]
            state = wait_finalized(client, run_id)
            payload = client.get(f"/dataset-runs/{run_id}").json()
            self.assertEqual(payload["dataset_run_id"], run_id)
            self.assertEqual(payload["status"], "COMPLETED")
            self.assertEqual(payload["target_samples"], 4)
            self.assertEqual(payload["successful_samples"], 4)
            self.assertEqual(payload["failed_samples"], 0)
            self.assertEqual(payload["interrupted_samples"], 0)


# ---------------------------------------------------------------------------
# Resume semantics
# ---------------------------------------------------------------------------

class TestResume(unittest.TestCase):
    def test_resume_paused_run(self):
        with tempfile.TemporaryDirectory() as tmp:
            results = {(1, 1): OUTCOME_PAUSE}
            client = client_for(tmp, runner=ScriptedRunner(results=results))
            run_id = post_target(client, 1).json()["dataset_run_id"]
            wait_status(client, run_id, "PAUSED")
            resp = client.post(f"/dataset-runs/{run_id}/resume")
            self.assertEqual(resp.status_code, 200)
            state = wait_finalized(client, run_id)
            self.assertEqual(state["status"], "COMPLETED")
            self.assertEqual(state["successful_samples"], 1)

    def test_resume_complete_run_does_not_duplicate_execution(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = ScriptedRunner()
            client = client_for(tmp, runner=runner)
            run_id = post_target(client, 2).json()["dataset_run_id"]
            wait_finalized(client, run_id)
            calls_before = list(runner.calls)
            resp = client.post(f"/dataset-runs/{run_id}/resume")
            self.assertEqual(resp.status_code, 200)
            self.assertEqual(resp.json()["status"], "COMPLETED")
            self.assertEqual(runner.calls, calls_before)
            state = client.get(f"/dataset-runs/{run_id}").json()
            self.assertEqual(state["successful_samples"], 2)

    def test_resume_running_run_does_not_start_second_worker(self):
        with tempfile.TemporaryDirectory() as tmp:
            gate = HoldGate((1, 1))
            runner = ScriptedRunner(gate=gate)
            client = client_for(tmp, runner=runner)
            run_id = post_target(client, 3).json()["dataset_run_id"]
            wait_status(client, run_id, "RUNNING")
            calls = len(runner.calls)
            resp = client.post(f"/dataset-runs/{run_id}/resume")
            self.assertEqual(resp.status_code, 409)
            self.assertIn("already running", resp.json()["detail"].lower())
            self.assertEqual(len(runner.calls), calls)
            gate.event.set()
            wait_finalized(client, run_id)

    def test_resume_validates_plan_fingerprint(self):
        from controller.dataset_planner import write_sample_plan
        with tempfile.TemporaryDirectory() as tmp:
            results = {(1, 1): OUTCOME_PAUSE}
            client = client_for(tmp, runner=ScriptedRunner(results=results))
            run_id = post_target(client, 1).json()["dataset_run_id"]
            wait_status(client, run_id, "PAUSED")
            original = json.loads(
                (Path(tmp) / "datasets" / run_id / "staging" / "plan.json"
                 ).read_text()
            )
            tampered = json.loads(json.dumps(original))
            tampered["samples"][0]["traffic_profile"] = (
                "video" if tampered["samples"][0]["traffic_profile"] != "video"
                else "web"
            )
            write_sample_plan(tmp, run_id, tampered)
            resp = client.post(f"/dataset-runs/{run_id}/resume")
            self.assertEqual(resp.status_code, 400)
            self.assertIn("plan.json", resp.json()["detail"])

    def test_resume_failed_run_is_rejected(self):
        # every attempt fails -> budget exhausted -> status FAILED
        with tempfile.TemporaryDirectory() as tmp:
            client = client_for(
                tmp, runner=ScriptedRunner(default=OUTCOME_FAILED)
            )
            run_id = post_target(client, 1).json()["dataset_run_id"]
            wait_status(client, run_id, "FAILED")
            resp = client.post(f"/dataset-runs/{run_id}/resume")
            self.assertEqual(resp.status_code, 409)
            self.assertIn("FAILED", resp.json()["detail"])


# ---------------------------------------------------------------------------
# Concurrent request / single-active-run protection
# ---------------------------------------------------------------------------

class TestConcurrency(unittest.TestCase):
    def test_duplicate_start_requests_are_prevented(self):
        with tempfile.TemporaryDirectory() as tmp:
            gate = HoldGate((1, 1))
            client = client_for(tmp, runner=ScriptedRunner(gate=gate))
            first = post_target(client, 500)
            self.assertEqual(first.status_code, 201)
            second = post_target(client, 500)
            self.assertEqual(second.status_code, 409)
            # exactly one dataset run directory was created
            runs = list((Path(tmp) / "datasets").iterdir())
            self.assertEqual(len(runs), 1)
            gate.event.set()
            wait_finalized(client, first.json()["dataset_run_id"])

    def test_dataset_run_conflicts_with_another_active_dataset_run(self):
        with tempfile.TemporaryDirectory() as tmp:
            gate1 = HoldGate((1, 1))
            client = client_for(tmp, runner=ScriptedRunner(gate=gate1))
            first = post_target(client, 2)
            self.assertEqual(first.status_code, 201)
            second = post_target(client, 3)
            self.assertEqual(second.status_code, 409)
            gate1.event.set()
            wait_finalized(client, first.json()["dataset_run_id"])
            # after completion the testbed is free again
            third = post_target(client, 3)
            self.assertEqual(third.status_code, 201)
            wait_finalized(client, third.json()["dataset_run_id"])

    def test_dataset_blocked_while_manual_experiment_active(self):
        with tempfile.TemporaryDirectory() as tmp:
            lock = TestbedLock()
            reserved, _ = lock.try_reserve(EXPERIMENT, "job-manual")
            self.assertTrue(reserved)
            client = client_for(tmp, lock=lock)
            resp = post_target(client, 2)
            self.assertEqual(resp.status_code, 409)
            self.assertIn("experiment", resp.json()["detail"])

    def test_manual_experiment_blocked_while_dataset_active(self):
        import controller.api as api
        with mock.patch.object(
            api.TESTBED_LOCK,
            "_owner",
            ("dataset", "dataset-fake"),
        ):
            with TestClient(api.app) as client:
                config = {
                    "mode": "tunnel",
                    "address_family": "ipv4",
                    "ike": {
                        "version": 2,
                        "encryption": "aes256",
                        "integrity": "sha256",
                        "dh_group": "modp2048",
                    },
                    "esp": {
                        "encryption": "aes256gcm16",
                        "integrity": None,
                        "dh_group": "modp2048",
                        "pfs": True,
                    },
                    "traffic": {"profile": "voip", "duration": 1},
                }
                resp = client.post("/experiments", json=config)
                self.assertEqual(resp.status_code, 409)
                self.assertIn("testbed", resp.json()["detail"].lower())
                self.assertNotIn("job_id", resp.json())


# ---------------------------------------------------------------------------
# Delegation to Modules 1-5 (no duplicate logic in the API)
# ---------------------------------------------------------------------------

class TestDelegation(unittest.TestCase):
    def test_api_does_not_reimplement_planner_logic(self):
        from controller import dataset_planner as planner_mod
        real = planner_mod.build_sample_plan
        seen = []
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch(
                "controller.dataset_planner.build_sample_plan",
                side_effect=lambda n: (seen.append(n), real(n))[1],
            ):
                client = client_for(tmp)
                run_id = post_target(client, 6).json()["dataset_run_id"]
                wait_finalized(client, run_id)
            # the API asked the planner once, with the exact target
            self.assertEqual(seen, [6])
            results = client.get(
                f"/dataset-runs/{run_id}/results"
            ).json()
            self.assertEqual(
                results["traffic_distribution"],
                planner_mod.traffic_quota(6),
            )

    def test_api_delegates_execution_to_the_executor(self):
        from controller import dataset_executor as executor_mod
        real = executor_mod.execute_dataset_run
        calls = []
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch(
                "controller.dataset_executor.execute_dataset_run",
                side_effect=lambda *a, **kw: (
                    calls.append((a, kw)),
                    real(*a, **kw),
                )[1],
            ):
                client = client_for(tmp)
                run_id = post_target(client, 2).json()["dataset_run_id"]
                wait_finalized(client, run_id)
            self.assertEqual(len(calls), 1)
            args, kwargs = calls[0]
            self.assertIn("collector_fn", kwargs)
            self.assertIsNotNone(kwargs["collector_fn"])

    def test_api_delegates_artifacts_to_dataset_artifacts(self):
        from controller import dataset_artifacts as artifacts_mod
        real = artifacts_mod.finalize_dataset
        seen = []
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch(
                "controller.dataset_artifacts.finalize_dataset",
                side_effect=lambda *a, **kw: (
                    seen.append(a),
                    real(*a, **kw),
                )[1],
            ):
                client = client_for(tmp)
                run_id = post_target(client, 2).json()["dataset_run_id"]
                wait_finalized(client, run_id)
            self.assertEqual(len(seen), 1)
            self.assertEqual(seen[0][1], run_id)


# ---------------------------------------------------------------------------
# Results endpoint
# ---------------------------------------------------------------------------

class TestResults(unittest.TestCase):
    def _completed(self, target=6):
        tmp = tempfile.TemporaryDirectory()
        client = client_for(tmp.name)
        run_id = post_target(client, target).json()["dataset_run_id"]
        wait_finalized(client, run_id)
        return tmp, client, run_id

    def test_results_exposes_traffic_distribution(self):
        tmp, client, run_id = self._completed(6)
        try:
            results = client.get(f"/dataset-runs/{run_id}/results").json()
            self.assertEqual(
                results["traffic_distribution"],
                {p: 1 for p in ("voip", "video", "messaging", "email", "web", "icmp")},
            )
        finally:
            tmp.cleanup()

    def test_results_exposes_posture_distribution(self):
        tmp, client, run_id = self._completed(6)
        try:
            plan = json.loads(
                (Path(tmp.name) / "datasets" / run_id / "staging" / "plan.json"
                 ).read_text()
            )
            expected = Counter(
                s["security_posture"] for s in plan["samples"]
            )
            results = client.get(f"/dataset-runs/{run_id}/results").json()
            self.assertEqual(
                results["security_posture_distribution"], dict(expected)
            )
        finally:
            tmp.cleanup()

    def test_results_does_not_read_the_full_parquet(self):
        with tempfile.TemporaryDirectory() as tmp:
            client = client_for(tmp)
            run_id = post_target(client, 3).json()["dataset_run_id"]
            wait_finalized(client, run_id)
            with mock.patch(
                "pyarrow.parquet.read_table",
                side_effect=AssertionError("results must not load the table"),
            ):
                resp = client.get(f"/dataset-runs/{run_id}/results")
            self.assertEqual(resp.status_code, 200)
            data = resp.json()
            self.assertEqual(data["feature_row_count"], 3)
            self.assertEqual(data["metadata_record_count"], 3)
            self.assertIn("features_parquet", data["artifact_paths"])

    def test_completion_not_reported_below_target(self):
        # one success out of target=2 => RUNNING, never COMPLETED
        gate = HoldGate((2, 1))
        with tempfile.TemporaryDirectory() as tmp:
            client = client_for(tmp, runner=ScriptedRunner(gate=gate))
            run_id = post_target(client, 2).json()["dataset_run_id"]
            wait_status(client, run_id, "RUNNING")
            # wait until the first sample is actually committed (the gate then
            # guarantees the run stays RUNNING at exactly 1 success)
            state = client.get(f"/dataset-runs/{run_id}").json()
            deadline = time.time() + 120
            while state["successful_samples"] < 1 and time.time() < deadline:
                time.sleep(0.02)
                state = client.get(f"/dataset-runs/{run_id}").json()
            self.assertEqual(state["successful_samples"], 1)
            self.assertNotEqual(state["status"], "COMPLETED")
            payload = client.get(f"/dataset-runs/{run_id}/results").json()
            self.assertNotEqual(payload["status"], "COMPLETED")
            self.assertEqual(payload["traffic_distribution"]["voip"], 1)
            gate.event.set()
            final = wait_finalized(client, run_id)
            self.assertEqual(
                final["successful_samples"], final["target_samples"]
            )


# ---------------------------------------------------------------------------
# Dataset download / export
# ---------------------------------------------------------------------------

DOWNLOAD_ARTIFACTS = (
    "features.parquet",
    "metadata.jsonl",
    "manifest.json",
    "README.txt",
)


class TestDatasetDownload(unittest.TestCase):
    def _completed(self, target=4):
        tmp = tempfile.TemporaryDirectory()
        client = client_for(tmp.name)
        run_id = post_target(client, target).json()["dataset_run_id"]
        wait_finalized(client, run_id)
        return tmp, client, run_id

    def _zip(self, client, run_id):
        import io
        import zipfile
        resp = client.get(f"/dataset-runs/{run_id}/download")
        self.assertEqual(resp.status_code, 200)
        return resp, zipfile.ZipFile(io.BytesIO(resp.content))

    def test_completed_run_downloads_a_zip_archive(self):
        tmp, client, run_id = self._completed(4)
        try:
            resp = client.get(f"/dataset-runs/{run_id}/download")
            self.assertEqual(resp.status_code, 200)
            self.assertEqual(
                resp.headers["content-type"].split(";")[0].strip(),
                "application/zip",
            )
            disposition = resp.headers["content-disposition"]
            self.assertIn("attachment", disposition)
            self.assertIn(f"{run_id}.zip", disposition)
            self.assertGreater(len(resp.content), 0)
        finally:
            tmp.cleanup()

    def test_zip_contains_exactly_the_required_final_artifacts(self):
        tmp, client, run_id = self._completed(4)
        try:
            resp, zf = self._zip(client, run_id)
            try:
                self.assertEqual(
                    sorted(zf.namelist()), sorted(DOWNLOAD_ARTIFACTS)
                )
                # Evidence/provenance directories are not part of the final
                # downloadable artifact and must never leak into the archive.
                for name in zf.namelist():
                    self.assertNotIn("/", name)
                    self.assertNotIn("captures", name)
                    self.assertNotIn("experiments", name)
                    self.assertNotIn("failures", name)
            finally:
                zf.close()
        finally:
            tmp.cleanup()

    def test_zip_contents_match_source_and_sources_unchanged(self):
        tmp, client, run_id = self._completed(3)
        directory = Path(tmp.name) / "datasets" / run_id
        try:
            before = {
                name: (directory / name).read_bytes() for name in DOWNLOAD_ARTIFACTS
            }
            resp, zf = self._zip(client, run_id)
            try:
                for name, payload in before.items():
                    self.assertEqual(zf.read(name), payload)
            finally:
                zf.close()
            after = {
                name: (directory / name).read_bytes() for name in DOWNLOAD_ARTIFACTS
            }
            self.assertEqual(after, before)
        finally:
            tmp.cleanup()

    def test_downloaded_parquet_rows_match_successful_sample_count(self):
        target = 5
        tmp, client, run_id = self._completed(target)
        try:
            import io
            import pyarrow.parquet as pq
            resp, zf = self._zip(client, run_id)
            try:
                table = pq.read_table(io.BytesIO(zf.read("features.parquet")))
                self.assertEqual(table.num_rows, target)
            finally:
                zf.close()
        finally:
            tmp.cleanup()

    def test_unknown_dataset_run_is_404(self):
        with tempfile.TemporaryDirectory() as tmp:
            client = client_for(tmp)
            resp = client.get("/dataset-runs/does-not-exist/download")
            self.assertEqual(resp.status_code, 404)

    def test_path_traversal_run_id_is_404(self):
        with tempfile.TemporaryDirectory() as tmp:
            client = client_for(tmp)
            resp = client.get(
                "/dataset-runs/..%2F..%2Fcontroller%2Fapi%2Fdownload"
            )
            self.assertEqual(resp.status_code, 404)

    def test_running_dataset_is_rejected(self):
        gate = HoldGate((1, 1))
        with tempfile.TemporaryDirectory() as tmp:
            client = client_for(tmp, runner=ScriptedRunner(gate=gate))
            run_id = post_target(client, 3).json()["dataset_run_id"]
            wait_status(client, run_id, "RUNNING")
            resp = client.get(f"/dataset-runs/{run_id}/download")
            self.assertEqual(resp.status_code, 409)
            self.assertIn("not a completed dataset", resp.json()["detail"])
            gate.event.set()
            wait_finalized(client, run_id)

    def test_paused_dataset_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            client = client_for(
                tmp, runner=ScriptedRunner(results={(1, 1): OUTCOME_PAUSE})
            )
            run_id = post_target(client, 1).json()["dataset_run_id"]
            wait_status(client, run_id, "PAUSED")
            resp = client.get(f"/dataset-runs/{run_id}/download")
            self.assertEqual(resp.status_code, 409)
            self.assertIn("not a completed dataset", resp.json()["detail"])

    def test_failed_dataset_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            client = client_for(
                tmp, runner=ScriptedRunner(default=OUTCOME_FAILED)
            )
            run_id = post_target(client, 1).json()["dataset_run_id"]
            wait_status(client, run_id, "FAILED")
            resp = client.get(f"/dataset-runs/{run_id}/download")
            self.assertEqual(resp.status_code, 409)
            self.assertIn("not a completed dataset", resp.json()["detail"])

    def test_completed_but_not_finalized_is_rejected(self):
        # Status flips to COMPLETED before finalization.json is written;
        # without finalization the artifacts are not safe to download.  Hold
        # the finalizer on a gate so the window is deterministic.
        from controller import dataset_artifacts as artifacts_mod
        real_finalize = artifacts_mod.finalize_dataset
        proceed = threading.Event()

        def blocked_finalize(results_root, dataset_run_id, log=None,
                             write_artifacts=True):
            proceed.wait(timeout=60)
            return real_finalize(
                results_root, dataset_run_id,
                log=log, write_artifacts=write_artifacts,
            )

        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.object(
                artifacts_mod, "finalize_dataset", side_effect=blocked_finalize
            ):
                client = client_for(tmp)
                run_id = post_target(client, 1).json()["dataset_run_id"]
                wait_status(client, run_id, "COMPLETED")
                resp = client.get(f"/dataset-runs/{run_id}/download")
                self.assertEqual(resp.status_code, 409)
                self.assertIn("not finalized", resp.json()["detail"])
                proceed.set()
                wait_finalized(client, run_id)
            # With finalization done the same run is downloadable.
            final = client.get(f"/dataset-runs/{run_id}/download")
            self.assertEqual(final.status_code, 200)

    def test_missing_artifact_is_422(self):
        tmp, client, run_id = self._completed(2)
        try:
            (Path(tmp.name) / "datasets" / run_id / "features.parquet").unlink()
            resp = client.get(f"/dataset-runs/{run_id}/download")
            self.assertEqual(resp.status_code, 422)
            self.assertIn("missing", resp.json()["detail"])
        finally:
            tmp.cleanup()

    def test_corrupt_artifact_is_422(self):
        tmp, client, run_id = self._completed(2)
        try:
            parquet = Path(tmp.name) / "datasets" / run_id / "features.parquet"
            parquet.unlink()
            parquet.mkdir()  # no longer a regular file -> unreadable artifact
            resp = client.get(f"/dataset-runs/{run_id}/download")
            self.assertEqual(resp.status_code, 422)
        finally:
            tmp.cleanup()


if __name__ == "__main__":
    unittest.main()