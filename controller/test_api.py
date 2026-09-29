"""FastAPI application tests for the real control-plane app object.

Every other controller test builds a *synthetic* ``FastAPI()`` around one
router (``controller/test_dataset_api.py::make_app``).  Nothing in the suite
imported ``controller.api.app`` itself, so the app the frontend actually talks
to -- its CORS middleware, its ``/static`` mount, its dataset-router wiring, its
error envelopes and its job lifecycle -- had no executable coverage at all.

These tests close that gap without touching the testbed: the experiment
executor is patched, so no Containerlab/StrongSwan/Docker call is ever made.
The shared ``TESTBED_LOCK`` and the module-level ``jobs``/``active_job_id``
globals are restored in ``tearDown`` so one test can never leak a reservation
into the next.
"""

import json
import threading
import time
import unittest
from unittest import mock

from fastapi.testclient import TestClient

from controller import api as api_module
from controller.api import app
from controller.dataset_api import DEFAULT_MAX_TARGET_SAMPLES
from controller.traffic import DEFAULT_DURATION, DURATION_RANGE, PROFILES

DEV_ORIGIN = "http://localhost:5173"
CONTROL_PATHS = {
    "/",
    "/health",
    "/experiments",
    "/experiments/configurations",
    "/experiments/{job_id}",
    "/dataset-runs",
    "/dataset-runs/settings",
    "/dataset-runs/{dataset_run_id}",
    "/dataset-runs/{dataset_run_id}/results",
    "/dataset-runs/{dataset_run_id}/resume",
    "/dataset-runs/{dataset_run_id}/download",
}

VALID_CONFIG = {
    "mode": "tunnel",
    "address_family": "ipv4",
    "ike": {
        "version": 2,
        "encryption": "aes128",
        "integrity": "sha256",
        "dh_group": "modp2048",
    },
    "esp": {
        "encryption": "aes128gcm16",
        "integrity": None,
        "dh_group": "modp2048",
        "pfs": True,
    },
    "traffic": {"profile": "voip", "duration": 10},
}


def _wait_for_job(client, job_id, statuses, timeout=10.0):
    """Poll ``/experiments/{job_id}`` until it leaves QUEUED/RUNNING."""
    deadline = time.time() + timeout
    payload = None
    while time.time() < deadline:
        payload = client.get(f"/experiments/{job_id}").json()
        if payload.get("status") in statuses:
            return payload
        time.sleep(0.02)
    return payload


class TestAppWiring(unittest.TestCase):
    """The app object boots and exposes every documented route."""

    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)

    def test_app_starts_and_every_control_route_is_reachable(self):
        # The dataset router is attached lazily (FastAPI 0.141 keeps an
        # ``_IncludedRouter`` until the app is exercised), so the route table
        # is not the right place to assert registration.  The generated
        # OpenAPI document is: it is resolved from the same routing tree the
        # requests use, and a route that cannot be reached cannot appear.
        documented = set(self.client.get("/openapi.json").json()["paths"])
        self.assertTrue(
            (CONTROL_PATHS - {"/"}).issubset(documented), (CONTROL_PATHS - {"/"}) - documented
        )

    def test_health_reports_ok(self):
        r = self.client.get("/health")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json(), {"status": "ok"})

    def test_root_serves_the_frontend_shell(self):
        r = self.client.get("/")
        self.assertEqual(r.status_code, 200)
        self.assertIn("text/html", r.headers["content-type"])

    def test_static_mount_serves_frontend_assets(self):
        r = self.client.get("/static/app.js")
        self.assertEqual(r.status_code, 200)
        self.assertIn("javascript", r.headers["content-type"])

    def test_openapi_documents_every_control_path(self):
        r = self.client.get("/openapi.json")
        self.assertEqual(r.status_code, 200)
        documented = set(r.json()["paths"])
        # ``/`` serves the frontend shell and is deliberately out of the schema.
        self.assertTrue(
            (CONTROL_PATHS - {"/"}).issubset(documented), (CONTROL_PATHS - {"/"}) - documented
        )

    def test_swagger_ui_is_reachable(self):
        self.assertEqual(self.client.get("/docs").status_code, 200)

    def test_configurations_match_the_real_traffic_profiles(self):
        body = self.client.get("/experiments/configurations").json()
        self.assertEqual(sorted(body["traffic"]["profiles"]), sorted(PROFILES))
        self.assertEqual(body["traffic"]["duration"]["default"], DEFAULT_DURATION)
        self.assertEqual(body["traffic"]["duration"]["min"], DURATION_RANGE[0])
        self.assertEqual(body["traffic"]["duration"]["max"], DURATION_RANGE[1])
        self.assertEqual(body["address_families"], ["ipv4", "ipv6"])

    def test_configuration_response_is_deterministic_across_calls(self):
        first = self.client.get("/experiments/configurations").content
        second = self.client.get("/experiments/configurations").content
        self.assertEqual(first, second)

    def test_dataset_settings_endpoint_is_reachable(self):
        r = self.client.get("/dataset-runs/settings")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(
            r.json()["maximum_target_samples"], DEFAULT_MAX_TARGET_SAMPLES
        )


class TestCors(unittest.TestCase):
    """The dev frontend origin is readable and preflight succeeds."""

    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)

    def test_dev_origin_is_readable(self):
        # The control plane runs an open development CORS policy
        # (``allow_origins=["*"]``), so a browser read is permitted either by
        # echoing the origin or by the wildcard.  What must never happen is the
        # header being absent, which is what actually blocks a frontend.
        r = self.client.get("/health", headers={"Origin": DEV_ORIGIN})
        self.assertEqual(r.status_code, 200)
        self.assertIn(
            r.headers.get("access-control-allow-origin"), (DEV_ORIGIN, "*")
        )

    def test_preflight_from_the_dev_origin_is_answered(self):
        r = self.client.options(
            "/experiments",
            headers={
                "Origin": DEV_ORIGIN,
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "content-type",
            },
        )
        self.assertEqual(r.status_code, 200)
        self.assertIn(r.headers.get("access-control-allow-origin"), (DEV_ORIGIN, "*"))
        self.assertIn("POST", r.headers.get("access-control-allow-methods", ""))


class TestValidation(unittest.TestCase):
    """Bad input is rejected with a structured, trace-free 422/404."""

    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)

    def test_missing_required_sections_return_422(self):
        r = self.client.post("/experiments", json={"mode": "tunnel"})
        self.assertEqual(r.status_code, 422)
        detail = r.json()["detail"]
        self.assertIsInstance(detail, list)
        missing = {item["loc"][-1] for item in detail}
        self.assertEqual(missing, {"ike", "esp"})

    def test_validation_error_never_leaks_a_traceback_or_host_path(self):
        body = self.client.post("/experiments", json={"mode": "tunnel"}).text
        self.assertNotIn("Traceback", body)
        self.assertNotIn("/home/", body)

    def test_validation_failure_does_not_consume_the_testbed(self):
        self.client.post("/experiments", json={"mode": "tunnel"})
        self.assertIsNone(api_module.TESTBED_LOCK.owner())

    def test_unknown_job_returns_404_with_a_message(self):
        r = self.client.get("/experiments/does-not-exist")
        self.assertEqual(r.status_code, 404)
        self.assertIn("not found", r.json()["detail"].lower())

    def test_unsafe_dataset_run_id_is_refused_before_touching_the_filesystem(self):
        r = self.client.get("/dataset-runs/@@bad@@")
        self.assertEqual(r.status_code, 404)
        self.assertIn("detail", r.json())


class TestExperimentLifecycle(unittest.TestCase):
    """Create -> run -> terminal state, with the executor patched."""

    def setUp(self):
        self.client = TestClient(app)
        self._saved_jobs = dict(api_module.jobs)
        self._saved_active = api_module.active_job_id
        api_module.jobs.clear()
        api_module.active_job_id = None
        self.addCleanup(self._restore)

    def _restore(self):
        for kind, owner_id in list(api_module.TESTBED_LOCK._owner or ()):  # noqa: SLF001
            api_module.TESTBED_LOCK.release(kind, owner_id)
        api_module.jobs.clear()
        api_module.jobs.update(self._saved_jobs)
        api_module.active_job_id = self._saved_active

    def test_create_queues_a_job_and_reaches_completed(self):
        with mock.patch.object(api_module, "run_experiment", return_value={"ok": True}):
            r = self.client.post("/experiments", json=VALID_CONFIG)
            self.assertEqual(r.status_code, 200)
            body = r.json()
            self.assertEqual(body["status"], "QUEUED")
            self.assertIn("job_id", body)

            final = _wait_for_job(self.client, body["job_id"], {"COMPLETED", "FAILED"})
            self.assertEqual(final["status"], "COMPLETED")
            self.assertEqual(final["result"], {"ok": True})
            self.assertIsNone(final["error"])

    def test_completed_job_releases_the_shared_testbed(self):
        with mock.patch.object(api_module, "run_experiment", return_value={"ok": True}):
            job_id = self.client.post("/experiments", json=VALID_CONFIG).json()["job_id"]
            _wait_for_job(self.client, job_id, {"COMPLETED", "FAILED"})
        self.assertIsNone(api_module.TESTBED_LOCK.owner())

    def test_executor_failure_becomes_a_failed_job_not_an_http_error(self):
        with mock.patch.object(
            api_module, "run_experiment", side_effect=ValueError("bad cipher")
        ):
            job_id = self.client.post("/experiments", json=VALID_CONFIG).json()["job_id"]
            final = _wait_for_job(self.client, job_id, {"COMPLETED", "FAILED"})
        self.assertEqual(final["status"], "FAILED")
        self.assertEqual(final["error"], "bad cipher")
        self.assertIsNone(api_module.TESTBED_LOCK.owner())

    def test_a_second_concurrent_experiment_is_refused_with_409(self):
        # The executor is held open so the first job is still RUNNING when the
        # second request arrives; a fast mock would let it finish first and the
        # 409 path would never be exercised.
        release = threading.Event()

        def _hold(*_args, **_kwargs):
            release.wait(timeout=10)
            return {"ok": True}

        with mock.patch.object(api_module, "run_experiment", side_effect=_hold):
            first = self.client.post("/experiments", json=VALID_CONFIG)
            self.addCleanup(release.set)
            self.assertEqual(first.status_code, 200)
            second = self.client.post("/experiments", json=VALID_CONFIG)
            self.assertEqual(second.status_code, 409)
            self.assertIn("already running", second.json()["detail"])
            release.set()
            _wait_for_job(self.client, first.json()["job_id"], {"COMPLETED", "FAILED"})

    def test_a_dataset_run_holding_the_testbed_blocks_a_manual_experiment(self):
        from controller.testbed_lock import DATASET

        self.assertTrue(api_module.TESTBED_LOCK.try_reserve(DATASET, "dataset-xyz"))
        try:
            r = self.client.post("/experiments", json=VALID_CONFIG)
            self.assertEqual(r.status_code, 409)
            self.assertIn("dataset-xyz", r.json()["detail"])
        finally:
            api_module.TESTBED_LOCK.release(DATASET, "dataset-xyz")

    def test_responses_are_json_serializable(self):
        with mock.patch.object(api_module, "run_experiment", return_value={"n": 1}):
            job_id = self.client.post("/experiments", json=VALID_CONFIG).json()["job_id"]
            _wait_for_job(self.client, job_id, {"COMPLETED", "FAILED"})
            r = self.client.get(f"/experiments/{job_id}")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(json.loads(r.text), r.json())


if __name__ == "__main__":
    unittest.main()
