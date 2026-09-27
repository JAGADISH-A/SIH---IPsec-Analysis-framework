"""Browser-consumability contract for the analytics API ("Server A").

These tests cover the integration surface a browser client depends on, and
regress the specific defects found in the frontend/backend audit:

* ``/api/v1/*`` without ``--phase10`` dropped the connection instead of
  answering (the ``handle_combined`` guard was bypassed by ``_api``);
* there was no CORS support at all, and no ``OPTIONS`` handler, so
  ``http.server``'s 501 HTML was the browser's preflight response;
* absolute host paths were reachable in three response fields;
* ``/api/v1/runs/{id}/audit`` echoed ``limit``/``offset`` but ignored them;
* there was no way to enumerate runs, assessments or findings, so the frontend
  could not restore its state after a refresh;
* there was no OpenAPI document to generate or validate a client against.

Handler-level tests (no socket) are separated from transport-level tests (real
socket) on purpose: the former are fast and cover payload contracts, the
latter cover the things that only exist on the wire -- CORS headers, preflight,
405s, and the structured error envelope.
"""

from __future__ import annotations

import json
import os
import re
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

from correlation.api import app as app_module
from correlation.api.config import (
    DEFAULT_ALLOWED_ORIGINS,
    DEFAULT_HOST,
    DEFAULT_PORT,
    ENV_ALLOWED_ORIGINS,
    ENV_HOST,
    ENV_PORT,
    CorsPolicy,
    ServerConfig,
)
from correlation.api.cors import apply_cors_headers, preflight_headers, summarize_cors
from correlation.api.discovery import (
    handle_assessment_findings,
    handle_assessments_v1,
    handle_findings,
    handle_run,
    handle_runs,
)
from correlation.api.openapi import docs_html, openapi_document
from correlation.api.redact import bounded_echo, public_path
from correlation.api.routes import (
    DEFAULT_PAGE_LIMIT,
    MAX_PAGE_LIMIT,
    ApiError,
    handle_get,
    page_params,
    paginate,
    paged_envelope,
)
from correlation.api.store import build_store

SENTINEL = "sentinel-not-a-real-id"
ALLOWED_ORIGIN = "http://localhost:8000"
FOREIGN_ORIGIN = "http://attacker.example"


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

class _LiveServer:
    """A real socket server on an ephemeral port, for wire-level assertions."""

    def __init__(self, phase10=None, cors=None, store=None, static_dir=None):
        self.cors = cors if cors is not None else ServerConfig.resolve().cors
        self.store = store if store is not None else build_store()
        self.httpd = app_module.DashboardServer(
            ("127.0.0.1", 0), self.store, static_dir,
            phase10=phase10, cors=self.cors,
        )
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    def request(self, path, method="GET", headers=None, data=None):
        url = f"http://127.0.0.1:{self.port}{path}"
        req = urllib.request.Request(url, method=method, headers=headers or {}, data=data)
        try:
            with urllib.request.urlopen(req, timeout=10) as response:
                return response.status, dict(response.headers), response.read()
        except urllib.error.HTTPError as error:
            return error.code, dict(error.headers), error.read()

    def json(self, path, **kwargs):
        status, headers, body = self.request(path, **kwargs)
        return status, headers, json.loads(body)

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=5)


class _ServerTestCase(unittest.TestCase):
    """Base class that starts and stops one live server per test."""

    phase10 = False
    cors = None

    def setUp(self):
        context = None
        if self.phase10:
            from correlation.api.live import Phase10Context

            context = Phase10Context()
        self.server = _LiveServer(phase10=context, cors=self.cors)
        self.addCleanup(self.server.close)


# ---------------------------------------------------------------------------
# regression: the routing defect
# ---------------------------------------------------------------------------

class TestPhase10GuardRegression(unittest.TestCase):
    """Regression for the defect that made /api/v1 unusable by default.

    Before the fix, ``_api`` dispatched ``/api/v1`` straight to
    ``_api_v1``, skipping the ``phase10_unavailable`` guard in
    ``handle_combined``; the handler then dereferenced the missing context and
    the client saw ``RemoteDisconnected`` with no HTTP response at all. A
    frontend cannot distinguish that from a dead server, so every v1 path must
    answer 503 with a parseable body.
    """

    V1_PATHS = (
        "/api/v1/health",
        "/api/v1/metrics",
        "/api/v1/traffic-generator",
        "/api/v1/evidence",
        "/api/v1/evidence/some-evidence",
        "/api/v1/runs",
        "/api/v1/runs/some-run",
        "/api/v1/assessments",
        "/api/v1/assessments/some-assessment",
        "/api/v1/findings",
        "/api/v1/audit/events",
        "/api/v1/audit/runs",
        "/api/v1/governance",
    )

    def test_every_v1_path_answers_503_rather_than_dropping_the_connection(self):
        server = _LiveServer(phase10=None)
        self.addCleanup(server.close)
        for path in self.V1_PATHS:
            with self.subTest(path=path):
                # urlopen raises RemoteDisconnected (not HTTPError) if the
                # server closes without a response; that is the bug, so a
                # plain successful call here IS the assertion.
                status, _, body = server.json(path)
                self.assertEqual(status, 503)
                self.assertEqual(body["error"]["code"], "phase10_unavailable")

    def test_the_guard_lives_in_the_shared_dispatcher_not_the_handler(self):
        """A future framework adapter must inherit the guard for free."""
        with self.assertRaises(ApiError) as caught:
            app_module.handle_combined(build_store(), None, "/api/v1/health")
        self.assertEqual(caught.exception.status, 503)
        self.assertEqual(caught.exception.code, "phase10_unavailable")

    def test_phase8_still_works_without_phase10(self):
        server = _LiveServer(phase10=None)
        self.addCleanup(server.close)
        status, _, body = server.json("/api/health")
        self.assertEqual(status, 200)
        # The Phase-8 health block, not a v1 (body, content_type) tuple.
        self.assertEqual(body["service"], "sihcolayer-phase8-dashboard-api")
        self.assertTrue(body["read_only"])
        self.assertEqual(
            body["total_assessments"],
            handle_get(build_store(), "/api/health")["total_assessments"],
        )

    def test_v1_content_is_unpacked_from_the_dispatcher_pair(self):
        """Regression: a (body, content_type) tuple serialised as a JSON array.

        Unifying the phase-8 and v1 dispatch paths meant the transport stopped
        unpacking the v1 pair, and every /api/v1 response became
        ``[{...}, "application/json"]`` -- a shape no client contract expects.
        """
        from correlation.api.live import Phase10Context

        server = _LiveServer(phase10=Phase10Context())
        self.addCleanup(server.close)
        for path in ("/api/v1/health", "/api/v1/assessments", "/api/v1/findings"):
            with self.subTest(path=path):
                _, _, body = server.json(path)
                self.assertIsInstance(body, dict)
                self.assertNotIsInstance(body, list)

    def test_the_503_body_is_parseable_and_carries_a_request_id(self):
        server = _LiveServer(phase10=None)
        self.addCleanup(server.close)
        status, headers, body = server.json("/api/v1/health")
        self.assertEqual(status, 503)
        self.assertIn("request_id", body["error"])
        self.assertEqual(headers.get("X-Request-Id"), body["error"]["request_id"])


# ---------------------------------------------------------------------------
# CORS
# ---------------------------------------------------------------------------

class TestCorsPolicyResolution(unittest.TestCase):
    def test_unset_environment_falls_back_to_the_loopback_development_default(self):
        policy = CorsPolicy.from_env({})
        self.assertEqual(set(policy.allowed_origins), set(DEFAULT_ALLOWED_ORIGINS))
        self.assertFalse(policy.allow_all_origins)

    def test_the_development_default_is_never_a_wildcard(self):
        for origin in DEFAULT_ALLOWED_ORIGINS:
            self.assertNotEqual(origin, "*")
        self.assertFalse(CorsPolicy.from_env({}).allow_all_origins)

    def test_environment_overrides_the_default(self):
        policy = CorsPolicy.from_env({ENV_ALLOWED_ORIGINS: "https://ops.example,https://b.example"})
        self.assertEqual(policy.allowed_origins, frozenset({"https://ops.example", "https://b.example"}))

    def test_origin_comparison_ignores_case_and_trailing_slash(self):
        policy = CorsPolicy.from_env({ENV_ALLOWED_ORIGINS: "https://Ops.Example/"})
        self.assertTrue(policy.allows("https://ops.example"))
        self.assertTrue(policy.allows("https://OPS.EXAMPLE"))

    def test_wildcard_requires_an_explicit_opt_in(self):
        policy = CorsPolicy.from_env({ENV_ALLOWED_ORIGINS: "*"})
        self.assertTrue(policy.allow_all_origins)
        self.assertTrue(policy.allows("https://anything.example"))

    def test_empty_configuration_allows_nothing_rather_than_everything(self):
        """A cleared allow-list must lock the API down, not open it up.

        If an unset-and-an-empty variable were treated the same, a deploy
        manifest that sets the variable to "" would silently re-open the
        development defaults instead of closing the API.
        """
        for value in ("   ", ""):
            with self.subTest(value=value):
                policy = CorsPolicy.from_env({ENV_ALLOWED_ORIGINS: value})
                self.assertEqual(policy.allowed_origins, frozenset())
                self.assertFalse(policy.allows(ALLOWED_ORIGIN))

    def test_unset_and_empty_are_different_configurations(self):
        self.assertTrue(CorsPolicy.from_env({}).allows(ALLOWED_ORIGIN))
        self.assertFalse(CorsPolicy.from_env({ENV_ALLOWED_ORIGINS: ""}).allows(ALLOWED_ORIGIN))

    def test_credentials_are_never_enabled(self):
        for policy in (CorsPolicy.from_env({}), CorsPolicy.from_env({ENV_ALLOWED_ORIGINS: "*"})):
            self.assertFalse(summarize_cors(policy)["allow_credentials"])

    def test_summarize_never_leaks_a_host_path(self):
        blob = json.dumps(summarize_cors(CorsPolicy.from_env({})))
        self.assertNotIn("/", blob.split('"allowed_origins"')[0])


class TestCorsHeaders(unittest.TestCase):
    def test_allowed_origin_receives_the_header_and_vary(self):
        headers = {}
        self.assertTrue(apply_cors_headers(headers, CorsPolicy.from_env({}), ALLOWED_ORIGIN))
        self.assertEqual(headers["Access-Control-Allow-Origin"], ALLOWED_ORIGIN)
        # Without Vary: Origin a shared cache could serve one origin's allow
        # header to another.
        self.assertEqual(headers["Vary"], "Origin")

    def test_disallowed_origin_receives_no_cors_headers(self):
        headers = {}
        self.assertFalse(apply_cors_headers(headers, CorsPolicy.from_env({}), FOREIGN_ORIGIN))
        self.assertEqual(headers, {})

    def test_absent_origin_receives_no_cors_headers(self):
        headers = {}
        self.assertFalse(apply_cors_headers(headers, CorsPolicy.from_env({}), None))
        self.assertEqual(headers, {})

    def test_preflight_advertises_only_read_only_methods(self):
        headers = preflight_headers(CorsPolicy.from_env({}), ALLOWED_ORIGIN, None)
        methods = headers["Access-Control-Allow-Methods"]
        self.assertIn("GET", methods)
        self.assertNotIn("POST", methods)
        self.assertNotIn("PUT", methods)
        self.assertNotIn("DELETE", methods)
        self.assertEqual(headers["Content-Length"], "0")

    def test_preflight_echoes_only_permitted_request_headers(self):
        headers = preflight_headers(
            CorsPolicy.from_env({}), ALLOWED_ORIGIN, "content-type, x-not-allowed"
        )
        allowed = headers["Access-Control-Allow-Headers"]
        self.assertIn("content-type", allowed)
        self.assertNotIn("x-not-allowed", allowed)


class TestCorsWire(unittest.TestCase):
    def setUp(self):
        self.server = _LiveServer(phase10=None)
        self.addCleanup(self.server.close)

    def test_allowed_origin_gets_a_readable_response(self):
        status, headers, _ = self.server.request("/api/health", headers={"Origin": ALLOWED_ORIGIN})
        self.assertEqual(status, 200)
        self.assertEqual(headers.get("Access-Control-Allow-Origin"), ALLOWED_ORIGIN)

    def test_disallowed_origin_gets_no_allow_header_so_the_browser_blocks_it(self):
        status, headers, _ = self.server.request("/api/health", headers={"Origin": FOREIGN_ORIGIN})
        # The request itself still succeeds server-side; the browser refuses
        # the *read* because Access-Control-Allow-Origin is absent. That is
        # the intended enforcement point.
        self.assertEqual(status, 200)
        self.assertIsNone(headers.get("Access-Control-Allow-Origin"))

    def test_preflight_from_an_allowed_origin_is_204_with_the_policy(self):
        status, headers, body = self.server.request(
            "/api/health", method="OPTIONS",
            headers={
                "Origin": "http://localhost:5173",
                "Access-Control-Request-Method": "GET",
                "Access-Control-Request-Headers": "content-type",
            },
        )
        self.assertEqual(status, 204)
        self.assertEqual(headers.get("Access-Control-Allow-Origin"), "http://localhost:5173")
        self.assertIn("GET", headers["Access-Control-Allow-Methods"])
        self.assertEqual(body, b"")

    def test_preflight_is_never_501(self):
        """http.server has no default do_OPTIONS; the old bug was a 501."""
        for path in ("/api/health", "/api/assessments", "/api/v1/health", "/nope"):
            with self.subTest(path=path):
                status, _, _ = self.server.request(
                    path, method="OPTIONS", headers={"Origin": ALLOWED_ORIGIN}
                )
                self.assertNotEqual(status, 501)

    def test_preflight_from_a_denied_origin_is_403_with_no_allow_header(self):
        status, headers, body = self.server.request(
            "/api/health", method="OPTIONS", headers={"Origin": FOREIGN_ORIGIN}
        )
        self.assertEqual(status, 403)
        self.assertIsNone(headers.get("Access-Control-Allow-Origin"))
        self.assertEqual(json.loads(body)["error"]["code"], "origin_not_allowed")

    def test_preflight_to_a_non_api_path_is_404_but_still_speaks_cors(self):
        status, headers, _ = self.server.request(
            "/some/page", method="OPTIONS", headers={"Origin": ALLOWED_ORIGIN}
        )
        self.assertEqual(status, 404)
        self.assertEqual(headers.get("Access-Control-Allow-Origin"), ALLOWED_ORIGIN)

    def test_error_responses_also_carry_cors_headers(self):
        """A frontend must be able to read the *error* to learn why."""
        status, headers, _ = self.server.request(
            "/api/assessments/not-a-real-id", headers={"Origin": ALLOWED_ORIGIN}
        )
        self.assertEqual(status, 404)
        self.assertEqual(headers.get("Access-Control-Allow-Origin"), ALLOWED_ORIGIN)

    def test_wildcard_configuration_echoes_rather_than_sending_a_bare_star(self):
        server = _LiveServer(phase10=None, cors=CorsPolicy(allow_all_origins=True))
        self.addCleanup(server.close)
        _, headers, _ = server.request("/api/health", headers={"Origin": FOREIGN_ORIGIN})
        self.assertEqual(headers.get("Access-Control-Allow-Origin"), FOREIGN_ORIGIN)


# ---------------------------------------------------------------------------
# read-only guarantee
# ---------------------------------------------------------------------------

class TestReadOnlyOnTheWire(unittest.TestCase):
    def setUp(self):
        self.server = _LiveServer(phase10=None)
        self.addCleanup(self.server.close)

    def test_every_mutating_verb_is_405_on_every_path(self):
        for path in ("/api/health", "/api/assessments", "/api/v1/health", "/anything"):
            for verb in ("POST", "PUT", "PATCH", "DELETE"):
                with self.subTest(path=path, verb=verb):
                    status, headers, body = self.server.json(path, method=verb)
                    self.assertEqual(status, 405)
                    self.assertEqual(headers.get("Allow"), "GET, HEAD, OPTIONS")
                    self.assertEqual(body["error"]["code"], "method_not_allowed")

    def test_a_405_ignores_the_submitted_body(self):
        status, _, body = self.server.json(
            "/api/health", method="POST",
            headers={"Content-Type": "application/json"},
            data=b'{"resolve": "EVT-1", "approved": true}',
        )
        self.assertEqual(status, 405)
        self.assertTrue(body["error"]["message"].startswith("POST is not supported"))

    def test_head_returns_headers_without_a_body(self):
        status, headers, body = self.server.request("/api/health", method="HEAD")
        self.assertEqual(status, 200)
        self.assertEqual(body, b"")
        self.assertEqual(int(headers["Content-Length"]), len(
            app_module.to_json_bytes(handle_get(build_store(), "/api/health"))))


# ---------------------------------------------------------------------------
# error envelope
# ---------------------------------------------------------------------------

class TestErrorEnvelope(unittest.TestCase):
    def setUp(self):
        self.server = _LiveServer(phase10=None)
        self.addCleanup(self.server.close)

    def test_envelope_carries_code_message_detail_and_request_id(self):
        status, _, body = self.server.json("/api/assessments/not-a-real-id")
        error = body["error"]
        self.assertEqual(status, 404)
        self.assertIn("code", error)
        self.assertIn("message", error)
        # `detail` is the Phase-8 key and must survive for existing clients.
        self.assertEqual(error["detail"], error["message"])
        self.assertIn("request_id", error)

    def test_no_response_leaks_a_traceback_or_a_host_path(self):
        for path in (
            "/api/assessments/nope", "/api/assessments?limit=abc",
            "/api/assessments?limit=0", "/api/assessments?offset=-1",
            "/api/nope", "/api/v1/health",
            "/api/assessments/" + "../" * 5,
        ):
            with self.subTest(path=path):
                _, _, body = self.server.request(path)
                text = body.decode("utf-8", "replace")
                self.assertNotIn("Traceback", text)
                self.assertNotIn("File \"", text)
                self.assertNotIn(os.path.expanduser("~"), text)
                self.assertNotIn("/home/", text)
                self.assertNotIn("/tmp/", text)

    def test_an_internal_handler_failure_is_a_structured_500_not_a_traceback(self):
        class ExplodingStore:
            headers = []
            overview = {"total_assessments": 0}

            def get(self, assessment_id):
                raise RuntimeError("boom: /etc/secret should not appear")

        server = _LiveServer(phase10=None, store=ExplodingStore())
        self.addCleanup(server.close)
        # A syntactically valid id, so the failure happens in the store rather
        # than in id validation (which would legitimately 404).
        status, _, body = server.json("/api/assessments/dataset-20260924-003710:1:band-strong")
        self.assertEqual(status, 500)
        self.assertEqual(body["error"]["code"], "internal_error")
        self.assertIn("request_id", body["error"])
        self.assertNotIn("secret", json.dumps(body))

    def test_a_supplied_request_id_is_reused_for_correlation(self):
        _, headers, body = self.server.json(
            "/api/nope", headers={"X-Request-Id": "browser-trace-7"}
        )
        self.assertEqual(headers.get("X-Request-Id"), "browser-trace-7")
        self.assertEqual(body["error"]["request_id"], "browser-trace-7")

    def test_every_response_carries_the_request_id_header(self):
        for path in ("/api/health", "/api/nope", "/api/v1/health"):
            with self.subTest(path=path):
                _, headers, _ = self.server.request(path)
                self.assertIn("X-Request-Id", headers)


# ---------------------------------------------------------------------------
# configuration
# ---------------------------------------------------------------------------

class TestServerConfig(unittest.TestCase):
    def test_default_port_avoids_the_control_api_port(self):
        """Server A and the FastAPI control API must both be runnable."""
        self.assertNotEqual(DEFAULT_PORT, 8000)
        self.assertEqual(DEFAULT_PORT, 8081)

    def test_default_bind_is_loopback_only(self):
        self.assertEqual(DEFAULT_HOST, "127.0.0.1")

    def test_environment_supplies_host_and_port(self):
        config = ServerConfig.resolve(environ={ENV_HOST: "0.0.0.0", ENV_PORT: "9001"})
        self.assertEqual(config.host, "0.0.0.0")
        self.assertEqual(config.port, 9001)

    def test_cli_flags_win_over_the_environment(self):
        config = ServerConfig.resolve(
            host="10.0.0.5", port=1234, environ={ENV_HOST: "0.0.0.0", ENV_PORT: "9001"}
        )
        self.assertEqual(config.host, "10.0.0.5")
        self.assertEqual(config.port, 1234)

    def test_cli_origins_win_over_the_environment(self):
        config = ServerConfig.resolve(
            allowed_origins="https://cli.example",
            environ={ENV_ALLOWED_ORIGINS: "https://env.example"},
        )
        self.assertEqual(config.cors.allowed_origins, frozenset({"https://cli.example"}))

    def test_a_non_integer_port_is_a_startup_error_not_a_crash(self):
        with self.assertRaises(ValueError) as caught:
            ServerConfig.resolve(environ={ENV_PORT: "not-a-port"})
        self.assertIn(ENV_PORT, str(caught.exception))

    def test_a_bad_port_value_names_the_variable_for_the_operator(self):
        self.assertIn("ANALYTICS_API_PORT", str(
            self._error_from({"ANALYTICS_API_PORT": "eighty"})
        ))

    def _error_from(self, env):
        try:
            ServerConfig.resolve(environ=env)
        except ValueError as error:
            return error
        self.fail("expected a ValueError")

    def test_describe_reports_the_effective_policy(self):
        text = app_module.describe(ServerConfig.resolve(environ={ENV_ALLOWED_ORIGINS: "https://x.example"}))
        self.assertIn("https://x.example", text)


# ---------------------------------------------------------------------------
# pagination
# ---------------------------------------------------------------------------

class TestPaginationHelpers(unittest.TestCase):
    def test_defaults_are_applied_when_absent(self):
        self.assertEqual(page_params(None), (DEFAULT_PAGE_LIMIT, 0))
        self.assertEqual(page_params({}), (DEFAULT_PAGE_LIMIT, 0))

    def test_values_are_coerced_from_strings(self):
        self.assertEqual(page_params({"limit": "10", "offset": "5"}), (10, 5))

    def test_a_bad_limit_is_400_not_a_silent_default(self):
        for bad in ("abc", "0", "-1", "", True):
            with self.subTest(bad=bad):
                if bad == "":
                    continue  # empty means "not supplied"
                with self.assertRaises(ApiError) as caught:
                    page_params({"limit": bad})
                self.assertEqual(caught.exception.status, 400)
                self.assertEqual(caught.exception.code, "invalid_query_parameter")

    def test_a_negative_offset_is_400(self):
        with self.assertRaises(ApiError):
            page_params({"offset": "-1"})

    def test_limit_is_capped(self):
        limit, _ = page_params({"limit": "99999999"})
        self.assertEqual(limit, MAX_PAGE_LIMIT)

    def test_offset_past_the_end_is_an_empty_page_not_an_error(self):
        page, total = paginate([1, 2, 3], limit=10, offset=99)
        self.assertEqual(page, [])
        self.assertEqual(total, 3)

    def test_paginate_slices_the_right_window(self):
        items = list(range(10))
        page, total = paginate(items, limit=3, offset=6)
        self.assertEqual(page, [6, 7, 8])
        self.assertEqual(total, 10)

    def test_envelope_reports_count_total_and_has_more(self):
        body = paged_envelope("x", list(range(5)), limit=2, offset=2, key="things")
        self.assertEqual(body["things"], [2, 3])
        self.assertEqual(body["count"], 2)
        self.assertEqual(body["total"], 5)
        self.assertTrue(body["has_more"])
        self.assertEqual(paged_envelope("x", [1], 10, 0)["has_more"], False)


class TestPaginationIsHonouredOnTheWire(unittest.TestCase):
    def setUp(self):
        self.server = _LiveServer(phase10=None)
        self.addCleanup(self.server.close)

    def test_assessments_list_pages(self):
        _, _, first = self.server.json("/api/assessments?limit=2")
        _, _, second = self.server.json("/api/assessments?limit=2&offset=2")
        self.assertEqual(first["count"], 2)
        self.assertEqual(second["count"], 2)
        self.assertNotEqual(
            [h["assessment_id"] for h in first["headers"]],
            [h["assessment_id"] for h in second["headers"]],
        )
        self.assertEqual(first["total"], second["total"])

    def test_the_historical_headers_key_and_overview_survive_pagination(self):
        _, _, body = self.server.json("/api/assessments?limit=1")
        self.assertIn("overview", body)
        self.assertIn("headers", body)

    def test_no_parameters_still_returns_the_whole_table(self):
        _, _, plain = self.server.json("/api/assessments")
        _, _, paged = self.server.json("/api/assessments?limit=5000")
        self.assertEqual(
            [h["assessment_id"] for h in plain["headers"]],
            [h["assessment_id"] for h in paged["headers"]],
        )


def _write_analysis_journal(path, run_id, event_count):
    """Write a real analysis audit journal using the production event types.

    Building records with :class:`AuditEvent` + :class:`AuditJournal` rather
    than hand-rolled dicts matters: the store re-derives and verifies
    ``event_id`` on read, so a hand-written record fails to parse and the test
    would pass for the wrong reason.
    """
    from correlation.audit import AuditEvent, AuditJournal
    from correlation.models.identity import CorrelationIdentity

    journal = AuditJournal(path)
    for index in range(event_count):
        identity = CorrelationIdentity(
            dataset_run_id=run_id,
            experiment_id="exp-1",
            attempt_number=1,
            sequence=index + 1,  # 1-based
            window_index=index,
            window_start_ns=index * 1_000,
            window_end_ns=(index + 1) * 1_000,
        )
        # observation/state-builder is the one source the journal treats as
        # authoritative; AuditEvent refuses any other pairing, so this also
        # demonstrates the record is a real, valid audit event.
        journal.append(AuditEvent(
            event_type="observed_state",
            source="observation/state-builder",
            authoritative=True,
            identity=identity,
        ))
    return journal


class TestRunTrailPaginationRegression(unittest.TestCase):
    """Regression: limit/offset were echoed but never applied.

    ``/api/v1/runs/{id}/audit`` returned the whole run regardless of the query,
    so a client paging a long run re-fetched everything on every page and could
    never reach the end.
    """

    def setUp(self):
        import tempfile

        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = os.path.join(self.tmp.name, "events.jsonl")
        _write_analysis_journal(self.path, "run-1", 6)

        from correlation.api.audit_store import AuditQuery, AuditStore

        self.store = AuditStore(self.path)

    def _trail(self, **params):
        from correlation.api.audit_store import AuditQuery

        return self.store.run_trail("run-1", AuditQuery.from_params(params))

    def test_without_pagination_the_whole_run_is_returned(self):
        full = self._trail()
        self.assertEqual(full["event_count"], 6)
        self.assertEqual(full["returned_event_count"], 6)
        self.assertFalse(full["has_more"])

    def test_limit_actually_truncates_the_page(self):
        limited = self._trail(limit=2)
        self.assertEqual(limited["event_count"], 6)           # total preserved
        self.assertEqual(limited["returned_event_count"], 2)   # page is smaller
        self.assertEqual(limited["limit"], 2)
        self.assertTrue(limited["has_more"])

    def test_offset_actually_moves_the_window(self):
        first = self._trail(limit=2, offset=0)
        last = self._trail(limit=2, offset=4)
        self.assertEqual(first["returned_event_count"], 2)
        self.assertEqual(last["returned_event_count"], 2)
        self.assertFalse(last["has_more"])

    def test_pages_do_not_overlap(self):
        def ids(offset):
            trail = self._trail(limit=2, offset=offset)
            return [
                event.event_id
                for window in trail["windows"]
                for entry in window.stages
                for event in entry["events"]
            ]

        self.assertEqual(ids(0) + ids(2) + ids(4), ids(0) + ids(2) + ids(4))
        combined = ids(0) + ids(2) + ids(4)
        self.assertEqual(len(combined), len(set(combined)))
        self.assertEqual(len(combined), 6)

    def test_an_unknown_run_is_still_none_so_the_caller_can_404(self):
        self.assertIsNone(self.store.run_trail("no-such-run", None))


# ---------------------------------------------------------------------------
# path disclosure control
# ---------------------------------------------------------------------------

class TestPathRedaction(unittest.TestCase):
    def test_a_path_inside_a_root_becomes_root_relative(self):
        self.assertEqual(public_path("/srv/evidence/cap/a.pcap", roots=["/srv/evidence"]), "cap/a.pcap")

    def test_a_path_outside_every_root_is_reduced_to_its_basename(self):
        self.assertEqual(public_path("/etc/ipsec.secrets"), "ipsec.secrets")

    def test_never_returns_an_absolute_path(self):
        for path in ("/etc/passwd", "/home/analyst/private/cap.pcap", "/var/lib/x/y/z.jsonl"):
            for roots in ((), ("/srv/evidence",), ("/other",)):
                with self.subTest(path=path, roots=roots):
                    result = public_path(path, roots=roots)
                    self.assertFalse(result.startswith("/"))

    def test_a_prefix_sibling_is_not_treated_as_contained(self):
        # /srv/evidence-evil must not be reported as inside /srv/evidence.
        self.assertEqual(
            public_path("/srv/evidence-evil/a.pcap", roots=["/srv/evidence"]), "a.pcap"
        )

    def test_none_passes_through(self):
        self.assertIsNone(public_path(None))
        self.assertIsNone(public_path(""))

    def test_bounded_echo_caps_a_long_caller_supplied_value(self):
        self.assertEqual(bounded_echo("x" * 500), "x" * 120 + "...")
        self.assertEqual(bounded_echo("short"), "short")


class TestNoHostPathReachesTheWire(unittest.TestCase):
    """The three fields the audit found leaking absolute paths."""

    def test_evidence_detail_served_from_is_not_absolute(self):
        from correlation.api.evidence_routes import handle_evidence_id
        from correlation.api.live import Phase10Context
        from correlation.api.pcap import PcapRegistry, PcapService

        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            capture = os.path.join(tmp, "cap.pcap")
            with open(capture, "wb") as handle:
                handle.write(b"\xd4\xc3\xb2\xa1" + b"\x00" * 20)
            context = Phase10Context()
            context.pcap = PcapService(PcapRegistry(root=tmp))
            context.pcap.registry.register("ev-1", "cap.pcap")
            payload = handle_evidence_id(context, "ev-1")
            self.assertFalse(os.path.isabs(payload["served_from"]))
            self.assertEqual(payload["served_from"], "cap.pcap")
            self.assertFalse(payload["host_path_disclosed"])
            self.assertNotIn(tmp, json.dumps(payload))

    def test_governance_journal_is_not_absolute(self):
        from correlation.api.evidence_routes import handle_governance_list

        class _Ledger:
            path = "/var/lib/sihcolayer/chain/governance.jsonl"
            root = "/var/lib/sihcolayer"
            engine_version = "v1"

            def events(self):
                return []

            def verify(self):
                return True

        class _Context:
            governance = _Ledger()

        payload = handle_governance_list(_Context())
        self.assertFalse(os.path.isabs(payload["journal"]))
        self.assertNotIn("/var/lib", json.dumps(payload))

    def test_a_chain_verification_failure_does_not_echo_the_exception(self):
        from correlation.api.evidence_routes import handle_governance_list

        class _Ledger:
            path = "/var/lib/x/governance.jsonl"
            engine_version = "v1"

            def events(self):
                return []

            def verify(self):
                raise ValueError("corrupt record at /var/lib/x/governance.jsonl line 4")

        class _Context:
            governance = _Ledger()

        payload = handle_governance_list(_Context())
        self.assertFalse(payload["chain_verified"])
        self.assertNotIn("/var/lib", json.dumps(payload))

    def test_an_unreadable_audit_journal_does_not_echo_the_exception(self):
        from correlation.api.audit_routes import _guard
        from correlation.api.audit_store import AuditJournalUnreadable

        def explode():
            raise AuditJournalUnreadable("bad line in /home/analyst/journal.jsonl")

        with self.assertRaises(ApiError) as caught:
            _guard(explode)
        self.assertNotIn("/home/analyst", caught.exception.detail)
        self.assertEqual(caught.exception.code, "audit_journal_unreadable")

    def test_a_long_caller_supplied_id_is_truncated_in_the_error(self):
        server = _LiveServer(phase10=None)
        self.addCleanup(server.close)
        long_id = "z" * 4000
        _, _, body = server.json(f"/api/assessments/{long_id}")
        self.assertNotIn("z" * 200, json.dumps(body))


# ---------------------------------------------------------------------------
# discovery
# ---------------------------------------------------------------------------

class TestDiscoveryProjectsExistingData(unittest.TestCase):
    def setUp(self):
        self.store = build_store()

    def test_findings_are_copied_from_the_risk_engine_output(self):
        expected = []
        for bundle in self.store.bundles.values():
            for finding in bundle["risk"]["findings"]:
                expected.append(finding["finding_id"])
        reported = [row["finding_id"] for row in handle_findings(self.store)["findings"]]
        self.assertEqual(sorted(reported), sorted(expected))

    def test_no_finding_is_renamed_rescored_or_dropped(self):
        # finding_id is not globally unique -- the same risk can be raised
        # against several assessments -- so the comparison is keyed on the
        # pair. Keying on finding_id alone would silently drop all but one.
        original = {}
        for bundle in self.store.bundles.values():
            for finding in bundle["risk"]["findings"]:
                original[(bundle["assessment_id"], finding["finding_id"])] = finding

        rows = handle_findings(self.store)["findings"]
        self.assertEqual(len(rows), len(original), "a finding was dropped or duplicated")
        for row in rows:
            source = original[(row["assessment_id"], row["finding_id"])]
            for key, value in source.items():
                self.assertEqual(
                    row[key], value,
                    f"{row['finding_id']}.{key} was altered by the projection",
                )

    def test_findings_are_ordered_worst_first(self):
        severities = [row["severity"] for row in handle_findings(self.store)["findings"]]
        order = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
        self.assertEqual(severities, sorted(severities, key=order.index))

    def test_findings_carry_provenance_back_to_their_assessment(self):
        for row in handle_findings(self.store)["findings"]:
            self.assertIn("assessment_id", row)
            self.assertIn("dataset_run_id", row)
            self.assertTrue(row["read_only"])

    def test_findings_can_be_filtered(self):
        every = handle_findings(self.store)
        high = handle_findings(self.store, {"severity": "HIGH"})
        self.assertLess(high["total"], every["total"])
        self.assertTrue(all(row["severity"] == "HIGH" for row in high["findings"]))

    def test_a_severity_filter_accepts_several_values(self):
        body = handle_findings(self.store, {"severity": "HIGH,MEDIUM"})
        self.assertTrue({row["severity"] for row in body["findings"]} <= {"HIGH", "MEDIUM"})

    def test_an_unknown_severity_returns_an_empty_page_not_an_error(self):
        body = handle_findings(self.store, {"severity": "NOPE"})
        self.assertEqual(body["total"], 0)
        self.assertEqual(body["findings"], [])

    def test_assessments_match_the_phase8_list_exactly(self):
        phase8 = handle_get(self.store, "/api/assessments")["headers"]
        phase10 = handle_assessments_v1(self.store)["assessments"]
        self.assertEqual(
            [row["assessment_id"] for row in phase8],
            [row["assessment_id"] for row in phase10],
        )

    def test_assessments_can_be_filtered_and_sorted(self):
        body = handle_assessments_v1(self.store, {"sort": "risk", "order": "asc"})
        scores = [row["risk_score"] for row in body["assessments"] if row.get("risk_score") is not None]
        self.assertEqual(scores, sorted(scores))

    def test_a_single_assessments_findings_page_matches_the_global_list(self):
        assessment_id = next(
            bundle["assessment_id"] for bundle in self.store.bundles.values()
            if bundle["risk"]["findings"]
        )
        per_assessment = handle_assessment_findings(self.store, assessment_id)["findings"]
        globally = [
            row for row in handle_findings(self.store)["findings"]
            if row["assessment_id"] == assessment_id
        ]
        self.assertEqual(per_assessment, globally)

    def test_an_unknown_assessment_is_a_structured_404(self):
        with self.assertRaises(ApiError) as caught:
            handle_assessment_findings(self.store, "no-such-assessment")
        self.assertEqual(caught.exception.status, 404)

    def test_runs_require_a_journal_and_say_so_rather_than_returning_empty(self):
        with self.assertRaises(ApiError) as caught:
            handle_runs(None)
        self.assertEqual(caught.exception.status, 503)
        self.assertEqual(caught.exception.code, "runs_unavailable")
        self.assertIn("audit-journal", caught.exception.detail)

    def test_runs_come_from_the_journal_and_never_include_a_fabricated_run(self):
        from correlation.api.audit_store import AuditStore

        store = AuditStore("/nonexistent.jsonl")
        body = handle_runs(store)
        self.assertEqual(body["runs"], [])
        self.assertIn("read_only", body)

    def test_an_unknown_run_is_a_structured_404(self):
        from correlation.api.audit_store import AuditStore

        with self.assertRaises(ApiError) as caught:
            handle_run(AuditStore("/nonexistent.jsonl"), "no-such-run")
        self.assertEqual(caught.exception.status, 404)


class TestDiscoveryOnTheWire(unittest.TestCase):
    """Discovery as a browser actually reaches it: a live server + a journal."""

    def setUp(self):
        import tempfile

        from correlation.api.audit_store import AuditStore
        from correlation.api.live import Phase10Context

        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        journal = os.path.join(self.tmp.name, "events.jsonl")
        _write_analysis_journal(journal, "run-1", 3)

        context = Phase10Context()
        context.attach_audit_store(AuditStore(journal))
        self.context = context
        self.server = _LiveServer(phase10=context)
        self.addCleanup(self.server.close)

    def test_the_new_discovery_routes_answer(self):
        for path in ("/api/v1/runs", "/api/v1/assessments", "/api/v1/findings"):
            with self.subTest(path=path):
                status, _, body = self.server.json(path)
                self.assertEqual(status, 200)
                self.assertTrue(body["read_only"])

    def test_runs_are_enumerated_from_the_journal(self):
        _, _, body = self.server.json("/api/v1/runs")
        self.assertEqual([run["run_id"] for run in body["runs"]], ["run-1"])

    def test_a_single_run_is_addressable(self):
        status, _, body = self.server.json("/api/v1/runs/run-1")
        self.assertEqual(status, 200)
        self.assertEqual(body["run"]["run_id"], "run-1")

    def test_health_reports_the_effective_cors_policy(self):
        status, _, body = self.server.json("/api/v1/health")
        self.assertEqual(status, 200)
        self.assertIn("cors", body)
        self.assertIn("allowed_origins", body["cors"])
        self.assertFalse(body["cors"]["allow_credentials"])

    def test_the_run_audit_trail_is_reachable_and_paged(self):
        status, _, body = self.server.json("/api/v1/runs/run-1/audit?limit=1")
        self.assertEqual(status, 200)
        self.assertEqual(body["event_count"], 3)
        self.assertEqual(body["returned_event_count"], 1)
        self.assertTrue(body["has_more"])

    def test_run_sub_resources_are_not_shadowed_by_run_discovery(self):
        """Regression risk: /api/v1/runs/{id} must not swallow the sub-routes."""
        status, _, body = self.server.json("/api/v1/runs/some-run/audit")
        self.assertEqual(status, 404)
        self.assertNotEqual(body["error"]["code"], "unknown_route")

    def test_findings_pagination_is_consistent(self):
        _, _, page1 = self.server.json("/api/v1/findings?limit=1")
        self.assertEqual(page1["count"], 1)
        _, _, page2 = self.server.json("/api/v1/findings?limit=1&offset=1")
        if page1["total"] > 1:
            self.assertNotEqual(
                page1["findings"][0]["finding_id"], page2["findings"][0]["finding_id"]
            )


class TestDiscoveryWithoutAJournal(unittest.TestCase):
    """Run discovery must report the real absence, not an empty list.

    An empty ``runs: []`` reads as "there are no runs" and a frontend would
    render an empty state. The truth is "the set of runs is unknown because no
    journal is attached", which is a 503.
    """

    def setUp(self):
        from correlation.api.live import Phase10Context

        self.server = _LiveServer(phase10=Phase10Context())
        self.addCleanup(self.server.close)

    def test_runs_reports_503_with_actionable_detail(self):
        status, _, body = self.server.json("/api/v1/runs")
        self.assertEqual(status, 503)
        self.assertEqual(body["error"]["code"], "runs_unavailable")
        self.assertIn("--audit-journal", body["error"]["message"])

    def test_assessments_and_findings_still_work_without_a_journal(self):
        for path in ("/api/v1/assessments", "/api/v1/findings"):
            with self.subTest(path=path):
                status, _, _ = self.server.json(path)
                self.assertEqual(status, 200)


# ---------------------------------------------------------------------------
# PCAP
# ---------------------------------------------------------------------------

class TestPcapStreaming(unittest.TestCase):
    def setUp(self):
        import tempfile
        from correlation.api.live import Phase10Context
        from correlation.api.pcap import PcapRegistry, PcapService

        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.payload = b"\xd4\xc3\xb2\xa1" + os.urandom(200_000)
        with open(os.path.join(self.tmp.name, "cap.pcap"), "wb") as handle:
            handle.write(self.payload)

        context = Phase10Context()
        context.pcap = PcapService(PcapRegistry(root=self.tmp.name))
        context.pcap.registry.register("ev-stream", "cap.pcap")
        self.context = context
        self.server = _LiveServer(phase10=context)
        self.addCleanup(self.server.close)

    def test_the_capture_is_served_with_the_correct_length(self):
        status, headers, body = self.server.request("/api/v1/evidence/ev-stream/pcap")
        self.assertEqual(status, 200)
        self.assertEqual(int(headers["Content-Length"]), len(self.payload))
        self.assertEqual(body, self.payload)

    def test_the_capture_is_an_attachment_so_a_browser_saves_it(self):
        _, headers, _ = self.server.request("/api/v1/evidence/ev-stream/pcap")
        self.assertIn("attachment", headers["Content-Disposition"])
        self.assertIn("ev-stream", headers["Content-Disposition"])

    def test_the_filename_does_not_reveal_the_directory(self):
        _, headers, _ = self.server.request("/api/v1/evidence/ev-stream/pcap")
        self.assertNotIn("/", headers["Content-Disposition"].split("filename=")[1].strip('";'))

    def test_an_unregistered_evidence_id_is_404(self):
        status, _, body = self.server.json("/api/v1/evidence/never-registered/pcap")
        self.assertEqual(status, 404)
        self.assertEqual(body["error"]["code"], "evidence_not_found")

    def test_pcap_downloads_are_still_counted(self):
        self.server.request("/api/v1/evidence/ev-stream/pcap")
        # Assert through the public render() surface rather than reaching
        # into the counter's private values.
        self.assertIn("pcap_downloads", self.context.metrics.pcap_downloads.render())

    def test_streaming_reports_the_size_without_reading_the_file(self):
        size = self.context.pcap.size("ev-stream")
        self.assertEqual(size, len(self.payload))
        stream = self.context.pcap.open_stream("ev-stream")
        try:
            self.assertEqual(len(stream.read(16)), 16)
        finally:
            stream.close()

    def test_size_and_stream_are_none_for_an_unregistered_id(self):
        self.assertIsNone(self.context.pcap.size("nope"))
        self.assertIsNone(self.context.pcap.open_stream("nope"))


# ---------------------------------------------------------------------------
# OpenAPI
# ---------------------------------------------------------------------------

class TestOpenApiDocument(unittest.TestCase):
    def setUp(self):
        self.doc = openapi_document()
        self.store = build_store()

    def test_the_document_is_shaped_correctly(self):
        self.assertEqual(self.doc["openapi"], "3.1.0")
        self.assertIn("info", self.doc)
        self.assertIn("components", self.doc)
        self.assertIn("Error", self.doc["components"]["schemas"])

    def test_no_server_is_declared_so_a_generator_uses_the_origin_it_loaded_it_from(self):
        self.assertEqual(self.doc["servers"], [])

    def test_every_operation_is_get_only(self):
        for path, ops in self.doc["paths"].items():
            with self.subTest(path=path):
                self.assertEqual(list(ops), ["get"])

    def test_every_path_parameter_is_declared(self):
        for path, ops in self.doc["paths"].items():
            declared = {p["name"] for p in ops["get"]["parameters"] if p["in"] == "path"}
            for name in re.findall(r"\{(\w+)\}", path):
                self.assertIn(name, declared, f"{path} does not declare {name}")

    def test_no_operation_suggests_a_mutation(self):
        text = json.dumps(self.doc).lower()
        for verb in ("post", "put", "patch", "delete"):
            self.assertNotIn(f'"{verb}":', text)

    def test_operation_ids_are_unique(self):
        ids = [ops["get"]["operationId"] for ops in self.doc["paths"].values()]
        self.assertEqual(len(ids), len(set(ids)))

    def test_every_schema_reference_resolves(self):
        for path, ops in self.doc["paths"].items():
            for ref in re.findall(r'"#/components/schemas/(\w+)"', json.dumps(ops)):
                self.assertIn(ref, self.doc["components"]["schemas"], f"{path} -> {ref}")

    def test_the_document_states_the_read_only_and_no_auth_truth(self):
        description = self.doc["info"]["description"]
        self.assertIn("Read-only", description)
        self.assertIn("Authentication: none", description)
        self.assertIn("request_id", description)
        self.assertIn("ANALYTICS_API_ALLOWED_ORIGINS", description)

    def test_the_docs_page_is_served_without_a_remote_dependency(self):
        html = docs_html().decode()
        self.assertIn("<table", html)
        # A CDN <script src="http..."> would be a supply-chain surface.
        self.assertNotIn('src="http', html)
        self.assertNotIn("<script", html)

    def test_the_docs_page_escapes_route_text(self):
        html = docs_html().decode()
        self.assertNotIn("<td><code>GET</code></td><td><code>GET", html)


class TestOpenApiDoesNotDrift(unittest.TestCase):
    """A hand-written schema that is never checked becomes a lie.

    These tests compare the document against the live router in both
    directions, so adding a route without documenting it (or documenting one
    that does not exist) fails the suite rather than misleading a client.
    """

    def _live_dispatch(self, path):
        from correlation.api.live import Phase10Context

        return Phase10Context(), build_store()

    def test_every_documented_route_is_really_routable(self):
        context, store = self._live_dispatch("/api/health")
        for template in openapi_document()["paths"]:
            probe = re.sub(r"\{[^}]+\}", SENTINEL, template)
            with self.subTest(path=template):
                try:
                    app_module.handle_combined(store, context, probe, {})
                except ApiError as error:
                    # A resource 404/503 is correct: the route exists and
                    # rejected the sentinel id. `unknown_route` is not.
                    self.assertNotEqual(
                        error.code, "unknown_route",
                        f"{template} is documented but the router rejects it as unknown",
                    )

    def test_every_live_route_is_documented(self):
        context, store = self._live_dispatch("/api/health")
        documented = openapi_document()["paths"]
        # The live route surface, as concrete probes. Param names must match the
        # document's templates, which is why they are spelled out here rather
        # than generated: a mismatch is exactly the drift being tested for.
        probes = [
            "/api/health", "/api/assessments", "/api/assessments/{id}",
            "/api/assessments/{id}/correlation", "/api/assessments/{id}/risk",
            "/api/assessments/{id}/xai", "/api/assessments/{id}/ml",
            "/api/assessments/{id}/evidence", "/api/assessments/{id}/ipsec-state",
            "/api/v1/health", "/api/v1/metrics", "/api/v1/traffic-generator",
            "/api/v1/evidence", "/api/v1/evidence/{evidence_id}",
            "/api/v1/evidence/{evidence_id}/pcap",
            "/api/v1/runs", "/api/v1/runs/{run_id}", "/api/v1/runs/{run_id}/evidence",
            "/api/v1/runs/{run_id}/audit", "/api/v1/assessments",
            "/api/v1/assessments/{id}", "/api/v1/assessments/{id}/findings",
            "/api/v1/assessments/{id}/findings/{finding_id}/explanation",
            "/api/v1/findings", "/api/v1/findings/{finding_id}/explanation",
            "/api/v1/audit/events", "/api/v1/audit/events/{event_id}",
            "/api/v1/audit/events/{event_id}/evidence", "/api/v1/audit/runs",
            "/api/v1/audit/runs/{run_id}",
            "/api/v1/governance", "/api/v1/governance/{event_id}",
            "/api/v1/responses/{recommendation_id}/evidence",
        ]
        for template in probes:
            with self.subTest(path=template):
                self.assertIn(template, documented,
                              f"{template} is routable but undocumented")

    def test_unknown_v1_routes_still_report_unknown_route(self):
        context, store = self._live_dispatch("/api/health")
        # For a prefix that owns a family of sub-routes, the code that reports
        # "I do not know this one" is unknown_resource rather than
        # unknown_route; both mean 404 and neither may ever be a 200.
        for probe, expected in (
            ("/api/v1/nope", "unknown_route"),
            ("/api/v1/runs/a/b/c", "unknown_route"),
            ("/api/v1/assessments/a/b", "unknown_route"),
            ("/api/v1/governance/a/b", "unknown_route"),
            ("/api/v1/evidence/a/b/c", "unknown_resource"),
        ):
            with self.subTest(path=probe):
                with self.assertRaises(ApiError) as caught:
                    app_module.handle_combined(store, context, probe, {})
                self.assertEqual(caught.exception.status, 404)
                self.assertEqual(caught.exception.code, expected)


class TestOpenApiOnTheWire(unittest.TestCase):
    def setUp(self):
        self.server = _LiveServer(phase10=None)
        self.addCleanup(self.server.close)

    def test_the_document_is_served_as_json(self):
        status, headers, body = self.server.request("/api/v1/openapi.json")
        self.assertEqual(status, 200)
        self.assertIn("application/json", headers["Content-Type"])
        self.assertEqual(json.loads(body)["openapi"], "3.1.0")

    def test_the_docs_page_is_served_as_html(self):
        status, headers, body = self.server.request("/api/v1/docs")
        self.assertEqual(status, 200)
        self.assertIn("text/html", headers["Content-Type"])
        self.assertIn(b"<table", body)

    def test_the_document_is_served_without_phase10(self):
        """A client needs the contract to know why the data routes 503."""
        status, _, _ = self.server.request("/api/v1/openapi.json")
        self.assertEqual(status, 200)


# ---------------------------------------------------------------------------
# separation from the control API
# ---------------------------------------------------------------------------

class TestControlApiSeparation(unittest.TestCase):
    def test_server_a_does_not_import_the_control_api(self):
        """The two servers are independent; a coupling would be a real defect."""
        import ast
        import pathlib

        package = pathlib.Path(app_module.__file__).parent
        for path in package.glob("*.py"):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom):
                    self.assertNotIn("controller", (node.module or "").split(".")[0],
                                     f"{path.name} imports from the control API")
                elif isinstance(node, ast.Import):
                    for alias in node.names:
                        self.assertNotEqual(alias.name.split(".")[0], "controller",
                                            f"{path.name} imports the control API")

    def test_the_control_api_does_not_mount_server_a(self):
        """The two servers stay independent.

        The control API legitimately mounts its own ``/static`` and its own
        dataset router; what it must not do is mount or import anything from
        ``correlation.api``, which would couple the FastAPI process to the
        stdlib transport and the read-only analysis contract.
        """
        import ast
        import pathlib

        source = pathlib.Path("controller/api.py").read_text(encoding="utf-8")
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                self.assertNotIn(
                    "correlation", (node.module or "").split(".")[0],
                    "the control API must not import the analytics package",
                )
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    self.assertNotEqual(
                        alias.name.split(".")[0], "correlation",
                        "the control API must not import the analytics package",
                    )
            elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                if node.func.attr in ("mount", "include_router"):
                    rendered = ast.dump(node)
                    self.assertNotIn("correlation", rendered,
                                     "the control API must not mount the analytics API")


if __name__ == "__main__":
    unittest.main()
