"""Dashboard / analytics HTTP service (stdlib only) — "Server A".

A zero-dependency JSON API server implementing the Phase-8 REST contract, the
observable-only Phase-10 ``/api/v1`` surface, resource discovery, and a
maintained OpenAPI description:

    python -m correlation.api.app --phase10

Configuration is environment-first so a browser frontend can be pointed at a
running instance without editing code:

==============================  =========================================
``ANALYTICS_API_HOST``          bind address      (default ``127.0.0.1``)
``ANALYTICS_API_PORT``          bind port         (default ``8081``)
``ANALYTICS_API_ALLOWED_ORIGINS``  CORS origin allow-list (comma separated)
==============================  =========================================

CLI flags (``--host``/``--port``/``--allowed-origins``) win over the
environment.  The default port is 8081 rather than 8000 on purpose: the
testbed control API (``controller/api.py``) is a separate FastAPI app
conventionally started on 8000, and the two are meant to run side by side.

Design boundaries
-----------------
* The endpoint handlers live in ``.routes``, ``.v1``, ``.evidence_routes``,
  ``.audit_routes`` and ``.discovery`` (pure functions; tested without
  sockets).  This module is a thin stdlib transport.
* It does not modify any backend domain object and ports no decision logic.
* The API is READ-ONLY.  Every mutating verb is answered 405; there is no
  action, approval, target or enforcement input on any route.
* A FastAPI deployment could reuse ``handle_get``/``handle_v1_get`` unchanged
  (they are transport agnostic).

See ``docs/analytics/ANALYTICS_API_FRONTEND_CONTRACT.md`` for the contract a
browser client codes against, and ``docs/analytics/ANALYTICS_API_INTEGRATION_REPORT.md``
for what was changed and how it was verified.
"""

import argparse
import json
import os
import sys
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, Optional, Tuple
from urllib.parse import parse_qs, unquote

from .config import (
    DEFAULT_HOST,
    DEFAULT_PORT,
    ENV_ALLOWED_ORIGINS,
    ENV_CAPTURE_FEED,
    ENV_HOST,
    ENV_PORT,
    ServerConfig,
    describe,
)
from .capture_feed import DEFAULT_CAPTURE_FEED_PATH
from .cors import (
    PREFLIGHT_DENIED_STATUS,
    PREFLIGHT_STATUS,
    PREFLIGHT_UNKNOWN_STATUS,
    apply_cors_headers,
    preflight_headers,
)
from .pcap import PcapService
from .routes import ApiError, handle_get, serializable
from .store import AssessmentStore, build_store
from .v1 import (
    CONTENT_TYPE_PCAP,
    DOCS_PATH,
    OPENAPI_PATH,
    handle_v1_pcap,
    handle_v1_get,
    is_v1_path,
)

SNAPSHOT_PATH = os.path.join(
    os.path.dirname(__file__), "..", "..", "out", "dashboard_snapshot.json"
)
STATIC_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "dashboard", "build")

#: Methods that mutate state.  There are no such routes; these verbs are
#: answered with a structured 405 so a browser client learns the API is
#: read-only instead of seeing a bare connection error.
MUTATING_METHODS = ("POST", "PUT", "PATCH", "DELETE")

#: How much of a query value is echoed back in a 400.  Unbounded echoing lets
#: a caller push an arbitrarily long string into our logs and their devtools.
MAX_ECHOED_VALUE = 120


def to_json_bytes(payload: dict) -> bytes:
    return (json.dumps(payload, indent=2, sort_keys=False) + "\n").encode("utf-8")


def snapshot(store: AssessmentStore, output: str = SNAPSHOT_PATH) -> str:
    """Persist the full deterministic store for fully-static dashboards."""
    os.makedirs(os.path.dirname(os.path.abspath(output)), exist_ok=True)
    with open(output, "w", encoding="utf-8") as handle:
        json.dump(serializable(store), handle, indent=2, sort_keys=True)
        handle.write("\n")
    return output


def parse_assessment_id_for_url(assessment_id: str) -> Tuple[Optional[tuple], Optional[str]]:
    """Return (parsed, None) or (None, error detail) — used for validation docs."""
    return None, None  # (kept for symmetry; real check is inside routes)


def truncate_for_echo(value: Any) -> str:
    """Bound a caller-supplied value before it is reflected in a response."""
    text = str(value)
    if len(text) <= MAX_ECHOED_VALUE:
        return text
    return text[:MAX_ECHOED_VALUE] + "..."


def handle_combined(store, context, path: str, params: Optional[dict] = None) -> Any:
    """Dispatch /api (phase 8) or /api/v1 (phase 10) without file I/O here.

    This is the single place the "is the /api/v1 surface attached?" guard
    lives, so every transport (or future framework adapter) inherits it.

    ``params`` is the parsed query string; it is forwarded to the /api/v1
    handlers (the audit, discovery and governance routes filter and page on
    it). The Phase-8 contract is path-only apart from ``/api/assessments``
    pagination, and is unaffected.
    """
    if context is not None:
        annex = getattr(context, "annex", None)
        if annex is not None:
            annex.sync()
    if is_v1_path(path):
        if context is None:
            raise ApiError(503, "phase10_unavailable",
                           "/api/v1 requires --phase10 (live context not attached)")
        return handle_v1_get(context, path, params, store=store)
    return handle_get(store, path, params)


class DashboardHandler(BaseHTTPRequestHandler):
    server_version = "SIHColayerAnalyticsAPI"

    # -- verbs ---------------------------------------------------------------

    def do_GET(self) -> None:  # noqa: N802
        self._dispatch()

    def do_HEAD(self) -> None:  # noqa: N802
        # HEAD is GET without a body.  Implemented rather than falling through
        # to BaseHTTPRequestHandler's 501 so a client can probe endpoint
        # existence and CORS policy with a cheap request.
        self._head_only = True
        self._dispatch()

    def do_OPTIONS(self) -> None:  # noqa: N802
        self._options()

    def do_POST(self) -> None:  # noqa: N802
        self._method_not_allowed("POST")

    def do_PUT(self) -> None:  # noqa: N802
        self._method_not_allowed("PUT")

    def do_PATCH(self) -> None:  # noqa: N802
        self._method_not_allowed("PATCH")

    def do_DELETE(self) -> None:  # noqa: N802
        self._method_not_allowed("DELETE")

    # -- helpers ------------------------------------------------------------

    def _phase10(self):
        return getattr(self.server, "phase10", None)  # type: ignore[attr-defined]

    def _cors_policy(self):
        return getattr(self.server, "cors", None)  # type: ignore[attr-defined]

    def _origin(self) -> Optional[str]:
        return self.headers.get("Origin")

    def _request_id(self) -> str:
        return getattr(self, "_rid", None) or "-"

    def _method_not_allowed(self, verb: str) -> None:
        """405 for every mutating verb, on any path.

        The API is read-only by design, so this is the *only* correct answer.
        ``Allow`` is included per RFC 9110 so a client (and a browser preflight)
        can see what is actually supported instead of guessing.
        """
        self._rid = uuid.uuid4().hex
        self._start()
        body = {
            "error": {
                "code": "method_not_allowed",
                "message": (
                    f"{verb} is not supported; the analytics API is read-only "
                    "(GET, HEAD and OPTIONS only)"
                ),
                "detail": (
                    f"{verb} is not supported; the analytics API is read-only."
                ),
                "request_id": self._rid,
            }
        }
        self._send(
            405,
            "application/json",
            to_json_bytes(body),
            extra_headers={"Allow": "GET, HEAD, OPTIONS"},
        )

    def _options(self) -> None:
        """Answer a CORS preflight for any path.

        Every path is answered, not just known routes, because a browser must
        receive a CORS-bearing response to evaluate the real request.  For a
        path that is not part of the API the preflight is 404 so a typo'd
        route is visible, but it still carries CORS headers when the origin is
        allowed so the browser reports a clean 404 rather than a CORS error
        that masks the real problem.
        """
        self._rid = uuid.uuid4().hex
        path, _, _ = unquote(self.path).partition("?")
        self._start()
        policy = self._cors_policy()
        if policy is None:
            self._end(PREFLIGHT_STATUS, {})
            return
        origin = self._origin()
        if not policy.allows(origin):
            # Visible rejection for operators; deliberately no
            # Access-Control-Allow-Origin, so the browser blocks the follow-up.
            self._send(
                PREFLIGHT_DENIED_STATUS,
                "application/json",
                to_json_bytes(
                    {
                        "error": {
                            "code": "origin_not_allowed",
                            "message": (
                                f"origin {truncate_for_echo(origin or '')!r} is not "
                                f"in the configured allow-list; set "
                                f"{ENV_ALLOWED_ORIGINS} to add it"
                            ),
                            "detail": "origin not allowed",
                            "request_id": self._rid,
                        }
                    }
                ),
            )
            return
        headers = preflight_headers(
            policy, origin, self.headers.get("Access-Control-Request-Headers")
        )
        status = PREFLIGHT_STATUS if self._is_api_path(path) else PREFLIGHT_UNKNOWN_STATUS
        self._end(status, headers)

    def _is_api_path(self, path: str) -> bool:
        return path == "/api" or path.startswith("/api/")

    def _start(self) -> None:
        """Allocate this request's correlation id, honouring an inbound one.

        Reusing a client-supplied ``X-Request-Id`` lets a browser console line
        be matched to a server log, but it is length-bounded and character-
        filtered so it cannot be used to inject headers or blow up the logs.
        """
        supplied = self.headers.get("X-Request-Id")
        if supplied:
            cleaned = "".join(
                ch for ch in supplied.strip() if ch.isalnum() or ch in "-_."
            )[:64]
            self._rid = cleaned or uuid.uuid4().hex
        else:
            self._rid = uuid.uuid4().hex

    def _dispatch(self) -> None:
        self._start()
        try:
            raw = unquote(self.path)
            path, _, query = raw.partition("?")
            # parse_qs yields lists; collapse the common single-value case so
            # handlers see scalars, and keep repeated params as lists.
            self._query = {
                key: (values[0] if len(values) == 1 else values)
                for key, values in (parse_qs(query, keep_blank_values=True) if query else {}).items()
            }
            if self._is_api_path(path):
                self._api(path)
            else:
                self._static(path)
        except ApiError as error:
            self._send_error_payload(error)
        except (BrokenPipeError, ConnectionResetError):
            # The client went away mid-response; nothing to report to it.
            raise
        except Exception as error:  # noqa: BLE001 - deliberate catch-all
            # A handler bug must not reach the client as a traceback: that
            # leaks absolute paths, source layout and internals.  Log the
            # detail server-side with the request id, return a structured 500.
            self._log_exception(error)
            self._send(
                500,
                "application/json",
                to_json_bytes(
                    {
                        "error": {
                            "code": "internal_error",
                            "message": (
                                "the analytics API failed to process this "
                                "request; quote the request_id when reporting it"
                            ),
                            "detail": "internal server error",
                            "request_id": self._rid,
                        }
                    }
                ),
            )

    def _log_exception(self, error: BaseException) -> None:
        import traceback

        traceback.print_exception(type(error), error, error.__traceback__, file=sys.stderr)
        sys.stderr.write(f"[analytics-api] request_id={self._rid} error={error!r}\n")

    def _send_error_payload(self, error: ApiError) -> None:
        self._send(
            error.status,
            "application/json",
            to_json_bytes(error.payload(self._rid)),
        )

    def _api(self, path: str) -> None:
        """Route one /api path through the single guarded dispatcher.

        The phase10 guard lives in :func:`handle_combined` so that
        ``/api/v1/*`` without ``--phase10`` yields a structured 503 instead of
        the connection drop that dereferencing a missing context caused.
        """
        context = self._phase10()
        params = getattr(self, "_query", {}) or {}
        store = getattr(self.server, "store", None)  # type: ignore[attr-defined]
        if is_v1_path(path):
            if self._is_pcap_path(path):
                self._pcap(context, path)
                return
            if path in (OPENAPI_PATH, DOCS_PATH):
                from .openapi import docs_html, openapi_document

                payload, content_type = (
                    (openapi_document(), "application/json")
                    if path == OPENAPI_PATH
                    else (docs_html(), "text/html; charset=utf-8")
                )
                self._send(200, content_type, payload if isinstance(payload, bytes)
                           else to_json_bytes(payload))
                return
        try:
            payload = handle_combined(store, context, path, params)
        except ApiError as error:
            self._send_error_payload(error)
            return
        # /api (phase 8) returns a bare dict; /api/v1 returns a
        # (content, content_type) pair so it can serve Prometheus text as well
        # as JSON. Unpack here, once, rather than duplicating the branch in
        # every handler -- serialising the tuple directly would emit a JSON
        # array of [body, "application/json"], which is not the contract.
        content_type = "application/json"
        if isinstance(payload, tuple):
            payload, content_type = payload
        if isinstance(payload, str):
            self._send(200, content_type, payload.encode("utf-8"))
        elif isinstance(payload, bytes):
            self._send(200, content_type, payload)
        else:
            self._send(200, content_type, to_json_bytes(payload))

    def _is_pcap_path(self, path: str) -> bool:
        prefix = "/api/v1/evidence/"
        return path.startswith(prefix) and path.endswith("/pcap")

    def _pcap(self, context, path: str) -> None:
        """Stream a registered capture.

        Streaming rather than ``read()`` because a capture is routinely tens of
        megabytes: buffering it whole doubled peak memory for every concurrent
        browser download.  The bytes still come from the hardened registry
        (allow-listed evidence id, contained under the root, known extension),
        so streaming is not a weaker path than the buffered one.
        """
        if context is None:
            self._send_error_payload(
                ApiError(503, "phase10_unavailable",
                         "/api/v1 requires --phase10 (live context not attached)")
            )
            return
        prefix = "/api/v1/evidence/"
        evidence_id = path[len(prefix):-len("/pcap")]
        try:
            handle_v1_pcap(context, evidence_id)  # descriptor + validation
        except ApiError as error:
            self._send_error_payload(error)
            return
        service: PcapService = context.pcap
        size = service.size(evidence_id)
        stream = service.open_stream(evidence_id)
        if stream is None or size is None:
            self._send_error_payload(
                ApiError(404, "evidence_unavailable",
                         f"no capture available for {truncate_for_echo(evidence_id)!r}")
            )
            return
        context.metrics.pcap_downloads.inc(1.0)
        self._start()
        try:
            self.send_response(200)
            self.send_header("Content-Type", CONTENT_TYPE_PCAP)
            self.send_header("Content-Length", str(size))
            self.send_header(
                "Content-Disposition",
                f'attachment; filename="{service.suggested_filename(evidence_id)}"',
            )
            self._common_headers()
            self.end_headers()
            if getattr(self, "_head_only", False):
                return
            while True:
                chunk = stream.read(service.STREAM_CHUNK_SIZE)
                if not chunk:
                    break
                self.wfile.write(chunk)
        finally:
            stream.close()

    def _static(self, path: str) -> None:
        static = getattr(self.server, "static_dir", None)  # type: ignore[attr-defined]
        if not static or not os.path.isdir(static):
            self._send_error_payload(
                ApiError(404, "api_only",
                         "no static dashboard build is served by the analytics API; "
                         "the testbed UI is served by the control API on a different port")
            )
            return
        safe = self._resolve_static(static, path)
        if safe is None:
            self._send(404, "application/json",
                       b'{"error":{"code":"not_found","detail":"static asset not found."}}\n')
            return
        content_type = "text/html" if safe.endswith(".html") else (
            "application/json" if safe.endswith(".json") else
            "application/javascript" if safe.endswith(".js") else
            "text/css" if safe.endswith(".css") else
            "image/svg+xml" if safe.endswith(".svg") else
            "application/octet-stream")
        with open(safe, "rb") as handle:
            body = handle.read()
        if getattr(self, "_head_only", False):
            self._send(200, content_type, b"", extra_headers={"Content-Length": str(len(body))})
            return
        self._send(200, content_type, body)

    def _resolve_static(self, static: str, path: str):
        name = path.lstrip("/") or "index.html"
        candidate = os.path.abspath(os.path.join(static, name))
        if not candidate.startswith(os.path.abspath(static) + os.sep) and candidate != os.path.abspath(static):
            return None
        if os.path.isfile(candidate):
            return candidate
        if name != "index.html":
            index = os.path.join(static, "index.html")
            if os.path.isfile(index):
                return index
        return None

    # -- response plumbing --------------------------------------------------

    def _common_headers(self) -> Dict[str, str]:
        """Headers every response carries, including the resolved CORS policy.

        Returns them (rather than sending them) so ``_send``/``_end``/the PCAP
        stream can all add them through one code path.
        """
        headers = {
            "Cache-Control": "no-store",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer",
            "X-Request-Id": self._request_id(),
        }
        policy = self._cors_policy()
        if policy is not None:
            apply_cors_headers(headers, policy, self._origin())
        return headers

    def _end(self, status: int, extra: Optional[Dict[str, str]] = None) -> None:
        """Send headers with no body (preflight)."""
        self.send_response(status)
        for name, value in self._common_headers().items():
            self.send_header(name, value)
        for name, value in (extra or {}).items():
            self.send_header(name, value)
        self.end_headers()

    def _send(
        self,
        status: int,
        content_type: str,
        body: bytes,
        extra_headers: Optional[Dict[str, str]] = None,
    ) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        for name, value in self._common_headers().items():
            self.send_header(name, value)
        for name, value in (extra_headers or {}).items():
            self.send_header(name, value)
        if getattr(self, "_head_only", False):
            # HEAD advertises the real length but sends no body.
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            return
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt: str, *args) -> None:
        sys.stderr.write(
            f"[analytics-api] {self.address_string()} {fmt % args}\n"
        )


class DashboardServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, addr, store, static_dir, phase10=None, cors=None, **kwargs) -> None:
        self.store = store
        self.static_dir = static_dir
        self.phase10 = phase10
        self.cors = cors
        super().__init__(addr, DashboardHandler, **kwargs)


def main(argv=None) -> None:
    parser = argparse.ArgumentParser(description="Analytics API (Server A)")
    parser.add_argument(
        "--host", default=None,
        help=f"bind address (default: ${ENV_HOST} or {DEFAULT_HOST})",
    )
    parser.add_argument(
        "--port", type=int, default=None,
        help=f"bind port (default: ${ENV_PORT} or {DEFAULT_PORT})",
    )
    parser.add_argument(
        "--allowed-origins", default=None,
        help=f"comma-separated CORS origin allow-list; wins over "
             f"${ENV_ALLOWED_ORIGINS}. Unset falls back to the loopback "
             f"development default. Use '*' only for a trusted same-site deploy.",
    )
    parser.add_argument("--plan", default=None, help="override the Phase-3 plan.json")
    parser.add_argument("--no-static", action="store_true",
                        help="serve API only (no dashboard/build)")
    parser.add_argument("--snapshot", default=None,
                        help="also write the full static snapshot to this path")
    parser.add_argument("--phase10", action="store_true",
                        help="attach the read-only /api/v1 live surface")
    parser.add_argument("--audit-journal", default=None,
                        help="expose this analysis audit journal (JSONL written "
                             "by correlation.audit.AuditJournal) read-only at "
                             "/api/v1/audit/*; the file is never written here")
    parser.add_argument("--capture-feed", default=None,
                        help="expose this xdp_monitor packet journal (JSONL write "
                             "side of the passive gateway capture) read-only at "
                             "/api/v1/capture/events; the file is never written "
                             f"here. Default: ${ENV_CAPTURE_FEED} or "
                             f"{DEFAULT_CAPTURE_FEED_PATH} when --phase10 is on")
    parser.add_argument("--evidence-root", default=os.getcwd(),
                        help="root directory that evidence references must "
                             "resolve inside before they are served as metadata "
                             "at /api/v1/evidence/* (default: the current "
                             "working directory)")
    parser.add_argument("--governance-journal", default=None,
                        help="write-side governance journal (append-only JSONL) "
                             "for assessment/recommendation/authorization/"
                             "approval events; an existing chain is verified and "
                             "continued, never rewritten")
    parser.add_argument("--observation-journal", default=None,
                        help="the observation journal the governance ledger's "
                             "audit_tap evidence references point into "
                             "(default: results/audit/events.jsonl)")
    args = parser.parse_args(argv)

    try:
        config = ServerConfig.resolve(
            host=args.host, port=args.port, allowed_origins=args.allowed_origins
        )
    except ValueError as error:
        raise SystemExit(f"[analytics-api] {error}") from None

    store = build_store(args.plan) if args.plan else build_store()
    print(f"[analytics-api] store built: {store.overview['total_assessments']} "
          f"assessments (deterministic, score/severity from Phase-6 RiskAssessment)")

    phase10 = None
    if args.phase10 or args.audit_journal or args.governance_journal:
        from .live import Phase10Context

        phase10 = Phase10Context()
        phase10.cors_policy = config.cors
        print("[phase10] passive-observation /api/v1 surface attached "
              "(no XDP enforcement action; dashboard remains read-only)")

    if args.audit_journal:
        from .audit_store import AuditJournalUnreadable, AuditStore

        audit_store = AuditStore(args.audit_journal)
        try:
            count = len(audit_store)
        except AuditJournalUnreadable as error:
            raise SystemExit(
                f"[analytics-api] refusing to serve the audit journal: {error}"
            ) from None
        phase10.attach_audit_store(audit_store)
        print(f"[analytics-api] audit journal attached ({count} analysis audit "
              f"event(s), read-only)")
        if not audit_store.available:
            print("[analytics-api] warning: journal path does not exist; audit "
                  "routes will report zero events (nothing will be fabricated)",
                  file=sys.stderr)

    if phase10 is not None:
        from .capture_feed import (
            CaptureFeedService,
            build_risk_index,
        )

        feed_path = (
            args.capture_feed
            or os.environ.get(ENV_CAPTURE_FEED)
            or DEFAULT_CAPTURE_FEED_PATH
        )
        feed = CaptureFeedService(feed_path, risk_index=build_risk_index(store))
        phase10.attach_capture_feed(feed)
        from .run_annex import CurrentRunAnnex

        phase10.annex = CurrentRunAnnex(store=store, feed=feed)
        # The annex also provides the experiment boundary: when gating is
        # enabled (real testbed deployment via start-live-analytics.sh) the
        # feed serves ONLY this experiment's journal bytes.
        feed.boundary_provider = phase10.annex.boundary
        gated = "1" if feed.experiment_gated else "0"
        print("[phase10] current-run annex attached (binds live journal "
              "packets to the current testbed experiment when its manifest is "
              "present and the feed is current)")
        print(f"[phase10] capture experiment boundary gate enabled={gated} "
              "(ANALYTICS_CAPTURE_EXPERIMENT_GATED)" if gated == "1" else
              "[phase10] capture experiment boundary gate disabled; live feed "
              "serves the full journal (legacy/demo/replay mode)")
        status = feed.status()
        if status["present"]:
            print(f"[phase10] capture feed attached ({status['events']} packet(s) "
                  f"in {status['source']}, read-only tail)")
        else:
            print(f"[analytics-api] capture feed configured but not present yet: "
                  f"{status['reason']}; the capture view will report its waiting "
                  f"state (nothing will be fabricated)", file=sys.stderr)

    if phase10 is not None and args.evidence_root:
        from .evidence_routes import register_journal_evidence

        phase10.pcap.registry.root = os.path.abspath(args.evidence_root)
        if phase10.audit_store is not None:
            summary = register_journal_evidence(
                phase10.audit_store, phase10.pcap.registry,
                root=phase10.pcap.registry.root,
            )
            print(f"[analytics-api] evidence registry: {summary['registered']} "
                  f"reference(s) from the journal are served as metadata "
                  f"(read-only)")
            phase10.note_evidence_registered(
                summary["registered"], phase10.pcap.registry.root)
            for entry in summary["skipped"]:
                print(f"[analytics-api] warning: evidence {entry['evidence_id']} "
                      f"not served ({entry['reason']})", file=sys.stderr)

    if phase10 is not None and args.governance_journal:
        from ..response.audit import (
            DEFAULT_OBSERVATION_JOURNAL,
            AuditIntegrityError,
            AuditLedger,
        )

        observation = args.observation_journal or DEFAULT_OBSERVATION_JOURNAL
        try:
            ledger = AuditLedger.open(args.governance_journal)
        except (AuditIntegrityError, ValueError) as error:
            raise SystemExit(
                f"[phase9] refusing to use governance journal: {error}"
            ) from None
        report = phase10.attach_governance(ledger, observation)
        if phase10.audit_store is not None:
            # The persisted ledger is what makes /api/v1/responses/<id>/evidence
            # resolvable: until it is attached the store reports the absence.
            phase10.audit_store.response_ledger = ledger
        print(f"[phase9] governance journal attached ({len(ledger)} event(s), "
              f"chain verified, append-only)")
        print(f"[phase9] observation link: {report['referenced']} audit_tap "
              f"reference(s) -> {report['resolved']} resolved, "
              f"{report['unresolved']} unresolved")

    if args.snapshot:
        path = snapshot(store, args.snapshot)
        print(f"[analytics-api] snapshot written: {path}")

    static_dir = None if args.no_static else STATIC_DIR
    if static_dir and not os.path.isdir(static_dir):
        print(f"[analytics-api] note: no static UI build here; serving the API "
              f"only (the testbed UI is served by the control API on a "
              f"different port)", file=sys.stderr)
        static_dir = None

    server = DashboardServer(
        (config.host, config.port), store, static_dir,
        phase10=phase10, cors=config.cors,
    )
    print(f"[analytics-api] listening on http://{config.host}:{config.port}"
          + (" + static ui" if static_dir else " (api only)"))
    print(f"[analytics-api] {describe(config)}")
    print(f"[analytics-api] read-only API: GET, HEAD, OPTIONS; every mutating "
          f"verb is 405. Contract: /api/v1/openapi.json")
    if config.host not in ("127.0.0.1", "::1", "localhost"):
        print(f"[analytics-api] WARNING: bound to {config.host} with no "
              f"authentication. Every route is read-only, but the full evidence "
              f"and audit surface is reachable by anything that can route here. "
              f"Restrict ${ENV_ALLOWED_ORIGINS} and put the port behind an "
              f"authenticating proxy.", file=sys.stderr)
    if not config.cors.is_configured():
        print(f"[analytics-api] warning: no origins are allowed, so browsers "
              f"will block every cross-origin read; set ${ENV_ALLOWED_ORIGINS}",
              file=sys.stderr)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[analytics-api] shutting down")
        server.shutdown()


if __name__ == "__main__":
    main()
