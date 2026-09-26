"""PHASE 8 — Dashboard HTTP service (stdlib only).

A zero-dependency JSON API server implementing the Phase-8 REST contract plus
static hosting of the built dashboard (Vite output) when present:

    python -m correlation.api.app [--port 8000] [--host 127.0.0.1]
                                  [--plan <path>] [--no-static]
                                  [--snapshot <out/dashboard_snapshot.json>]

The endpoint handlers live in ``.routes`` (pure functions; tested without
sockets). This module is a thin stdlib transport: it routes GET paths to JSON
payloads and serves the static build directory read-only. It does not modify
any backend domain object and ports no decision logic.

Phase 10 adds the observable-only ``/api/v1`` surface (health, Prometheus
metrics, traffic-generator status, evidence/PCAP metadata) behind
:func:`handle_combined`. The dashboard stays READ-ONLY and PASSIVE-ONLY: v1
accepts no action, approval or target inputs, and no XDP enforcement action is
wired into the deployed application. Run with ``--phase10`` to attach a live
``Phase10Context``.

A FastAPI deployment could reuse ``handle_get`` unchanged (it is transport
agnostic); the JSON contract is documented in PHASE_8_DASHBOARD_REPORT.md.
"""

import argparse
import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Optional, Tuple
from urllib.parse import parse_qs, unquote

from .pcap import PcapService
from .routes import ApiError, handle_get, serializable
from .store import AssessmentStore, build_store
from .v1 import (
    CONTENT_TYPE_PCAP,
    handle_v1_pcap,
    handle_v1_get,
    is_v1_path,
)

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8000
SNAPSHOT_PATH = os.path.join(
    os.path.dirname(__file__), "..", "..", "out", "dashboard_snapshot.json"
)
STATIC_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "dashboard", "build")


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


def handle_combined(store, context, path: str, params: Optional[dict] = None) -> Any:
    """Dispatch /api (phase 8) or /api/v1 (phase 10) without file I/O here.

    ``params`` is the parsed query string; it is forwarded to the /api/v1
    handlers (the audit routes filter on it). The Phase-8 contract is path-only
    and is unaffected.
    """
    if is_v1_path(path):
        if context is None:
            raise ApiError(503, "phase10_unavailable",
                           "/api/v1 requires --phase10 (live context not attached)")
        return handle_v1_get(context, path, params)
    return handle_get(store, path)


class DashboardHandler(BaseHTTPRequestHandler):
    server_version = "SIHColayerPhase8"

    def do_GET(self) -> None:  # noqa: N802
        raw = unquote(self.path)
        path, _, query = raw.partition("?")
        self._query = parse_qs(query, keep_blank_values=True) if query else {}
        if path.startswith("/api/"):
            self._api(path)
        else:
            self._static(path)

    def do_POST(self) -> None:  # noqa: N802
        self._send(405, "application/json",
                   b'{"error":{"code":"method_not_allowed","detail":"POST is not supported; the dashboard API is read-only."}}\n')

    def do_PUT(self) -> None:  # noqa: N802
        self.do_POST()

    def do_DELETE(self) -> None:  # noqa: N802
        self.do_POST()

    # -- helpers ------------------------------------------------------------

    def _phase10(self):
        return getattr(self.server, "phase10", None)  # type: ignore[attr-defined]

    def _api(self, path: str) -> None:
        context = self._phase10()
        if is_v1_path(path):
            self._api_v1(path, context)
            return
        try:
            payload = handle_get(self.server.store, path)  # type: ignore[attr-defined]
        except ApiError as error:
            self._send(error.status, "application/json", to_json_bytes(error.payload()))
            return
        self._send(200, "application/json", to_json_bytes(payload))

    def _api_v1(self, path: str, context) -> None:
        params = getattr(self, "_query", {}) or {}
        # parse_qs yields lists; collapse the common single-value case so
        # handlers see scalars, and keep repeated params as lists.
        collapsed = {
            key: (values[0] if len(values) == 1 else values)
            for key, values in params.items()
        }
        try:
            if "/pcap" in path and path.startswith("/api/v1/evidence/"):
                descriptor = handle_v1_pcap(context, path.split("/api/v1/evidence/")[1].split("/")[0])
                evidence_id = path.split("/api/v1/evidence/")[1].split("/")[0]
                data = context.pcap.download(evidence_id)
                context.metrics.pcap_downloads.inc(1.0)
                if data is None:
                    raise ApiError(404, "evidence_unavailable",
                                   f"no capture available for {evidence_id!r}")
                self._send(200, CONTENT_TYPE_PCAP, data)
                return
            content, content_type = handle_v1_get(context, path, collapsed)
        except ApiError as error:
            self._send(error.status, "application/json", to_json_bytes(error.payload()))
            return
        if isinstance(content, str):
            self._send(200, content_type, content.encode("utf-8"))
        else:
            self._send(200, content_type, to_json_bytes(content))

    def _static(self, path: str) -> None:
        static = getattr(self.server, "static_dir", None)  # type: ignore[attr-defined]
        if not static or not os.path.isdir(static):
            self._send(404, "application/json",
                       b'{"error":{"code":"api_only","detail":"no static dashboard build available; run the Vite build or use the API directly."}}\n')
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
            self._send(200, content_type, handle.read())

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

    def _send(self, status: int, content_type: str, body: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt: str, *args) -> None:
        sys.stderr.write(f"[phase8] {self.address_string()} {fmt % args}\n")


class DashboardServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, addr, store, static_dir, phase10=None, **kwargs) -> None:
        self.store = store
        self.static_dir = static_dir
        self.phase10 = phase10
        super().__init__(addr, DashboardHandler, **kwargs)


def main(argv=None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
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

    store = build_store(args.plan) if args.plan else build_store()
    print(f"[phase8] store built: {store.overview['total_assessments']} assessments "
          f"(deterministic, score/severity from Phase-6 RiskAssessment)")

    phase10 = None
    if args.phase10 or args.audit_journal or args.governance_journal:
        from .live import Phase10Context
        phase10 = Phase10Context()
        print("[phase10] passive-observation /api/v1 surface attached "
              "(no XDP enforcement action; dashboard remains read-only)")

    if args.audit_journal:
        from .audit_store import AuditJournalUnreadable, AuditStore

        audit_store = AuditStore(args.audit_journal)
        try:
            count = len(audit_store)
        except AuditJournalUnreadable as error:
            raise SystemExit(
                f"[phase8] refusing to serve {args.audit_journal}: {error}"
            ) from None
        phase10.attach_audit_store(audit_store)
        print(f"[phase8] audit journal attached: {args.audit_journal} "
              f"({count} analysis audit event(s), read-only)")
        if not audit_store.available:
            print("[phase8] warning: journal path does not exist; audit routes "
                  "will report zero events (nothing will be fabricated)",
                  file=sys.stderr)

    if phase10 is not None and args.evidence_root:
        from .evidence_routes import register_journal_evidence

        phase10.pcap.registry.root = os.path.abspath(args.evidence_root)
        if phase10.audit_store is not None:
            summary = register_journal_evidence(
                phase10.audit_store, phase10.pcap.registry,
                root=phase10.pcap.registry.root,
            )
            print(f"[phase8] evidence registry: {summary['registered']} "
                  f"reference(s) from the journal are served as metadata "
                  f"under {phase10.pcap.registry.root} (read-only)")
            phase10.note_evidence_registered(
                summary["registered"], phase10.pcap.registry.root)
            for entry in summary["skipped"]:
                print(f"[phase8] warning: evidence {entry['evidence_id']} not "
                      f"served ({entry['reason']})", file=sys.stderr)

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
                f"[phase9] refusing to use governance journal "
                f"{args.governance_journal}: {error}"
            ) from None
        report = phase10.attach_governance(ledger, observation)
        if phase10.audit_store is not None:
            # The persisted ledger is what makes /api/v1/responses/<id>/evidence
            # resolvable: until it is attached the store reports the absence.
            phase10.audit_store.response_ledger = ledger
        print(f"[phase9] governance journal attached: {args.governance_journal} "
              f"({len(ledger)} event(s), chain verified, append-only)")
        print(f"[phase9] observation link: {report['referenced']} audit_tap "
              f"reference(s) -> {report['resolved']} resolved, "
              f"{report['unresolved']} unresolved in {observation}")
        if report["unresolved"]:
            print("[phase9] warning: some governance evidence references do "
                  "not resolve in the observation journal; they are reported, "
                  "not repaired", file=sys.stderr)

    if args.snapshot:
        path = snapshot(store, args.snapshot)
        print(f"[phase8] snapshot written: {path}")

    static_dir = None if args.no_static else STATIC_DIR
    if static_dir and not os.path.isdir(static_dir):
        print(f"[phase8] warning: static build not found at {static_dir} "
              f"(API serving only; run `npm run build` in dashboard/)", file=sys.stderr)
        static_dir = None

    server = DashboardServer((args.host, args.port), store, static_dir, phase10=phase10)
    print(f"[phase8] dashboard API listening on http://{args.host}:{args.port}"
          + (" + static ui" if static_dir else " (api only)"))
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[phase8] shutting down")
        server.shutdown()


if __name__ == "__main__":
    main()