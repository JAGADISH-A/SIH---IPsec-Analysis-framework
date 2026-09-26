"""Phase 10 — /api/v1 route handlers (pure functions, no sockets).

Complements the Phase-8 contract WITHOUT touching it:

    GET /api/v1/health                      -> component health
    GET /api/v1/metrics                     -> Prometheus text exposition
    GET /api/v1/traffic-generator           -> traffic generator status
    GET /api/v1/evidence                    -> registered evidence references
    GET /api/v1/evidence/{evidence_id}      -> evidence reference + integrity
    GET /api/v1/evidence/{evidence_id}/pcap -> binary PCAP download (or 404)
    GET /api/v1/runs/{run_id}/evidence      -> evidence per analysis window
    GET /api/v1/responses/{id}/evidence     -> evidence on a response lifecycle
    GET /api/v1/audit/events[/{event_id}]   -> analysis audit journal (read-only)
    GET /api/v1/audit/events/{event_id}/evidence -> evidence behind a stage
    GET /api/v1/audit/runs                  -> per-run audit summaries
    GET /api/v1/runs/{run_id}/audit         -> ordered audit trail for a run
    GET /api/v1/governance[/{event_id}]     -> persisted governance chain

The audit surface is a QUERY layer over the existing
``correlation.audit.AuditJournal``: it reads persisted records and returns them
verbatim, so the frontend reads the same authoritative evidence the analysis
pipeline wrote. See ``audit_routes`` for the integrity rules.

The governance surface is the query side of the *persisted* response ledger
(``correlation.response.audit.AuditLedger(path=...)``) -- the write side that
records assessment/recommendation/authorization/approval decisions to disk. It
is read-only here like everything else: the dashboard still approves nothing.

The dashboard remains read-only: NO endpoint accepts an action, an approval
or a target; enforcement stays behind the two-layer gateway.
"""

from dataclasses import dataclass
from typing import Any, Dict, Mapping, Optional

from .audit_routes import handle_audit_get, is_audit_path
from .evidence_routes import (
    EVIDENCE_LIST_PATH,
    RESPONSE_EVIDENCE_PREFIX,
    RUN_EVIDENCE_PREFIX,
    handle_evidence_id,
    handle_evidence_list,
    handle_event_evidence,
    handle_governance_event,
    handle_governance_list,
    handle_response_evidence,
    handle_run_evidence,
)
from .pcap import PcapService
from .routes import ApiError

CONTENT_TYPE_JSON = "application/json"
CONTENT_TYPE_PROMETHEUS = "text/plain; version=0.0.4; charset=utf-8"
CONTENT_TYPE_PCAP = "application/vnd.tcpdump.pcap"

HEALTH_PATH = "/api/v1/health"
METRICS_PATH = "/api/v1/metrics"
TRAFFIC_GENERATOR_PATH = "/api/v1/traffic-generator"
EVIDENCE_PREFIX = "/api/v1/evidence/"
GOVERNANCE_PATH = "/api/v1/governance"
GOVERNANCE_PREFIX = "/api/v1/governance/"


def _evidence_id(path: str) -> str:
    remainder = path[len(EVIDENCE_PREFIX):]
    if "/" in remainder:
        evidence_id, sub = remainder.split("/", 1)
        if sub != "pcap":
            raise ApiError(
                404, "unknown_resource",
                f"unknown evidence sub-resource {sub!r}; expected 'pcap'",
            )
        return evidence_id
    return remainder


def handle_v1_health(health) -> Dict[str, Any]:
    return health.to_dict()


def handle_v1_metrics(metrics) -> str:
    return metrics.render()


def handle_v1_traffic_generator(monitor) -> Dict[str, Any]:
    status = monitor.status()
    return {
        "api": "traffic-generator",
        "status": status,
    }


def handle_v1_evidence(context, evidence_id: str) -> Dict[str, Any]:
    """One evidence reference plus its read-only integrity status."""
    return handle_evidence_id(context, evidence_id)


def handle_v1_pcap(context, evidence_id: str) -> Dict[str, Any]:
    """Return a download descriptor; the transport layer streams the bytes."""
    pcap: PcapService = context.pcap
    registry = pcap.registry
    if not registry.has(evidence_id):
        raise ApiError(404, "evidence_not_found", f"no evidence {evidence_id!r}")
    if registry.resolve(evidence_id) is None:
        raise ApiError(
            403, "evidence_unavailable",
            f"evidence {evidence_id!r} cannot be served",
        )
    return {"evidence_id": evidence_id}


def handle_v1_audit(context, path: str, params: Optional[Mapping[str, Any]] = None):
    """Read-only audit queries. 503 when no journal is wired, never invented."""
    store = getattr(context, "audit_store", None)
    if store is None:
        raise ApiError(
            503, "audit_unavailable",
            "no analysis audit journal is attached; start the server with "
            "--audit-journal <path> (or --phase10) to expose audit evidence",
        )
    return handle_audit_get(store, path, dict(params or {}))


def handle_v1_get(context, path: str, params: Optional[Mapping[str, Any]] = None):
    """Dispatch one /api/v1 path; returns (content, content_type) or raises.

    ``params`` is the already-parsed query string. It is optional so existing
    callers and the Phase-10 tests keep working unchanged.
    """
    if path.startswith(HEALTH_PATH):
        return handle_v1_health(context.health), CONTENT_TYPE_JSON
    if path == METRICS_PATH:
        return handle_v1_metrics(context.metrics), CONTENT_TYPE_PROMETHEUS
    if path == TRAFFIC_GENERATOR_PATH:
        return handle_v1_traffic_generator(context.traffic_generator), CONTENT_TYPE_JSON
    if is_audit_path(path):
        # The evidence sub-resource answers "what evidence backed this stage?"
        # for one recorded event; everything else audit-shaped goes to the
        # journal query layer.
        prefix = "/api/v1/audit/events/"
        if path.startswith(prefix) and path.endswith("/evidence"):
            remainder = path[len(prefix):-len("/evidence")]
            if remainder and "/" not in remainder:
                return handle_event_evidence(context, remainder), CONTENT_TYPE_JSON
        return handle_v1_audit(context, path, params), CONTENT_TYPE_JSON
    if path == GOVERNANCE_PATH:
        return handle_governance_list(context, params), CONTENT_TYPE_JSON
    if path.startswith(GOVERNANCE_PREFIX):
        remainder = path[len(GOVERNANCE_PREFIX):]
        if remainder and "/" not in remainder:
            return handle_governance_event(context, remainder), CONTENT_TYPE_JSON
        raise ApiError(404, "unknown_route", f"unknown route {path!r}")
    if path == EVIDENCE_LIST_PATH:
        return handle_evidence_list(context, params), CONTENT_TYPE_JSON
    if path.startswith(RESPONSE_EVIDENCE_PREFIX):
        remainder = path[len(RESPONSE_EVIDENCE_PREFIX):]
        if remainder.endswith("/evidence") and "/" not in remainder[:-len("/evidence")]:
            return (
                handle_response_evidence(context, remainder[:-len("/evidence")]),
                CONTENT_TYPE_JSON,
            )
        raise ApiError(404, "unknown_route", f"unknown route {path!r}")
    if path.startswith(EVIDENCE_PREFIX):
        remainder = path[len(EVIDENCE_PREFIX):]
        if not remainder:
            raise ApiError(404, "invalid_route", f"unknown route {path!r}")
        if "/" not in remainder:
            return handle_v1_evidence(context, remainder), CONTENT_TYPE_JSON
        evidence_id, sub = remainder.split("/", 1)
        if sub == "pcap":
            # transport reads + streams the bytes (handled by app layer)
            return handle_v1_pcap(context, evidence_id), CONTENT_TYPE_JSON
        raise ApiError(404, "unknown_resource",
                       f"unknown evidence sub-resource {sub!r}; expected 'pcap'")
    if path.startswith(RUN_EVIDENCE_PREFIX):
        remainder = path[len(RUN_EVIDENCE_PREFIX):]
        if remainder.endswith("/evidence"):
            run_id = remainder[:-len("/evidence")]
            if run_id and "/" not in run_id:
                return handle_run_evidence(context, run_id, params), CONTENT_TYPE_JSON
        raise ApiError(404, "unknown_route", f"unknown route {path!r}")
    raise ApiError(404, "unknown_route", f"unknown route {path!r}")


def is_v1_path(path: str) -> bool:
    return path.startswith("/api/v1/") or path == "/api/v1"