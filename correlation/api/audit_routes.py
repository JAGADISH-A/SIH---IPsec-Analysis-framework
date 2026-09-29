"""Audit query routes -- pure functions over :class:`AuditStore`.

Follows the conventions already established in this package:

* handlers are PURE functions returning plain dicts, tested without sockets;
* failures raise :class:`~correlation.api.routes.ApiError` with a status, a
  stable machine code and a human detail;
* a detail route returns the record itself, a list route returns a small
  envelope (matching ``/api/assessments`` vs ``/api/assessments/{id}``).

Routes added, under the existing ``/api/v1`` prefix::

    GET /api/v1/audit/events          list + filter + page
    GET /api/v1/audit/events/{id}     one event, by its existing event_id
    GET /api/v1/audit/runs            per-run summaries
    GET /api/v1/runs/{run_id}/audit   ordered lifecycle trail for a run

Read-only guarantees
--------------------
Every route here is a projection of persisted journal records:

* ``event_id`` is read, never regenerated (``AuditEvent.from_dict`` re-derives
  and verifies it, so a tampered record 404s/500s rather than being served);
* ``source`` and ``authoritative`` are echoed verbatim, so ``comparison-engine``
  is never presented as ``observation/state-builder`` and ``ml`` is never
  presented as authoritative;
* a missing stage, reference or value is returned as ``null`` / omitted, never
  backfilled from expected state;
* no route accepts a target, action or approval, and no route can reach the
  response engine or XDP. ``do_POST``/``PUT``/``DELETE`` already return 405 in
  ``app.py``, and these handlers are only ever reached from ``do_GET``.
"""

from __future__ import annotations

import sys
from typing import Any, Dict, List, Optional

from .audit_store import (
    AUDIT_STAGE_ORDER,
    AuditJournalUnreadable,
    AuditQuery,
    AuditStore,
)
from .redact import bounded_echo
from .routes import ApiError

AUDIT_EVENTS_PATH = "/api/v1/audit/events"
AUDIT_RUNS_PATH = "/api/v1/audit/runs"
RUN_AUDIT_PREFIX = "/api/v1/runs/"

API_NAME = "audit"


def _query_or_400(params: Optional[Dict[str, Any]]) -> AuditQuery:
    """Build a query, mapping a bad filter value onto a structured 400.

    The ``ValueError`` text only ever contains the field name and the value we
    rejected, both of which the caller supplied, so echoing it is safe -- but
    it is still bounded in case a caller passes something very long.
    """
    try:
        return AuditQuery.from_params(params)
    except ValueError as exc:
        raise ApiError(400, "invalid_query_parameter", bounded_echo(exc)) from None


def _guard(read):
    """Turn a journal read failure into a structured 500, never partial data.

    The exception text is deliberately NOT included in the response. A
    parse failure can carry a host path or the content of the corrupt record,
    and this API is unauthenticated. The client gets the fact and a request id;
    the detail stays in the server log.
    """
    try:
        return read()
    except AuditJournalUnreadable as exc:
        sys.stderr.write(
            f"[analytics-api] audit journal unreadable: {exc!r}\n"
        )
        raise ApiError(
            500, "audit_journal_unreadable",
            "the audit journal could not be read as intact evidence; it is "
            "reported as unavailable rather than partially served. Check the "
            "analytics API log for the parse error.",
        ) from None


def _summary(event) -> Dict[str, Any]:
    """Compact per-event listing row.

    Deliberately not the full payload: the list route is for navigation, and
    ``/api/v1/audit/events/{event_id}`` serves the complete record. ``source``
    and ``authoritative`` are included here because a client must be able to
    see provenance without a second request per row.
    """
    identity = event.identity
    stage = {
        "expected_state": "expected",
        "observed_state": "observed",
        "comparison": "comparison",
        "ml_result": "ml",
        "ml_failure": "ml",
        "risk_assessment": "risk",
        "explanation": "explanation",
        "evidence": "evidence",
        "response_proposal": "response",
    }.get(event.event_type)
    return {
        "event_id": event.event_id,
        "event_type": event.event_type,
        "stage": stage,
        "source": event.source,
        "authoritative": event.authoritative,
        "recorded_at": event.recorded_at,
        "dataset_run_id": identity.dataset_run_id,
        "sequence": identity.sequence,
        "experiment_id": identity.experiment_id,
        "attempt_number": identity.attempt_number,
        "window_index": identity.window_index,
        "window_start_ns": identity.window_start_ns,
        "window_end_ns": identity.window_end_ns,
        "response_proposal_ref": event.response_proposal_ref,
    }


def handle_audit_events(store: AuditStore, params: Optional[Dict[str, Any]] = None):
    """List + filter + page audit events.

    Filters: ``run_id``, ``experiment_id``, ``sequence``, ``attempt_number``,
    ``event_type`` (repeatable or comma-separated), ``source``,
    ``authoritative`` (``true``/``false``), ``window_index``,
    ``window_from_ns``/``window_to_ns``, ``event_id``, plus ``limit``/``offset``.
    """
    query = _query_or_400(params)
    page, total = _guard(lambda: store.list_events(query))
    return {
        "api": f"{API_NAME}-events",
        "read_only": True,
        "source_of_truth": "correlation.audit.AuditJournal (queried, never rewritten)",
        "count": len(page),
        "total": total,
        "limit": query.limit,
        "offset": query.offset,
        "filters": query.describe(),
        "stage_order": list(AUDIT_STAGE_ORDER),
        "events": [_summary(event) for event in page],
    }


def handle_audit_event(store: AuditStore, event_id: str):
    """One event by its existing ``event_id``, returned as persisted.

    The body is the record's own ``to_dict()``: same ``event_id``, same
    ``source``, same ``authoritative`` flag, same payload. Nothing is recomputed
    or re-labelled, so a frontend cannot read an audit event as evidence it is
    not.
    """
    if not event_id:
        raise ApiError(404, "invalid_route", "no audit event id in path")
    event = _guard(lambda: store.get_event(event_id))
    if event is None:
        raise ApiError(404, "audit_event_not_found", f"no audit event {event_id!r}")
    return event.to_dict()


def gated_empty_audit_payload(reason: str) -> Dict[str, Any]:
    """Envelope for a present-but-closed live audit tail.

    Same idea as the capture feed's ``_gated_empty_payload``: the journal may
    hold thousands of recorded events, but with no experiment active on this
    journal zero rows are LIVE. The response reports ``current: false`` and the
    reason; it never divulges recorded-history rows as if they were current.
    """
    return {
        "api": "audit-events-v1",
        "read_only": True,
        "source_of_truth": "correlation.audit.AuditJournal (queried, never rewritten)",
        "state": "gated-closed",
        "current": False,
        "reason": reason,
        "count": 0,
        "total": 0,
        "events": [],
    }


def handle_audit_runs(store: AuditStore, params: Optional[Dict[str, Any]] = None):
    """Per-run summaries so a client can discover which runs have evidence."""
    runs = _guard(store.runs)
    wanted = (params or {}).get("run_id")
    if wanted:
        runs = [item for item in runs if item["run_id"] == wanted]
    return {
        "api": f"{API_NAME}-runs",
        "read_only": True,
        "count": len(runs),
        "total": len(runs),
        "runs": runs,
    }


def handle_run_audit(store: AuditStore, run_id: str, params: Optional[Dict[str, Any]] = None):
    """Ordered audit trail for one run, grouped per window.

    Each window lists only the stages that actually have a recorded event, in
    :data:`~correlation.api.audit_store.AUDIT_STAGE_ORDER`. Missing stages are
    omitted rather than emitted empty, so a client can tell "not recorded" from
    "recorded as nothing".

    ``response`` is a read-only join: it reports the actual authorization and
    execution records when a response ledger is attached, and reports that it
    is unavailable otherwise. It never synthesises them.
    """
    if not run_id or run_id.endswith("/"):
        raise ApiError(404, "invalid_route", f"unknown route for run {run_id!r}")
    query = _query_or_400(params)
    trail = _guard(lambda: store.run_trail(run_id, query))
    if trail is None:
        raise ApiError(404, "audit_run_not_found", f"no audit trail for run {run_id!r}")

    windows: List[Dict[str, Any]] = []
    for window in trail["windows"]:
        stages = []
        for entry in window.stages:
            events = [_summary(event) for event in entry["events"]]
            stage_payload: Dict[str, Any] = {
                "stage": entry["stage"],
                "present": True,
                "event_count": len(events),
                "events": events,
            }
            # A proposal stage carries a reference into the response layer. Join
            # read-only; the response layer's own ledger remains the only
            # authority for authorization/execution.
            ref = events[0].get("response_proposal_ref") if events else None
            if ref:
                stage_payload["response_lifecycle"] = store.response_lifecycle(ref)
            stages.append(stage_payload)
        windows.append({
            "window_index": window.window_index,
            "window_start_ns": window.window_start_ns,
            "window_end_ns": window.window_end_ns,
            "stages": stages,
            "stage_names": [entry["stage"] for entry in stages],
        })

    return {
        "api": f"{API_NAME}-run-trail",
        "read_only": True,
        "run_id": trail["run_id"],
        "window_count": trail["window_count"],
        "event_count": trail["event_count"],
        # Pagination is real, not echoed: the store slices the filtered event
        # set. event_count is the total; returned_event_count is this page.
        "returned_event_count": trail.get("returned_event_count"),
        "limit": trail.get("limit"),
        "offset": trail.get("offset", 0),
        "has_more": trail.get("has_more", False),
        "stage_order": trail["stage_order"],
        "stages_present": trail["stages_present"],
        "filters": query.describe(),
        "windows": windows,
    }


def _run_audit_id(path: str) -> Optional[str]:
    """Extract ``run_id`` from ``/api/v1/runs/{run_id}/audit`` (else None)."""
    remainder = path[len(RUN_AUDIT_PREFIX):]
    parts = remainder.split("/")
    if len(parts) != 2 or not parts[0] or parts[1] != "audit":
        return None
    return parts[0]


def is_audit_path(path: str) -> bool:
    """True for a path this module owns, so ``v1`` can delegate cleanly."""
    return path.startswith(AUDIT_EVENTS_PATH) or path.startswith(AUDIT_RUNS_PATH) \
        or _run_audit_id(path) is not None


def handle_audit_get(store: AuditStore, path: str, params: Optional[Dict[str, Any]] = None):
    """Dispatch one audit path; returns a JSON-ready dict or raises ApiError."""
    if path == AUDIT_EVENTS_PATH:
        return handle_audit_events(store, params)
    if path == AUDIT_RUNS_PATH:
        return handle_audit_runs(store, params)
    if path.startswith(AUDIT_EVENTS_PATH + "/"):
        event_id = path[len(AUDIT_EVENTS_PATH) + 1:]
        if "/" in event_id:
            raise ApiError(
                404, "unknown_resource",
                f"unknown audit sub-resource {event_id.split('/', 1)[1]!r}",
            )
        return handle_audit_event(store, event_id)
    run_id = _run_audit_id(path)
    if run_id is not None:
        return handle_run_audit(store, run_id, params)
    raise ApiError(404, "unknown_route", f"unknown route {path!r}")
