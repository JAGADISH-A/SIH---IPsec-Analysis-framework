"""Resource discovery for the frontend: runs, assessments, findings.

Why this module exists
----------------------
The audit found the frontend could not restore its state after a browser
refresh, because every analytics route it needed was either absent or
id-addressed with no way to *enumerate* what exists.  The frontend held the
only copy of "which run am I looking at" in JavaScript memory.

This module adds enumeration endpoints so the authoritative state stays in the
backend and the browser can re-discover it on load:

    GET /api/v1/runs                      runs that have recorded analysis
    GET /api/v1/runs/{run_id}             one run summary
    GET /api/v1/assessments               assessment rows (paged, filterable)
    GET /api/v1/assessments/{id}          one assessment bundle
    GET /api/v1/assessments/{id}/findings findings for one assessment
    GET /api/v1/findings                  every finding, flat (paged, filterable)

Authority boundary
------------------
Every field here is a **projection of something the analysis engine already
produced**:

* runs come from :meth:`correlation.api.audit_store.AuditStore.runs`, i.e. runs
  that actually have persisted audit events.  No run is invented, and a run
  that has not been recorded is not listed.
* assessments come from the existing ``AssessmentStore`` -- the same objects
  ``GET /api/assessments`` already serves.  Nothing is recomputed.
* findings are the ``risk.findings[]`` entries the Phase-6 risk engine emitted,
  copied verbatim.  This module does not score, rank, suppress or re-derive a
  single one.

There are deliberately NO mutation routes.  No ``resolve``, ``dismiss``,
``override`` or ``acknowledge``: findings are read-only here, and the durable
home of any human decision remains the governance ledger
(``correlation.response.audit.AuditLedger``), written by the response engine
and never by an HTTP handler.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from .routes import (
    ApiError,
    MAX_PAGE_LIMIT,
    page_params,
    paged_envelope,
)

API_DISCOVERY = "discovery"

SEVERITY_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")


# ---------------------------------------------------------------------------
# runs
# ---------------------------------------------------------------------------

def _run_summaries(store) -> List[Dict[str, Any]]:
    """Run summaries from the audit journal, or a structured 503 without one.

    The audit journal is the only place a run's identity is durably recorded,
    so it is the authoritative source for "which runs exist".  When no journal
    is attached the honest answer is "unknown", not an empty list that looks
    like "there are no runs".
    """
    if store is None:
        raise ApiError(
            503, "runs_unavailable",
            "no analysis audit journal is attached, so the set of analysis "
            "runs is unknown; start the server with --audit-journal <path> "
            "(or --phase10) to expose run discovery",
        )
    return list(store.runs())


def handle_runs(store, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Discovery + pagination for analysis runs.

    Filters: ``run_id`` (exact).  Pagination: ``limit``/``offset``.
    """
    limit, offset = page_params(params)
    runs = _run_summaries(store)
    wanted = (params or {}).get("run_id")
    if wanted:
        runs = [item for item in runs if item.get("run_id") == wanted]
    runs.sort(key=lambda item: str(item.get("run_id", "")))
    return paged_envelope(
        f"{API_DISCOVERY}-runs", runs, limit, offset, key="runs",
        read_only=True,
        source_of_truth=(
            "correlation.audit.AuditJournal (queried, never rewritten)"
        ),
    )


def handle_run(store, run_id: str) -> Dict[str, Any]:
    """One run summary by id."""
    if not run_id:
        raise ApiError(404, "invalid_route", "no run id in path")
    for item in _run_summaries(store):
        if item.get("run_id") == run_id:
            return {
                "api": f"{API_DISCOVERY}-run",
                "read_only": True,
                "run": item,
            }
    raise ApiError(404, "run_not_found", f"no analysis run {run_id!r}")


# ---------------------------------------------------------------------------
# assessments
# ---------------------------------------------------------------------------

def _assessment_rows(store) -> List[Dict[str, Any]]:
    """One compact row per assessment, taken from the store's own headers."""
    return [dict(row) for row in store.headers]


def handle_assessments_v1(
    store, params: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """Paged, filterable assessment rows.

    Filters are limited to fields that genuinely exist on a header row:
    ``scenario``, ``severity``, ``mode``, ``address_family``,
    ``security_posture``, ``traffic_profile``, ``configuration_id``,
    ``dataset_run_id``, ``sequence``, ``window_index``.  No filter is invented
    for data the store does not carry.
    """
    limit, offset = page_params(params)
    rows = _assessment_rows(store)
    for field_name in (
        "scenario", "severity", "mode", "address_family",
        "security_posture", "traffic_profile", "configuration_id",
        "dataset_run_id",
    ):
        wanted = (params or {}).get(field_name)
        if wanted:
            rows = [r for r in rows if str(r.get(field_name, "")) == str(wanted)]
    for field_name in ("sequence", "window_index"):
        wanted = (params or {}).get(field_name)
        if wanted not in (None, ""):
            try:
                needle = int(str(wanted))
            except (TypeError, ValueError):
                raise ApiError(
                    400, "invalid_query_parameter",
                    f"{field_name} must be an integer, got {wanted!r}",
                ) from None
            rows = [r for r in rows if r.get(field_name) == needle]

    if params and str((params or {}).get("sort", "")).lower() in ("", "risk", "risk_score"):
        order = str((params or {}).get("order", "desc")).lower()
        reverse = order != "asc"
        rows = sorted(
            rows,
            key=lambda r: (r.get("risk_score") if r.get("risk_score") is not None else -1),
            reverse=reverse,
        )

    return paged_envelope(
        f"{API_DISCOVERY}-assessments", rows, limit, offset, key="assessments",
        read_only=True,
        overview=dict(store.overview),
        severity_order=list(SEVERITY_ORDER),
    )


def handle_assessment_v1(store, assessment_id: str) -> Dict[str, Any]:
    """The full backend-produced bundle for one assessment."""
    from .routes import _bundle_or_404  # reuse the canonical 404 semantics

    return _bundle_or_404(store, assessment_id)


# ---------------------------------------------------------------------------
# findings
# ---------------------------------------------------------------------------

def _provenance(bundle: Dict[str, Any]) -> Dict[str, Any]:
    """Assessment/run identity for a finding, without shadowing finding fields.

    A finding already carries its own ``sequence`` and ``window_index`` (those
    describe the *capture*, not the assessment window). Overwriting them with
    the bundle's would silently rewrite evidence provenance, so a key is only
    filled in when the finding does not already have it.
    """
    identity = bundle.get("identity") or {}
    risk = bundle.get("risk") or {}
    return {
        "assessment_id": bundle.get("assessment_id"),
        "dataset_run_id": identity.get("dataset_run_id"),
        "scenario": bundle.get("scenario"),
        "sequence": identity.get("sequence"),
        "window_index": identity.get("window_index"),
        "risk_policy_version": risk.get("risk_policy_version"),
    }


def _finding_row(bundle: Dict[str, Any], finding: Dict[str, Any]) -> Dict[str, Any]:
    """One finding, copied verbatim plus provenance that does not shadow it."""
    row = dict(finding)
    for key, value in _provenance(bundle).items():
        row.setdefault(key, value)
    row["read_only"] = True
    return row


def _severity_key(row: Dict[str, Any]):
    severity = row.get("severity")
    rank = SEVERITY_ORDER.index(severity) if severity in SEVERITY_ORDER else len(SEVERITY_ORDER)
    return (rank, str(row.get("finding_id", "")))


def _flatten_findings(store) -> List[Dict[str, Any]]:
    """Copy every backend-produced finding out of its assessment bundle.

    The finding dict itself is copied, not reshaped, so any field the risk
    engine emits reaches the frontend. The added keys are provenance needed to
    navigate back: which assessment and which run it came from.
    """
    out: List[Dict[str, Any]] = []
    for bundle in store.bundles.values():
        for finding in (bundle.get("risk") or {}).get("findings") or ():
            out.append(_finding_row(bundle, finding))
    # Stable, meaningful default order: worst first, then by id so paging is
    # deterministic across requests.
    out.sort(key=_severity_key)
    return out


def handle_findings(
    store, params: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """Every finding across every assessment, flat, paged and filterable.

    Filters: ``severity`` (repeatable/comma-separated), ``category``,
    ``assessment_id``, ``dataset_run_id``, ``model_version``.  Each is backed by
    a field the risk engine actually emits.

    There is no mutation counterpart.  This endpoint is read-only by
    construction: the module defines no write route and the transport answers
    405 for every mutating verb.
    """
    limit, offset = page_params(params, max_limit=MAX_PAGE_LIMIT)
    rows = _flatten_findings(store)

    for field_name in ("severity", "category"):
        raw = (params or {}).get(field_name)
        if raw:
            wanted = {
                part.strip() for part in str(raw).replace(",", " ").split() if part.strip()
            }
            rows = [r for r in rows if r.get(field_name) in wanted]
    for field_name in ("assessment_id", "dataset_run_id", "model_version"):
        wanted = (params or {}).get(field_name)
        if wanted:
            rows = [r for r in rows if str(r.get(field_name, "")) == str(wanted)]

    return paged_envelope(
        f"{API_DISCOVERY}-findings", rows, limit, offset, key="findings",
        read_only=True,
        severity_order=list(SEVERITY_ORDER),
        note=(
            "findings are backend-produced by the risk engine and are exposed "
            "read-only; no resolve/dismiss/override route exists on this API"
        ),
    )


def handle_assessment_findings(
    store, assessment_id: str, params: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """Findings for exactly one assessment (404 if the assessment is unknown).

    Rows are built by the same code path as the global list, so filtering
    ``/api/v1/findings?assessment_id=...`` returns byte-identical rows. A
    frontend can switch between the two views without reconciling shapes.
    """
    from .routes import _bundle_or_404

    bundle = _bundle_or_404(store, assessment_id)
    limit, offset = page_params(params)
    rows = [
        _finding_row(bundle, finding)
        for finding in ((bundle.get("risk") or {}).get("findings") or ())
    ]
    rows.sort(key=_severity_key)
    return paged_envelope(
        f"{API_DISCOVERY}-assessment-findings", rows, limit, offset, key="findings",
        read_only=True,
        assessment_id=bundle.get("assessment_id"),
    )
