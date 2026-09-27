"""A maintained, hand-written OpenAPI 3.1 description of the analytics API.

Why hand-written instead of framework-generated
------------------------------------------------
The server is stdlib ``http.server`` and will stay that way: swapping in
FastAPI/Flask to obtain automatic schema generation would add a runtime
dependency, a second transport, and a second route table to keep in sync --
for a read-only surface of 25-odd GET routes.  The alternative chosen here is a
single declarative table in this file that *is* the contract, plus a
:func:`self_check` that runs under the test suite and fails when the document
and the router have drifted apart.

That drift check is the point.  A hand-written schema that is never validated
becomes a lie within a week; one that is validated against the live route table
stays true.

The document is served at ``/api/v1/openapi.json`` and a dependency-free HTML
viewer at ``/api/v1/docs``.
"""

from __future__ import annotations

from typing import Any, Dict, List

OPENAPI_VERSION = "3.1.0"

_JSON = "application/json"
_PCAP = "application/vnd.tcpdump.pcap"
_PROM = "text/plain"


def _get(
    path: str,
    operation_id: str,
    summary: str,
    *,
    tags: List[str],
    params: List[Dict[str, Any]] = None,
    responses: Dict[str, Any] = None,
    description: str = None,
) -> Dict[str, Any]:
    return {
        "get": {
            "operationId": operation_id,
            "summary": summary,
            "tags": tags,
            "description": description,
            "parameters": params or [],
            "responses": responses or {"200": {"description": "ok"}},
        }
    }


def _param(name: str, where: str, schema: Dict[str, Any], description: str,
           required: bool = False) -> Dict[str, Any]:
    return {
        "name": name,
        "in": where,
        "required": required,
        "description": description,
        "schema": schema,
    }


_STR = {"type": "string"}
_INT = {"type": "integer", "minimum": 0}


def _ref(name: str) -> Dict[str, Any]:
    return {"$ref": f"#/components/schemas/{name}"}


_PAGE = [
    _param("limit", "query", {"type": "integer", "minimum": 1, "maximum": 5000, "default": 100},
           "Maximum items to return. Capped at 5000."),
    _param("offset", "query", _INT, "Items to skip. Beyond the end yields an empty page."),
]

_ERROR_RESPONSES = {
    "400": {
        "description": "Invalid query parameter.",
        "content": {_JSON: {"schema": _ref("Error")}},
    },
    "404": {
        "description": "No such resource.",
        "content": {_JSON: {"schema": _ref("Error")}},
    },
    "503": {
        "description": (
            "The surface is not attached. `/api/v1/*` requires `--phase10`; "
            "run discovery additionally requires an audit journal."
        ),
        "content": {_JSON: {"schema": _ref("Error")}},
    },
}


def _paged(ok: str = "ok") -> Dict[str, Any]:
    """The standard 200 for a list route.

    One shared schema, because every list route reports the same envelope
    (``count``/``total``/``limit``/``offset``/``has_more``) and differs only in
    what its array is called. Taking the array shape here would imply a
    per-route schema that does not exist.
    """
    return {
        "200": {
            "description": ok,
            "content": {_JSON: {"schema": _ref("PagedResponse")}},
        }
    }


def _json_ok(ok: str = "ok") -> Dict[str, Any]:
    return {"200": {"description": ok, "content": {_JSON: {"schema": {"type": "object"}}}}}


def openapi_document(base_url: str = "") -> Dict[str, Any]:
    """The full OpenAPI document.

    ``base_url`` is left empty by default: the server may be reached at
    different host names, and a wrong ``servers`` entry sends code generators
    to a host that does not exist.  Clients are expected to use the origin they
    loaded the document from.
    """
    paths: Dict[str, Any] = {}

    # -- phase 8 (always available) -----------------------------------------
    paths["/api/health"] = _get(
        "/api/health", "getApiHealth", "Liveness of the analytics API itself.",
        tags=["phase8"], responses=_json_ok())
    paths["/api/assessments"] = _get(
        "/api/assessments", "listAssessments",
        "Deterministic assessment table (one row per assessment).",
        tags=["phase8"],
        params=_PAGE,
        description=(
            "The response array is named `headers` for historical reasons. "
            "`limit`/`offset`/`total`/`count`/`has_more` are added alongside it; "
            "with no query parameters the full table is returned exactly as "
            "before."
        ),
        responses=_paged())
    for suffix, oid, summary in (
        ("", "getAssessment", "One full assessment bundle."),
        ("/correlation", "getAssessmentCorrelation", "Per-SA correlation evidence."),
        ("/risk", "getAssessmentRisk", "Risk assessment and findings."),
        ("/xai", "getAssessmentXai", "Explainability output."),
        ("/ml", "getAssessmentMl", "ML classification and its inputs."),
        ("/evidence", "getAssessmentEvidence", "Evidence references for the assessment."),
        ("/ipsec-state", "getAssessmentIpsecState", "Expected vs observed IPsec state."),
    ):
        paths[f"/api/assessments/{{id}}{suffix}"] = _get(
            f"/api/assessments/{{id}}{suffix}", oid, summary,
            tags=["phase8"],
            params=[_param("id", "path", _STR, "Assessment id.", required=True)],
            responses={**{"200": {"description": "ok", "content": {_JSON: {"schema": {"type": "object"}}}}},
                       **_ERROR_RESPONSES})

    # -- phase 10 ------------------------------------------------------------
    paths["/api/v1/health"] = _get(
        "/api/v1/health", "getV1Health",
        "Health of the live observation surface, including the CORS policy.",
        tags=["phase10"],
        description=(
            "Includes a `cors` object describing the effective origin "
            "allow-list, so a client can discover the policy instead of "
            "inferring it from a failed request."
        ),
        responses=_ERROR_RESPONSES)
    paths["/api/v1/metrics"] = _get(
        "/api/v1/metrics", "getV1Metrics",
        "Prometheus text exposition of live counters.",
        tags=["phase10"],
        responses={"200": {"description": "Prometheus text format.",
                          "content": {_PROM: {"schema": {"type": "string"}}}}})
    paths["/api/v1/traffic-generator"] = _get(
        "/api/v1/traffic-generator", "getTrafficGenerator",
        "Read-only status of the passive traffic generator.",
        tags=["phase10"],
        description=(
            "Status only. There is no route to start, stop or reconfigure it: "
            "the analytics API is read-only."
        ),
        responses=_ERROR_RESPONSES)

    paths["/api/v1/evidence"] = _get(
        "/api/v1/evidence", "listEvidence", "All registered evidence references.",
        tags=["evidence"],
        params=_PAGE + [
            _param("kind", "query", _STR, "Filter by evidence kind."),
            _param("run_id", "query", _STR, "Filter by analysis run id."),
        ],
        responses=_paged())
    paths["/api/v1/evidence/{evidence_id}"] = _get(
        "/api/v1/evidence/{evidence_id}", "getEvidence",
        "One evidence reference. Never contains a host filesystem path.",
        tags=["evidence"],
        params=[_param("evidence_id", "path", _STR, "Evidence id.", required=True)],
        responses={**{"200": {"description": "ok", "content": {_JSON: {"schema": _ref("Evidence")}}}},
                   **_ERROR_RESPONSES})
    paths["/api/v1/evidence/{evidence_id}/pcap"] = _get(
        "/api/v1/evidence/{evidence_id}/pcap", "downloadEvidencePcap",
        "Stream the raw capture bytes for a registered evidence id.",
        tags=["evidence"],
        description=(
            "Served only for an explicitly registered evidence id whose file "
            "resolves inside the configured evidence root and has a known "
            "capture extension. Traversal, symlink escapes and unregistered ids "
            "are refused. Streamed, with `Content-Disposition` set, so a "
            "browser saves the file instead of navigating to it."
        ),
        params=[_param("evidence_id", "path", _STR, "Evidence id.", required=True)],
        responses={
            "200": {
                "description": "The capture bytes.",
                "headers": {
                    "Content-Disposition": {
                        "schema": _STR,
                        "description": "attachment; filename derived from the evidence id.",
                    }
                },
                "content": {_PCAP: {"schema": {"type": "string", "format": "binary"}}},
            },
            **_ERROR_RESPONSES,
        })
    paths["/api/v1/runs/{run_id}/evidence"] = _get(
        "/api/v1/runs/{run_id}/evidence", "listRunEvidence",
        "Evidence referenced by one analysis run.",
        tags=["evidence"],
        params=[_param("run_id", "path", _STR, "Run id.", required=True)] + _PAGE,
        responses=_paged())
    paths["/api/v1/responses/{recommendation_id}/evidence"] = _get(
        "/api/v1/responses/{recommendation_id}/evidence", "listResponseEvidence",
        "Evidence attached to one recorded response decision.",
        tags=["governance"],
        params=[_param("recommendation_id", "path", _STR, "Recommendation id.", required=True)],
        responses=_ERROR_RESPONSES)

    paths["/api/v1/audit/events"] = _get(
        "/api/v1/audit/events", "listAuditEvents", "Query the analysis audit journal.",
        tags=["audit"],
        params=_PAGE + [
            _param("stage", "query", _STR, "Filter by pipeline stage."),
            _param("event_type", "query", _STR, "Filter by event type."),
            _param("run_id", "query", _STR, "Filter by run id."),
            _param("window_index", "query", _INT, "Filter by window index."),
            _param("since_seq", "query", _INT, "Only events with a higher sequence."),
        ],
        responses=_paged("A page of audit events."))
    paths["/api/v1/audit/events/{event_id}"] = _get(
        "/api/v1/audit/events/{event_id}", "getAuditEvent", "One audit event.",
        tags=["audit"],
        params=[_param("event_id", "path", _STR, "Event id.", required=True)],
        responses=_ERROR_RESPONSES)
    paths["/api/v1/audit/events/{event_id}/evidence"] = _get(
        "/api/v1/audit/events/{event_id}/evidence", "listEventEvidence",
        "Evidence recorded for one audit event.",
        tags=["audit", "evidence"],
        params=[_param("event_id", "path", _STR, "Event id.", required=True)] + _PAGE,
        responses=_paged())
    paths["/api/v1/audit/runs"] = _get(
        "/api/v1/audit/runs", "listAuditRuns",
        "Runs that appear in the audit journal, with per-run counts.",
        tags=["audit"], params=_PAGE, responses=_paged())
    paths["/api/v1/audit/runs/{run_id}"] = _get(
        "/api/v1/audit/runs/{run_id}", "getAuditRun", "One run's audit summary.",
        tags=["audit"],
        params=[_param("run_id", "path", _STR, "Run id.", required=True)],
        responses=_ERROR_RESPONSES)
    paths["/api/v1/runs/{run_id}/audit"] = _get(
        "/api/v1/runs/{run_id}/audit", "listRunEvents",
        "Ordered per-window lifecycle trail for one run.",
        tags=["audit"],
        params=[_param("run_id", "path", _STR, "Run id.", required=True)] + _PAGE,
        description=(
            "Windows follow the recorded pipeline order. Pagination is applied "
            "to the filtered event set, so `limit`/`offset` mean the same thing "
            "here as on the flat event list. Previously both were echoed but "
            "ignored, so a client paging a long run re-fetched the whole run "
            "every page and could never reach the end. `event_count` is the "
            "total; `returned_event_count` is this page."
        ),
        responses=_paged())

    paths["/api/v1/governance"] = _get(
        "/api/v1/governance", "listGovernance",
        "Governance ledger events, read-only.",
        tags=["governance"], params=_PAGE, responses=_paged())
    paths["/api/v1/governance/{event_id}"] = _get(
        "/api/v1/governance/{event_id}", "getGovernanceEvent",
        "One governance event with its chain position.",
        tags=["governance"],
        params=[_param("event_id", "path", _STR, "Event id.", required=True)],
        responses=_ERROR_RESPONSES)

    # -- discovery ----------------------------------------------------------
    paths["/api/v1/runs"] = _get(
        "/api/v1/runs", "listRuns",
        "Discovery: every analysis run that has recorded audit events.",
        tags=["discovery"], params=_PAGE, responses=_paged())
    paths["/api/v1/runs/{run_id}"] = _get(
        "/api/v1/runs/{run_id}", "getRun", "Discovery: one run summary.",
        tags=["discovery"],
        params=[_param("run_id", "path", _STR, "Run id.", required=True)],
        responses=_ERROR_RESPONSES)
    paths["/api/v1/assessments"] = _get(
        "/api/v1/assessments", "listAssessmentsV1",
        "Discovery: paged, filterable assessment rows.",
        tags=["discovery"],
        params=_PAGE + [
            _param("scenario", "query", _STR, "Filter by scenario."),
            _param("severity", "query", _STR, "Filter by severity."),
            _param("mode", "query", _STR, "Filter by mode."),
            _param("address_family", "query", _STR, "Filter by address family."),
            _param("security_posture", "query", _STR, "Filter by security posture."),
            _param("dataset_run_id", "query", _STR, "Filter by dataset run id."),
            _param("sort", "query", _STR, "Sort key. Only `risk` is meaningful."),
            _param("order", "query", _STR, "`asc` or `desc` (default `desc`)."),
        ],
        responses=_paged())
    paths["/api/v1/assessments/{id}"] = _get(
        "/api/v1/assessments/{id}", "getAssessmentV1",
        "Discovery: one full backend-produced assessment bundle.",
        tags=["discovery"],
        params=[_param("id", "path", _STR, "Assessment id.", required=True)],
        responses=_ERROR_RESPONSES)
    paths["/api/v1/assessments/{id}/findings"] = _get(
        "/api/v1/assessments/{id}/findings", "listAssessmentFindings",
        "Findings for one assessment, worst first.",
        tags=["discovery", "findings"],
        params=[_param("id", "path", _STR, "Assessment id.", required=True)] + _PAGE,
        responses=_paged())
    paths["/api/v1/findings"] = _get(
        "/api/v1/findings", "listFindings",
        "Discovery: every backend-produced finding, flat and filterable.",
        tags=["discovery", "findings"],
        description=(
            "Read-only by construction. There is no resolve/dismiss/override "
            "route anywhere on this API, so a client can render and filter "
            "findings but cannot change them. Findings are copied verbatim from "
            "the Phase-6 risk engine output; this API re-scores nothing."
        ),
        params=_PAGE + [
            _param("severity", "query", _STR,
                   "Filter by severity; comma-separated for several."),
            _param("category", "query", _STR, "Filter by finding category."),
            _param("assessment_id", "query", _STR, "Filter by assessment id."),
            _param("dataset_run_id", "query", _STR, "Filter by dataset run id."),
            _param("model_version", "query", _STR, "Filter by ML model version."),
        ],
        responses=_paged())

    return {
        "openapi": OPENAPI_VERSION,
        "info": {
            "title": "SIHColayer Analytics API (Server A)",
            "version": "1.0.0",
            "summary": "Read-only analytics, evidence and audit API.",
            "description": (
                "Read-only, passive-observation API. Every mutating verb is "
                "answered 405: there is no route that starts, stops, approves, "
                "resolves, dismisses or overrides anything, and no XDP "
                "enforcement action is reachable.\n\n"
                "CORS: cross-origin browser reads are allowed only from origins "
                "in the configured allow-list "
                "(`ANALYTICS_API_ALLOWED_ORIGINS`). A disallowed origin "
                "receives a response with no `Access-Control-Allow-Origin`, "
                "which the browser treats as a block. `GET "
                "/api/v1/health` reports the effective policy under `cors`.\n\n"
                "Authentication: none. This is a loopback-by-default "
                "development surface; see the contract document before exposing "
                "it.\n\n"
                "Errors: `{\"error\": {\"code\", \"message\", \"detail\", "
                "\"request_id\"}}`. Branch on `code`; `message` and `detail` are "
                "human text and may change. Quote `request_id` when reporting a "
                "failure -- it matches the server log line.\n\n"
                "Pagination: list routes accept `limit` (1..5000, default 100) "
                "and `offset`, and return `count`, `total`, `limit`, `offset` "
                "and `has_more` alongside their array.\n\n"
                "This API is a separate process from the testbed control API "
                "(`controller/api.py`, conventionally port 8000). It is not "
                "mounted into it and does not depend on it."
            ),
        },
        "servers": ([{"url": base_url}] if base_url else []),
        "tags": [
            {"name": "phase8", "description": "Deterministic recorded assessment data."},
            {"name": "phase10", "description": "Live observation health and metrics."},
            {"name": "evidence", "description": "Evidence references and raw captures."},
            {"name": "audit", "description": "The append-only analysis audit journal."},
            {"name": "governance", "description": "The governance decision ledger."},
            {"name": "discovery", "description": "Enumerating what exists, for state restoration."},
            {"name": "findings", "description": "Backend-produced risk findings, read-only."},
        ],
        "paths": paths,
        "components": {
            "schemas": {
                "Error": {
                    "type": "object",
                    "required": ["error"],
                    "properties": {
                        "error": {
                            "type": "object",
                            "required": ["code", "message"],
                            "properties": {
                                "code": {"type": "string",
                                         "description": "Stable machine-readable discriminator."},
                                "message": {"type": "string",
                                            "description": "Human-readable explanation."},
                                "detail": {"type": "string",
                                           "description": "Legacy alias of `message`."},
                                "request_id": {"type": "string",
                                               "description": "Correlates with the server log."},
                            },
                        }
                    },
                },
                "PagedResponse": {
                    "type": "object",
                    "required": ["count", "total", "limit", "offset", "has_more"],
                    "properties": {
                        "count": {"type": "integer", "description": "Items in this page."},
                        "total": {"type": "integer", "description": "Items matching the filters, before paging."},
                        "limit": {"type": "integer"},
                        "offset": {"type": "integer"},
                        "has_more": {"type": "boolean"},
                    },
                },
                "Evidence": {
                    "type": "object",
                    "description": (
                        "An evidence reference. Contains no host filesystem "
                        "path: artifacts are described by repository-relative "
                        "source path and content digest only."
                    ),
                    "properties": {
                        "evidence_id": _STR,
                        "kind": _STR,
                        "bytes": {"type": "integer"},
                        "sources": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "properties": {
                                    "path": {"type": "string",
                                             "description": "Repository-relative; never absolute."},
                                    "sha256": _STR,
                                },
                            },
                        },
                    },
                },
            }
        },
    }


def documented_paths() -> set:
    """The path templates in the document, for drift checking."""
    return set(openapi_document()["paths"])


def docs_html() -> bytes:
    """A dependency-free HTML page that renders the document.

    Deliberately no CDN script: a docs page that fetches its renderer from the
    internet is a supply-chain surface on a security tool, and it also breaks
    on an air-gapped host. The page lists the routes and points at the raw
    JSON for generators.
    """
    doc = openapi_document()
    rows = []
    for path, ops in doc["paths"].items():
        op = ops["get"]
        params = op.get("parameters") or []
        query = [p["name"] for p in params if p["in"] == "query"]
        rows.append(
            "<tr><td><code>GET</code></td><td><code>{path}</code></td>"
            "<td>{summary}</td><td>{tags}</td><td>{query}</td></tr>".format(
                path=_escape(path),
                summary=_escape(op["summary"]),
                tags=_escape(", ".join(op["tags"])),
                query=_escape(", ".join(query)) or "&mdash;",
            )
        )
    html = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>Analytics API contract</title>
<style>
 body{{font:14px/1.5 system-ui,sans-serif;margin:2rem auto;max-width:70rem;color:#1a1a1a}}
 h1{{font-size:1.4rem}} code{{background:#f4f4f5;padding:1px 4px;border-radius:3px}}
 table{{border-collapse:collapse;width:100%;margin:1rem 0}}
 th,td{{border:1px solid #d4d4d8;padding:.4rem .6rem;text-align:left;vertical-align:top}}
 th{{background:#fafafa}} .note{{background:#fffbeb;border-left:3px solid #d97706;padding:.6rem 1rem}}
</style></head><body>
<h1>Analytics API (Server A) &mdash; read-only contract</h1>
<p class="note"><strong>Read-only.</strong> No route starts, stops, approves,
resolves, dismisses or overrides anything. Every mutating verb returns 405.
No authentication is implemented; the server binds loopback by default.</p>
<p>Machine-readable document: <a href="/api/v1/openapi.json">/api/v1/openapi.json</a>
&mdash; OpenAPI {doc['openapi']}, {len(rows)} routes.</p>
<table><thead><tr><th>Method</th><th>Path</th><th>Summary</th><th>Tags</th>
<th>Query parameters</th></tr></thead><tbody>
{"".join(rows)}
</tbody></table>
</body></html>
"""
    return html.encode("utf-8")


def _escape(value: str) -> str:
    return (
        str(value)
        .replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        .replace('"', "&quot;")
    )
