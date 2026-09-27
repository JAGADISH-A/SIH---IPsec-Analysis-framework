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
    paths["/api/v1/assessments/{id}/findings/{finding_id}/explanation"] = _get(
        "/api/v1/assessments/{id}/findings/{finding_id}/explanation",
        "getAssessmentFindingExplanation",
        "Chain of custody for one finding of one assessment.",
        tags=["findings", "custody"],
        description=(
            "The audit view of one decision: the rule that fired, the "
            "observed/expected/derived/recommended facts with their authority "
            "stated, the content-addressed evidence with live integrity results, "
            "the ordered derivation steps, and the integrity checks.\n\n"
            "A finding id is NOT unique -- the same id is raised by several "
            "assessments -- so the (assessment, finding) pair addresses the "
            "decision. A finding id that exists in a different assessment is a "
            "404 here, never that other assessment's evidence.\n\n"
            "Read-only and derived: the chain quotes the Phase-3/4/6/7 objects "
            "the pipeline already produced. It runs no detection, changes no "
            "score, creates no evidence, proposes no control of its own, and "
            "applies nothing. `recommendation.applied` is always `false` and the "
            "model rejects any other value.\n\n"
            "Observation honesty: a variable the sensor cannot observe is "
            "reported with `value: null`, the comparison engine's own reason, an "
            "`observation.authoritative_value_present` check of status "
            "`unavailable`, and a matching entry in `limitations`. Nothing is "
            "substituted from the plan or from a model.\n\n"
            "Determinism: no wall clock, no random ids. `determinism."
            "filesystem_dependent_fields` lists the fields that can change if an "
            "artifact on disk changes, so a byte-diff can be attributed."
        ),
        params=[
            _param("id", "path", _STR, "Assessment id.", required=True),
            _param("finding_id", "path", _STR, "Finding id.", required=True),
            _param("verify", "query", _STR,
                   "Set to `0`, `false`, `no` or `off` to skip the read-only "
                   "artifact re-hash. Any other value (including `true`, and the "
                   "absent default) re-hashes every referenced artifact. The "
                   "recorded digests are always served either way; a skipped "
                   "re-hash is reported as `verification.performed: false` and "
                   "every evidence link as `not_performed`, so it is never "
                   "mistaken for a passed check."),
        ],
        responses={
            "200": {
                "description": "The chain of custody.",
                "content": {_JSON: {"schema": _ref("ChainOfCustody")}},
            },
            **_ERROR_RESPONSES,
        })
    paths["/api/v1/findings/{finding_id}/explanation"] = _get(
        "/api/v1/findings/{finding_id}/explanation",
        "getFindingExplanation",
        "Chain of custody for a finding id, disambiguated by ?assessment_id=.",
        tags=["findings", "custody"],
        description=(
            "Same document as the nested route, addressed by finding id alone.\n\n"
            "Because a finding id is raised by more than one assessment, this "
            "route answers `409 finding_ambiguous` and lists the candidate "
            "assessment ids rather than guessing. Re-request with "
            "`?assessment_id=<id>`, or use the nested route. Merging the "
            "candidates would invent a decision no assessment made, and "
            "returning the first would attach one capture's evidence to another "
            "capture's finding."
        ),
        params=[
            _param("finding_id", "path", _STR, "Finding id.", required=True),
            _param("assessment_id", "query", _STR,
                   "Disambiguator. Required when the finding id occurs in more "
                   "than one assessment."),
            _param("verify", "query", _STR,
                   "Set to `0`, `false`, `no` or `off` to skip the read-only "
                   "artifact re-hash; the default re-hashes every referenced "
                   "artifact. A skipped re-hash is reported as "
                   "`verification.performed: false` and every evidence link as "
                   "`not_performed`."),
        ],
        responses={
            "200": {
                "description": "The chain of custody.",
                "content": {_JSON: {"schema": _ref("ChainOfCustody")}},
            },
            "409": {
                "description": (
                    "The finding id is not unique. `error.candidates` lists the "
                    "assessment ids that produced it."
                ),
                "content": {_JSON: {"schema": _ref("Error")}},
            },
            **_ERROR_RESPONSES,
        })

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
            {"name": "custody", "description": "Chain of custody and integrity checks for a finding."},
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
                "ChainOfCustody": {
                    "type": "object",
                    "description": (
                        "The deterministic, read-only audit view of exactly one "
                        "decision, identified by (assessment_id, finding_id). "
                        "Every value is copied from an object the pipeline "
                        "already produced, or is a SHA-256 over canonical JSON "
                        "of one. Contains no PCAP bytes, no artifact payload and "
                        "no absolute host path."
                    ),
                    "required": [
                        # Every key below is emitted on every response, so a client
                        # may rely on its presence without a defaulting branch.
                        # Keys whose value may be null are marked nullable below.
                        "schema_version", "component", "assessment_id",
                        "finding_id", "finding_digest", "severity", "rule",
                        "facts", "steps", "evidence", "sources", "integrity",
                        "recommendation", "limitations", "audit_event_ids",
                        "audit_linkage_status", "read_only",
                    ],
                    "properties": {
                        "schema_version": _STR,
                        "component": _STR,
                        "component_version": _STR,
                        "read_only": {
                            "type": "boolean",
                            "const": True,
                            "description": "Always true; this API exposes no mutation route.",
                        },
                        "assessment_id": {
                            **_STR,
                            "description": (
                                "Half of the decision's identity. A finding id "
                                "repeats across assessments, so the pair is the key."
                            ),
                        },
                        "finding_id": _STR,
                        "finding_digest": {
                            **_STR,
                            "description": (
                                "SHA-256 over the canonical JSON of the "
                                "authoritative RiskFinding. Recompute it to detect "
                                "an edited finding."
                            ),
                        },
                        "title": _STR,
                        "summary": _STR,
                        "category": _STR,
                        "severity": _STR,
                        "risk_score": {"type": "integer", "minimum": 0, "maximum": 100},
                        "risk_severity": _STR,
                        "risk_policy_version": _STR,
                        "risk_engine_version": _STR,
                        "identity": {"type": "object", "description": "CorrelationIdentity of the assessment."},
                        "rule": {
                            "type": "object",
                            "description": (
                                "Which rule fired, copied from the rule registry. "
                                "`registered` is true only when the exact rule id is "
                                "a registry key; `base_rule_id` names the registered "
                                "rule a per-variable id was specialised from."
                            ),
                            "properties": {
                                "rule_id": _STR,
                                "finding_id": _STR,
                                "registered": {"type": "boolean"},
                                "base_rule_id": {"type": "string", "nullable": True},
                                "source_variable": {"type": "string", "nullable": True},
                                "authoritative_source": {"type": "string", "nullable": True},
                                "condition": {"type": "string", "nullable": True},
                                "evidence_requirement": {"type": "string", "nullable": True},
                                "unknown_handling": {"type": "string", "nullable": True},
                                "dedup_behavior": {"type": "string", "nullable": True},
                                "severity": {"type": "string", "nullable": True},
                                "score_contribution": {"type": "integer", "nullable": True},
                                "traceability": {"type": "object"},
                            },
                        },
                        "facts": {
                            "type": "array",
                            "description": (
                                "Sorted by fact_id. `category` says where the value "
                                "came from; `authority` says what may be relied on. "
                                "Only OBSERVED and EXPECTED are authoritative -- a "
                                "planned value is authoritative about intent, never "
                                "about what happened, and neither a model verdict nor "
                                "a policy proposal is authoritative at all."
                            ),
                            "items": {
                                "type": "object",
                                "required": ["fact_id", "category", "authority", "value", "source"],
                                "properties": {
                                    "fact_id": _STR,
                                    "category": {
                                        "type": "string",
                                        "enum": ["OBSERVED", "EXPECTED", "DERIVED", "RECOMMENDED"],
                                    },
                                    "authority": {
                                        "type": "string",
                                        "enum": [
                                            "authoritative_observation",
                                            "authoritative_plan",
                                            "derived_non_authoritative",
                                            "proposed_non_authoritative",
                                        ],
                                    },
                                    "authoritative": {"type": "boolean"},
                                    "label": _STR,
                                    "value": {"description": "Copied verbatim from the source object; may be null."},
                                    "value_digest": {
                                        "type": "string",
                                        "nullable": True,
                                        "description": "SHA-256 over the canonical JSON of `value`.",
                                    },
                                    "source": {
                                        **_STR,
                                        "description": "The exact domain field the value was copied from.",
                                    },
                                    "detail": {"type": "string", "nullable": True},
                                    "evidence_ids": {
                                        "type": "array",
                                        "items": _STR,
                                        "description": "Stable evidence ids. Never paths, never payloads.",
                                    },
                                },
                            },
                        },
                        "steps": {
                            "type": "array",
                            "description": (
                                "The ordered derivation, as the pipeline stages ran it. "
                                "A stage that produced nothing is still listed with an "
                                "outcome saying so. `authoritative` marks the decision path; "
                                "the XAI and response-planning steps are non-authoritative."
                            ),
                            "items": {
                                "type": "object",
                                "required": ["index", "stage", "component", "action", "authoritative"],
                                "properties": {
                                    "index": {"type": "integer", "minimum": 1},
                                    "stage": _STR,
                                    "component": _STR,
                                    "action": _STR,
                                    "authoritative": {"type": "boolean"},
                                    "inputs": {"type": "array", "items": _STR},
                                    "outcome": {"type": "string", "nullable": True},
                                },
                            },
                        },
                        "evidence": {
                            "type": "array",
                            "description": (
                                "Sorted by evidence_id. Identity and digests only: the "
                                "artifact is never inlined and its path is never emitted."
                            ),
                            "items": {
                                "type": "object",
                                "required": ["evidence_id", "verifiable"],
                                "properties": {
                                    "evidence_id": _STR,
                                    "artifact_type": {"type": "string", "nullable": True},
                                    "artifact_sha256": {"type": "string", "nullable": True},
                                    "byte_size": {"type": "integer", "nullable": True},
                                    "verifiable": {"type": "boolean"},
                                    "verification_status": {
                                        "type": "string",
                                        "nullable": True,
                                        "enum": ["valid", "unavailable", "invalid", "unverified",
                                                 "not_performed", None],
                                    },
                                    "verification_detail": {"type": "string", "nullable": True},
                                    "artifact_present": {
                                        "type": "boolean",
                                        "nullable": True,
                                        "description": (
                                            "Null when the artifact was not looked "
                                            "for, so an unchecked file is never "
                                            "reported as a verified absence."
                                        ),
                                    },
                                    "actual_sha256": {"type": "string", "nullable": True},
                                    "attached_by": {"type": "array", "items": _STR},
                                },
                            },
                        },
                        "sources": {
                            "type": "array",
                            "description": (
                                "The recorded input artifacts with their digests. "
                                "`public_path` has already been reduced by the API's "
                                "disclosure policy; an artifact outside the repository "
                                "collapses to a basename."
                            ),
                            "items": {
                                "type": "object",
                                "properties": {
                                    "role": _STR,
                                    "public_path": {"type": "string", "nullable": True},
                                    "artifact_sha256": {"type": "string", "nullable": True},
                                    "byte_size": {"type": "integer", "nullable": True},
                                    "record_count": {"type": "integer", "nullable": True},
                                    "detail": {"type": "object"},
                                },
                            },
                        },
                        "integrity": {
                            "type": "array",
                            "description": (
                                "Machine-evaluable checks, each phrased as a comparison "
                                "so a client can run it itself. A check that could not be "
                                "evaluated is `unavailable`, never `pass`; `invalid` "
                                "evidence is reported as `fail` and never repaired."
                            ),
                            "items": {
                                "type": "object",
                                "required": ["check_id", "description", "status", "detail", "passed"],
                                "properties": {
                                    "check_id": _STR,
                                    "description": _STR,
                                    "status": {
                                        "type": "string",
                                        "enum": ["pass", "fail", "unavailable", "not_applicable"],
                                    },
                                    "passed": {"type": "boolean"},
                                    "detail": _STR,
                                    "observed": {"description": "What the check compared."},
                                    "expected": {"description": "What it was compared against."},
                                    "client_verifiable": {"type": "boolean"},
                                },
                            },
                        },
                        "recommendation": {
                            "type": "object",
                            "nullable": True,
                            "description": (
                                "The response-policy proposal, copied from the reused "
                                "planner. `applied` is always false: this API has no route "
                                "that could apply it."
                            ),
                            "properties": {
                                "recommendation_id": {"type": "string", "nullable": True},
                                "action": {"type": "string", "nullable": True},
                                "priority": {"type": "string", "nullable": True},
                                "policy_version": {"type": "string", "nullable": True},
                                "reason": {"type": "string", "nullable": True},
                                "rationale": {"type": "string", "nullable": True},
                                "authorization_required": {"type": "boolean", "nullable": True},
                                "approval_required": {"type": "boolean", "nullable": True},
                                "required_roles": {"type": "array", "items": _STR},
                                "limitations": {"type": "array", "items": _STR},
                                "applied": {"type": "boolean", "const": False},
                                "derived_by": _STR,
                            },
                        },
                        "audit_event_ids": {
                            "type": "array",
                            "items": _STR,
                            "description": "Content-addressed audit events for this assessment; may be empty.",
                        },
                        "audit_linkage_status": {
                            "type": "string",
                            "enum": ["linked", "unavailable"],
                        },
                        "limitations": {
                            "type": "array",
                            "items": _STR,
                            "description": "What this chain does not establish. Stated as data, never omitted.",
                        },
                        "determinism": {
                            "type": "object",
                            "description": (
                                "How to reproduce the document byte for byte, and which "
                                "fields legitimately change when an artifact on disk changes."
                            ),
                            "properties": {
                                "deterministic": {"type": "boolean", "const": True},
                                "reads_wall_clock": {"type": "boolean", "const": False},
                                "generates_random_ids": {"type": "boolean", "const": False},
                                "order": _STR,
                                "digest_algorithm": _STR,
                                "canonical_json": _STR,
                                "filesystem_dependent_fields": {
                                    "type": "array",
                                    "items": _STR,
                                    "description": "The only fields a byte-diff can legitimately blame on disk state.",
                                },
                            },
                        },
                        "api": {"type": "string", "const": "custody.v1"},
                        "route": {"type": "string"},
                        "read_only": {"type": "boolean", "const": True},
                        "verification": {
                            "type": "object",
                            "description": (
                                "Added by the transport. `performed: false` means "
                                "the artifact re-hash genuinely did not run, and "
                                "every evidence link then carries "
                                "`not_performed` rather than `valid`."
                            ),
                            "required": ["performed", "reason"],
                            "properties": {
                                "performed": {"type": "boolean"},
                                "reason": _STR,
                            },
                        },
                    },
            }
        },
    }
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
