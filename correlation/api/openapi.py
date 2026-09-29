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
    paths["/api/v1/capture/events"] = _get(
        "/api/v1/capture/events", "getCaptureEvents",
        "Read-only tail of the xdp_monitor packet journal (capture view).",
        tags=["capture", "phase10"],
        description=(
            "Passive capture of the gateway traffic path. The server tails the "
            "packet journal the sensor writes (byte-offset cursor) and "
            "normalizes each raw XDP event through the streaming adapter; it "
            "never fabricates packets. When no journal is attached the route "
            "returns a structured 503 (`capture_feed_unavailable`); when the "
            "attached journal has no packets yet it reports "
            "`present:false` + a `reason`, i.e. an explicit waiting state. "
            "Per-packet `risk` is a verbatim projection of the assessment "
            "store by observed SPI, never inferred from the packet.\n\n"
            "The envelope also carries the backend's own `current` verdict: a "
            "journal is current only while it is actively being written (write "
            "activity inside `freshness_window_ms`, default 8000, overridable "
            "via `ANALYTICS_API_CAPTURE_FRESHNESS_MS`). A journal that exists "
            "but is not being written reports `current:false` — its rows are "
            "recorded history, not current live traffic, and the workspace "
            "must not present them as live. `last_write_age_ms`, "
            "`journal_mtime_ms`, `server_time_ms` and `newest_observed_at_ms` "
            "are the supporting timestamps; currentness is never approximated "
            "client-side."
        ),
        params=[
            _param("cursor", "query", {"type": "integer"},
                   "Byte offset into the journal to continue reading from.",
                   required=False),
            _param("limit", "query", {"type": "integer", "maximum": 2000},
                   "Maximum rows to return in this page (default 200).",
                   required=False),
        ],
        responses={**_paged(), **_ERROR_RESPONSES})

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
    paths["/api/v1/drift"] = _get(
        "/api/v1/drift",
        "getDrift",
        "Longitudinal IPsec security-state drift for this dataset run.",
        tags=["drift"],
        description=(
            "What this run's observations were compared against, and the outcome "
            "per assessment.\n\n"
            "`configuration_drift` is the only supported category, because the "
            "authoritative observation path reports only ESP presence, AH presence "
            "and the endpoint address family. No cipher, DH group, PFS, IKE "
            "version, firmware, implementation, traffic-behaviour or ML drift is "
            "detected, and the other categories are listed in "
            "`unsupported_categories` so the absence is explicit rather than "
            "silent.\n\n"
            "A baseline is only ever established explicitly by an operator and is "
            "never promoted from the most recent observation. With no baseline "
            "configured this route reports `configured: false` with a reason, and "
            "`status_counts` is empty -- which is not the same as reporting no "
            "drift. Transient values (timestamps, counters, SPI values, liveness, "
            "observation history) are excluded from the comparison by declaration "
            "and are listed in `canonicalization.excluded`."
        ),
        responses={
            "200": {
                "description": "The drift summary.",
                "content": {_JSON: {"schema": _ref("DriftSummary")}},
            },
            **_ERROR_RESPONSES,
        })
    paths["/api/v1/drift/baselines"] = _get(
        "/api/v1/drift/baselines",
        "getDriftBaselines",
        "The validated IPsec security-state baselines this store knows about.",
        tags=["drift"],
        description=(
            "Each baseline is disclosed as a record with both digests: "
            "`state_digest` fingerprints the comparable security state, and "
            "`baseline_digest` seals the whole record including who validated it "
            "and when, so an edit to either is detectable.\n\n"
            "Read-only: a baseline is created by the drift layer, not by this API. "
            "An empty list means no baseline was declared, not that no drift "
            "exists."
        ),
        responses={
            "200": {
                "description": "The registered baselines.",
                "content": {_JSON: {"schema": _ref("DriftBaselineList")}},
            },
            **_ERROR_RESPONSES,
        })
    paths["/api/v1/assessments/{id}/drift"] = _get(
        "/api/v1/assessments/{id}/drift",
        "getAssessmentDrift",
        "The drift comparison for one assessment.",
        tags=["drift"],
        description=(
            "The field-level comparison behind the run-level summary. A known "
            "assessment with no configured baseline is reported as "
            "`not_configured` rather than `drift` or `no_drift`.\n\n"
            "`indeterminate` means the current observation could not support a "
            "comparison claim -- for example it saw no traffic at all, so every "
            "presence flag reads false by observation rather than by security "
            "change. Nothing is then reported as changed and nothing as agreed."
        ),
        params=[
            _param("id", "path", _STR, "Assessment id.", required=True),
        ],
        responses={
            "200": {
                "description": "The assessment's drift comparison.",
                "content": {_JSON: {"schema": _ref("DriftAssessment")}},
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
            {"name": "drift", "description": (
                "Longitudinal drift of observed IPsec security state against an "
                "explicitly validated baseline. Read-only: a baseline is "
                "established by an operator, never inferred from the most recent "
                "observation."
            )},
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
                "ValidatedBaseline": {
                    "type": "object",
                    "description": (
                        "An explicitly validated historical IPsec security state. "
                        "`validation_status` is always `validated`: there is no "
                        "provisional or implicit baseline, and the most recent "
                        "observation is never promoted to one. `canonical_state` "
                        "holds only the declared comparable fields, which is why "
                        "transient values cannot enter the comparison."
                    ),
                    "required": ["baseline_id", "state_digest", "canonical_state",
                                 "validation_status", "baseline_digest",
                                 "model_version", "schema_version"],
                    "properties": {
                        "baseline_id": _STR,
                        "state_digest": {
                            **_STR,
                            "description": (
                                "sha256 over the canonical comparable state; the "
                                "fingerprint two observations are compared by, and "
                                "reproducible by any client holding the state."
                            ),
                        },
                        "baseline_digest": {
                            **_STR,
                            "description": (
                                "sha256 over the whole record including its "
                                "provenance metadata; the seal, so a change to the "
                                "validation metadata is detectable too."
                            ),
                        },
                        "canonical_state": {
                            "type": "object",
                            "description": (
                                "The comparable security state: address_family, "
                                "esp.presence, ah.presence."
                            ),
                            "additionalProperties": {"description": "Comparable value."},
                        },
                        "validation_status": {"type": "string", "enum": ["validated"]},
                        "asset_id": {"type": "string", "nullable": True},
                        "source_run_id": {"type": "string", "nullable": True},
                        "source_observation_ref": {"type": "string", "nullable": True},
                        "captured_at": {"type": "string", "nullable": True},
                        "validated_at": {"type": "string", "nullable": True},
                        "validated_by": {"type": "string", "nullable": True},
                        "notes": {"type": "string", "nullable": True},
                        "model_version": _STR,
                        "schema_version": _STR,
                        "component": _STR,
                        "component_version": _STR,
                        "source": _STR,
                        "evidence_refs": {
                            "type": "array",
                            "description": "Serialised evidence references; never a payload or a path.",
                            "items": {"type": "object"},
                        },
                    },
                },
                "DriftBaselineList": {
                    "type": "object",
                    "description": (
                        "The validated baselines this store knows about, plus the "
                        "canonicalization declaration. An empty `baselines` list "
                        "with `configured: false` means no baseline was declared, "
                        "which is not a claim that no drift exists."
                    ),
                    "required": ["configured", "baseline_ids", "baselines",
                                 "canonicalization"],
                    "properties": {
                        "api": _STR,
                        "read_only": {"type": "boolean", "const": True},
                        "configured": {"type": "boolean"},
                        "reason": {"type": "string", "nullable": True},
                        "persistent": {
                            "type": "boolean",
                            "description": "False for the in-memory default registry.",
                        },
                        "baseline_ids": {"type": "array", "items": _STR},
                        "baselines": {
                            "type": "array",
                            "items": _ref("ValidatedBaseline"),
                        },
                        "canonicalization": _ref("Canonicalization"),
                    },
                },
                "Canonicalization": {
                    "type": "object",
                    "description": (
                        "What participates in the comparison and what does not, with "
                        "the reason for each. Published so a reader can verify that "
                        "no excluded field was silently compared."
                    ),
                    "required": ["model_version", "included", "excluded"],
                    "properties": {
                        "model_version": _STR,
                        "included": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "required": ["variable", "comparison_rule",
                                             "security_relevance", "reason"],
                                "properties": {
                                    "variable": _STR,
                                    "label": _STR,
                                    "comparison_rule": _STR,
                                    "security_relevance": {"type": "boolean"},
                                    "reason": _STR,
                                },
                            },
                        },
                        "excluded": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "required": ["field", "reason"],
                                "properties": {"field": _STR, "reason": _STR},
                            },
                        },
                    },
                },
                "DriftAssessment": {
                    "type": "object",
                    "description": (
                        "The comparison of one observation against one validated "
                        "baseline. The same document appears at "
                        "`ChainOfCustody.drift`."
                    ),
                    "required": ["status", "drift_detected", "baseline", "current",
                                 "changed_fields", "unchanged_variables",
                                 "unknown_variables", "drift_categories",
                                 "model_version", "rule_id"],
                    "properties": {
                        "api": _STR,
                        "read_only": {"type": "boolean", "const": True},
                        "assessment_id": {"type": "string", "nullable": True},
                        "status": {
                            "type": "string",
                            "enum": ["drift", "no_drift", "not_configured",
                                     "indeterminate"],
                        },
                        "drift_detected": {
                            "type": "boolean",
                            "description": "True only for status `drift`.",
                        },
                        "baseline": _ref("DriftBaselineSide"),
                        "current": _ref("DriftCurrentSide"),
                        "changed_fields": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "required": ["variable", "baseline_value",
                                             "current_value", "drift_category",
                                             "security_relevance"],
                                "properties": {
                                    "variable": _STR,
                                    "label": _STR,
                                    "baseline_value": {"description": "Validated value."},
                                    "current_value": {"description": "Observed value."},
                                    "comparison_rule": _STR,
                                    "security_relevance": {"type": "boolean"},
                                    "drift_category": {
                                        "type": "string",
                                        "enum": ["configuration_drift"],
                                    },
                                    "finding_id": {"type": "string", "nullable": True},
                                    "severity": {"type": "string", "nullable": True},
                                },
                            },
                        },
                        "unchanged_variables": {"type": "array", "items": _STR},
                        "unknown_variables": {"type": "array", "items": _STR},
                        "drift_categories": {
                            "type": "array",
                            "items": {"type": "string",
                                      "enum": ["configuration_drift"]},
                        },
                        "risk": {"type": "object", "nullable": True},
                        "reason": _STR,
                        "model_version": _STR,
                        "rule_id": _STR,
                    },
                },
                "DriftBaselineSide": {
                    "type": "object",
                    "nullable": True,
                    "properties": {
                        "baseline_id": {"type": "string", "nullable": True},
                        "state_digest": {"type": "string", "nullable": True},
                        "baseline_digest": {"type": "string", "nullable": True},
                        "validated_at": {"type": "string", "nullable": True},
                        "validated_by": {"type": "string", "nullable": True},
                        "asset_id": {"type": "string", "nullable": True},
                        "validation_status": {"type": "string", "nullable": True},
                    },
                },
                "DriftCurrentSide": {
                    "type": "object",
                    "nullable": True,
                    "properties": {
                        "state_digest": {"type": "string", "nullable": True},
                        "source_ref": {"type": "string", "nullable": True},
                        "source": {
                            "allOf": [_ref("DriftCurrentSource")],
                            "nullable": True,
                            "description": (
                                "What kind of artifact the current state was. A "
                                "controlled demonstration is published here as "
                                "`declared_observation` with `is_capture: false`, "
                                "so it can never be read as an observation of a "
                                "live device."
                            ),
                        },
                        "run_id": {"type": "string", "nullable": True},
                        "sequence": {"type": "integer", "nullable": True},
                    },
                },
                "DriftCurrentSource": {
                    "type": "object",
                    "nullable": True,
                    "description": (
                        "The declared provenance of the current observed state. "
                        "`kind` is the canonical vocabulary; `declared_kind` and "
                        "`declaration` are the producer's own words, carried "
                        "verbatim rather than paraphrased."
                    ),
                    "required": ["kind", "is_capture", "is_live_capture"],
                    "properties": {
                        "kind": {
                            "type": "string",
                            "enum": ["recorded_capture", "declared_observation"],
                            "description": (
                                "`recorded_capture` means a sensor produced this "
                                "state. `declared_observation` means a producer "
                                "declared it, for example a controlled fixture "
                                "derived from a capture."
                            ),
                        },
                        "is_capture": {
                            "type": "boolean",
                            "description": (
                                "True only for `recorded_capture`. A declared "
                                "observation is never a capture, whatever the "
                                "artifact it was read from happens to be."
                            ),
                        },
                        "is_live_capture": {
                            "type": "boolean",
                            "nullable": True,
                            "description": (
                                "Defaults to `is_capture`. Explicitly false for a "
                                "declared observation; the model refuses a value "
                                "that contradicts `kind`."
                            ),
                        },
                        "artifact_sha256": {"type": "string", "nullable": True},
                        "public_path": {"type": "string", "nullable": True},
                        "declared_kind": {"type": "string", "nullable": True},
                        "declaration": {
                            "type": "string",
                            "nullable": True,
                            "description": (
                                "The producer's verbatim statement about the "
                                "artifact, including any 'this is not a capture' "
                                "claim."
                            ),
                        },
                        "derived_from": {
                            "type": "object",
                            "nullable": True,
                            "description": (
                                "The artifact a declared current state was "
                                "derived from, with its path and digest. Present "
                                "only for a declared observation."
                            ),
                            "additionalProperties": True,
                        },
                    },
                },
                "DriftSummary": {
                    "type": "object",
                    "description": "Run-level drift surface.",
                    "required": ["configured", "supported_categories",
                                 "unsupported_categories", "canonicalization",
                                 "status_counts", "assessments"],
                    "properties": {
                        "api": _STR,
                        "read_only": {"type": "boolean", "const": True},
                        "configured": {"type": "boolean"},
                        "reason": {"type": "string", "nullable": True},
                        "baseline_id": {"type": "string", "nullable": True},
                        "baseline": {
                            "oneOf": [_ref("ValidatedBaseline"), {"type": "null"}],
                        },
                        "persistent": {"type": "boolean"},
                        "supported_categories": {
                            "type": "array",
                            "items": {"type": "string",
                                      "enum": ["configuration_drift"]},
                        },
                        "unsupported_categories": {
                            "type": "array",
                            "description": (
                                "Categories deliberately not implemented. Published so "
                                "their absence is a documented decision rather than a "
                                "silent gap."
                            ),
                            "items": {"type": "string",
                                      "enum": ["firmware_drift", "implementation_drift",
                                               "traffic_behavior_drift",
                                               "ml_behavior_drift"]},
                        },
                        "canonicalization": _ref("Canonicalization"),
                        "status_counts": {
                            "type": "object",
                            "description": "Assessment counts per drift status.",
                            "additionalProperties": {"type": "integer"},
                        },
                        "comparison_count": {
                            "type": "integer",
                            "description": (
                                "Number of distinct comparison results. Lower than "
                                "`assessment_count` when a comparison produced "
                                "findings (it is then reported both as context and "
                                "as the drift-origin assessment) or when several "
                                "assessments share one security state."
                            ),
                        },
                        "assessment_count": {
                            "type": "integer",
                            "description": "Number of assessments reporting one.",
                        },
                        "drift_origin_count": {
                            "type": "integer",
                            "description": (
                                "How many of the reporting assessments are the "
                                "drift-origin alias of a comparison rather than an "
                                "independent comparison."
                            ),
                        },
                        "current_source_kinds": {
                            "type": "object",
                            "description": (
                                "Assessment counts per kind of current-state "
                                "artifact. A `declared_observation` here is a "
                                "controlled demonstration, not an observation of a "
                                "live device; present so a client reading the table "
                                "cannot mistake the two."
                            ),
                            "additionalProperties": {"type": "integer"},
                        },
                        "assessments": {
                            "type": "object",
                            "additionalProperties": {
                                "type": "object",
                                "properties": {
                                    "status": _STR,
                                    "drift_detected": {"type": "boolean"},
                                    "drift_categories": {"type": "array", "items": _STR},
                                    "current_source_kind": {
                                        "type": "string",
                                        "enum": ["recorded_capture",
                                                 "declared_observation"],
                                    },
                                    "current_source_is_capture": {"type": "boolean"},
                                    "entry_kind": {
                                        "type": "string",
                                        "enum": ["plan_comparison", "drift_origin"],
                                    },
                                    "parent_assessment_id": {
                                        "type": "string",
                                        "nullable": True,
                                    },
                                    "changed_fields": {
                                        "type": "array",
                                        "items": {"type": "object"},
                                    },
                                    "reason": _STR,
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
                                "a policy proposal is authoritative at all. CONFIGURED "
                                "is operator-declared assessment context (asset role, "
                                "criticality, mission impact): it is authoritative "
                                "about what the operator declared and about nothing "
                                "observed on the network."
                            ),
                            "items": {
                                "type": "object",
                                "required": ["fact_id", "category", "authority", "value", "source"],
                                "properties": {
                                    "fact_id": _STR,
                                    "category": {
                                        "type": "string",
                                        "enum": ["OBSERVED", "EXPECTED", "DERIVED",
                                                  "RECOMMENDED", "CONFIGURED"],
                                    },
                                    "authority": {
                                        "type": "string",
                                        "enum": [
                                            "authoritative_observation",
                                            "authoritative_plan",
                                            "derived_non_authoritative",
                                            "proposed_non_authoritative",
                                            "configured_assessment_context",
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
                        "mission_context": {
                            "type": "object",
                            "nullable": True,
                            "description": (
                                "Externally supplied asset context and the "
                                "contextualized risk it produced. `status` is "
                                "`configured` when an operator declared a profile for "
                                "this asset, and `not_configured` otherwise -- in which "
                                "case `profile` and `risk` are null, no criticality is "
                                "assumed, and the technical risk stands alone. Never "
                                "inferred from traffic, addresses, payloads or ML "
                                "output: `derived_from_observation` is always false."
                            ),
                            "required": ["status", "configured", "derived_from_observation"],
                            "properties": {
                                "status": {
                                    "type": "string",
                                    "enum": ["configured", "not_configured"],
                                },
                                "configured": {"type": "boolean"},
                                "asset_id": {"type": "string", "nullable": True},
                                "profile": {
                                    "type": "object",
                                    "nullable": True,
                                    "description": (
                                        "The operator's declarations. `role` is "
                                        "descriptive and never enters the calculation."
                                    ),
                                    "required": ["asset_id", "role", "criticality",
                                                 "mission_impact"],
                                    "properties": {
                                        "asset_id": _STR,
                                        "role": {
                                            "type": "string",
                                            "enum": ["development", "test",
                                                     "operational-communications",
                                                     "mission-support"],
                                        },
                                        "criticality": {
                                            "type": "string",
                                            "enum": ["low", "medium", "high"],
                                        },
                                        "mission_impact": {
                                            "type": "string",
                                            "enum": ["low", "medium", "high"],
                                        },
                                    },
                                },
                                "risk": {
                                    "type": "object",
                                    "nullable": True,
                                    "description": (
                                        "The contextualized view, over the "
                                        "assessment-level risk pair: "
                                        "`technical_risk` mirrors the response's "
                                        "`risk_score` and `technical_severity` mirrors "
                                        "`risk_severity`, both unchanged. The "
                                        "individual finding's own `severity` is a "
                                        "separate field and is not touched either. "
                                        "`contextualized_risk` is that score placed in "
                                        "the declared context, bounded by the same "
                                        "0-100 scale and never below the technical "
                                        "score."
                                    ),
                                    "required": ["technical_risk", "technical_severity",
                                                 "contextualized_risk",
                                                 "contextualized_severity", "model_version"],
                                    "properties": {
                                        "technical_risk": {"type": "integer"},
                                        "technical_severity": _STR,
                                        "contextualized_risk": {"type": "integer"},
                                        "contextualized_severity": _STR,
                                        "context_index": {"type": "integer"},
                                        "multiplier_bp": {
                                            "type": "integer",
                                            "description": "Basis points; 10000 is neutral.",
                                        },
                                        "criticality_weight": {"type": "integer"},
                                        "mission_impact_weight": {"type": "integer"},
                                        "model_version": _STR,
                                        "formula": _STR,
                                        "score_cap": {"type": "integer"},
                                        "inferred_from_traffic": {"type": "boolean", "const": False},
                                    },
                                },
                                "context_source": {"type": "string", "nullable": True},
                                "context_source_path": {
                                    "type": "string",
                                    "nullable": True,
                                    "description": "Repository-relative; never absolute.",
                                },
                                "context_source_sha256": {"type": "string", "nullable": True},
                                "reason": _STR,
                                "model_version": _STR,
                                "derived_from_observation": {
                                    "type": "boolean",
                                    "const": False,
                                },
                            },
                        },
                        "drift": {
                            "type": "object",
                            "nullable": True,
                            "description": (
                                "The validated-baseline comparison, or null when the "
                                "assessment declared no baseline. `status` is `drift` "
                                "when a comparable security-state field differs from "
                                "the baseline, `no_drift` when every comparable field "
                                "matches, `indeterminate` when the current observation "
                                "cannot support a comparison claim, and "
                                "`not_configured` when no baseline was supplied. A "
                                "`not_configured` or `indeterminate` status claims "
                                "neither drift nor agreement: absence of evidence is "
                                "never promoted to a security finding."
                            ),
                            "required": ["status", "drift_detected", "baseline",
                                         "current", "changed_fields",
                                         "unchanged_variables", "unknown_variables",
                                         "drift_categories", "model_version", "rule_id"],
                            "properties": {
                                "status": {
                                    "type": "string",
                                    "enum": ["drift", "no_drift", "not_configured",
                                             "indeterminate"],
                                },
                                "drift_detected": {"type": "boolean"},
                                "baseline": {
                                    "type": "object",
                                    "nullable": True,
                                    "description": (
                                        "The validated baseline the comparison was made "
                                        "against. `state_digest` fingerprints the "
                                        "comparable state and `baseline_digest` seals "
                                        "the whole record including its provenance, so "
                                        "tampering with either is detectable."
                                    ),
                                    "properties": {
                                        "baseline_id": _STR,
                                        "state_digest": _STR,
                                        "baseline_digest": _STR,
                                        "validated_at": {"type": "string", "nullable": True},
                                        "validated_by": {"type": "string", "nullable": True},
                                        "asset_id": {"type": "string", "nullable": True},
                                        "validation_status": {
                                            "type": "string",
                                            "nullable": True,
                                            "enum": ["validated", None],
                                        },
                                    },
                                },
                                "current": {
                                    "type": "object",
                                    "nullable": True,
                                    "properties": {
                                        "state_digest": _STR,
                                        "source_ref": {"type": "string", "nullable": True},
                                        "run_id": {"type": "string", "nullable": True},
                                        "sequence": {"type": "integer", "nullable": True},
                                    },
                                },
                                "changed_fields": {
                                    "type": "array",
                                    "description": (
                                        "Field-level differences. `baseline_value` is "
                                        "the validated historical value and "
                                        "`current_value` is the current observation; "
                                        "the two are separately named so neither can be "
                                        "mistaken for the other."
                                    ),
                                    "items": {
                                        "type": "object",
                                        "required": ["variable", "baseline_value",
                                                     "current_value", "drift_category",
                                                     "security_relevance"],
                                        "properties": {
                                            "variable": _STR,
                                            "label": _STR,
                                            "baseline_value": {"description": "Validated value."},
                                            "current_value": {"description": "Observed value."},
                                            "comparison_rule": _STR,
                                            "security_relevance": {"type": "boolean"},
                                            "drift_category": {
                                                "type": "string",
                                                "enum": ["configuration_drift"],
                                            },
                                            "finding_id": {"type": "string", "nullable": True},
                                            "severity": {"type": "string", "nullable": True},
                                        },
                                    },
                                },
                                "unchanged_variables": {
                                    "type": "array",
                                    "items": _STR,
                                },
                                "unknown_variables": {
                                    "type": "array",
                                    "description": (
                                        "Comparable fields that could not be "
                                        "established from one side; neither compared "
                                        "nor counted as agreement."
                                    ),
                                    "items": _STR,
                                },
                                "drift_categories": {
                                    "type": "array",
                                    "items": {
                                        "type": "string",
                                        "enum": ["configuration_drift"],
                                    },
                                },
                                "risk": {
                                    "type": "object",
                                    "nullable": True,
                                    "description": (
                                        "Findings raised by the comparison, scored by "
                                        "the existing risk engine under the existing "
                                        "policy. There is no separate drift scale."
                                    ),
                                },
                                "reason": _STR,
                                "model_version": _STR,
                                "rule_id": _STR,
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
