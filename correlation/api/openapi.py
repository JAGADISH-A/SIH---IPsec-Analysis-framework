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

from ..analysis.reports import EXECUTIVE_QUESTIONS

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


_STATE_ENUM = [
    "OBSERVED",
    "CONFIGURED",
    "INFERRED",
    "ASSESSED",
    "UNKNOWN",
    "NOT_AVAILABLE",
    "NOT_APPLICABLE",
]

_STATE_FIELD = {
    "type": "string",
    "enum": list(_STATE_ENUM),
    "description": (
        "Explicit state of this value (Phase-1 contract). The seven states "
        "are exhaustive: unavailable runtime evidence is reported as "
        "NOT_AVAILABLE or UNKNOWN, never as a negative finding."
    ),
}

#: The four keys every analytical product carries under the Phase-1 contract.
_CONTRACT = {
    "producer": {
        "type": "string",
        "description": (
            "The module-level call that produced this product (Phase-1 "
            "analytical contract): `producer`, `source`/`evidence`, explicit "
            "`state`, API representation and `reason`."
        ),
    },
    "state": dict(_STATE_FIELD),
    "reason": {
        "type": "string",
        "description": "Why this product reports what it reports, in the producer's own words.",
    },
    "source": {
        "type": "string",
        "description": (
            "Where the product's evidence came from: an artifact path, an "
            "engine or a policy version -- never a claim the product did not "
            "make."
        ),
    },
}

#: Any JSON value, typed as such rather than left as an untyped object.
_ANY_TYPE = ["null", "boolean", "integer", "number", "string", "array", "object"]


def _ANY(description: str) -> Dict[str, Any]:
    return {"description": description, "type": list(_ANY_TYPE)}


def _list(description: str, items: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "type": "array",
        "description": description,
        "items": items,
    }


def _free(description: str) -> Dict[str, Any]:
    """A JSON object whose internals are documented where they are produced.

    Used for engine metadata blocks that are passed through verbatim: typing
    them here would restate a contract that already lives with its producer.
    """
    return {
        "type": "object",
        "description": description,
        "additionalProperties": True,
    }


def _product(
    description: str,
    properties: Dict[str, Any],
    required: List[str] = None,
) -> Dict[str, Any]:
    """A component schema for one analytical product.

    The Phase-1 contract keys are always present and always required; the
    product's own keys are merged in after them, so a generator emits the
    contract before the payload.
    """
    contract_required = sorted(_CONTRACT)
    return {
        "type": "object",
        "description": description,
        "required": contract_required if required is None else required,
        "properties": {**_CONTRACT, **properties},
    }


def _json_ok(ok: str = "ok", schema: str = None) -> Dict[str, Any]:
    """The standard 200 for a route whose payload has a component schema.

    ``schema`` names a component under ``#/components/schemas``. Leaving it
    out keeps the untyped legacy shape, which every Phase-8 route now avoids:
    a response with no schema is one a client generator cannot use.
    """
    return {
        "200": {
            "description": ok,
            "content": {_JSON: {"schema": _ref(schema) if schema else {"type": "object"}}},
        }
    }


def _sub_resource_response(resource: str, product: str) -> Dict[str, Any]:
    """The typed 200 for one ``/api/assessments/{id}/{sub-resource}`` route.

    The envelope (``assessment_id`` / ``resource`` / ``data``) is shared by all
    fifteen sub-resources, so it is documented once as
    ``AssessmentSubResourceResponse`` and narrowed here: this route's
    ``resource`` is a constant and its ``data`` is the named product document
    rather than an untyped object.
    """
    return {
        "allOf": [
            _ref("AssessmentSubResourceResponse"),
            {
                "type": "object",
                "properties": {
                    "resource": {"type": "string", "const": resource},
                    "data": _ref(product),
                },
            },
        ]
    }


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
        tags=["phase8"], responses=_json_ok(schema="ApiHealth"))
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
    # Each entry names the component schema its 200 answers with: the bundle
    # route references its document directly, and each sub-resource narrows the
    # shared envelope so `data` is the product document and not a bare object.
    for suffix, oid, summary, resource, product in (
        ("", "getAssessment", "One full assessment bundle.",
         None, "AssessmentBundle"),
        ("/expected", "getAssessmentExpected",
         "The configured (expected) IPsec state this assessment compared against.",
         "expected", "ExpectedConfiguration"),
        ("/observed", "getAssessmentObserved",
         "The observed IPsec state, exactly as it was recorded.",
         "observed", "ObservedStateDocument"),
        ("/correlation", "getAssessmentCorrelation", "Per-SA correlation evidence.",
         "correlation", "CorrelationProduct"),
        ("/risk", "getAssessmentRisk", "Risk assessment and findings.",
         "risk", "RiskProduct"),
        ("/xai", "getAssessmentXai", "Explainability output.",
         "xai", "XaiProduct"),
        ("/ml", "getAssessmentMl", "ML classification and its inputs.",
         "ml", "MlProduct"),
        ("/evidence", "getAssessmentEvidence", "Evidence references for the assessment.",
         "evidence", "EvidenceProduct"),
        ("/ipsec-state", "getAssessmentIpsecState", "Expected vs observed IPsec state.",
         "ipsec-state", "ObservedStateDocument"),
        ("/sa", "getAssessmentSa",
         "Security associations: establishment, direction, packet counts, sequence "
         "and first/last packet, with unavailable lifetime facts stated as such.",
         "sa", "SaProduct"),
        ("/crypto-evidence", "getAssessmentCryptoEvidence",
         "Per-property runtime evidence for the configured cryptography: what is "
         "observable at runtime, what is configuration only, and why.",
         "crypto-evidence", "CryptoEvidenceProduct"),
        ("/replay", "getAssessmentReplay",
         "Replay-window assessment: duplicates, backward steps, gaps and the "
         "evidence level behind each, with gaps never reported as replays.",
         "replay", "ReplayProduct"),
        ("/metadata-exposure", "getAssessmentMetadataExposure",
         "Metadata an on-path observer can read from this capture, with "
         "limitations.",
         "metadata-exposure", "MetadataExposureProduct"),
        ("/threat-matrix", "getAssessmentThreatMatrix",
         "Findings mapped to threats, evidence, impact and recommendation.",
         "threat-matrix", "ThreatMatrixProduct"),
        ("/report", "getAssessmentReport",
         "Technical report: fourteen sections over the same evidence as the "
         "bundle, from the executive summary to evidence and provenance.",
         "report", "TechnicalReport"),
        ("/executive-report", "getAssessmentExecutiveReport",
         "Executive report answering what was assessed, the security posture, "
         "the major risks, the evidence behind them and what should be fixed.",
         "executive-report", "ExecutiveReport"),
    ):
        response_schema = (
            _ref(product) if resource is None
            else _sub_resource_response(resource, product)
        )
        paths[f"/api/assessments/{{id}}{suffix}"] = _get(
            f"/api/assessments/{{id}}{suffix}", oid, summary,
            tags=["phase8"],
            params=[_param("id", "path", _STR, "Assessment id.", required=True)],
            responses={**{"200": {"description": "ok",
                                  "content": {_JSON: {"schema": response_schema}}}},
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

    paths["/api/v1/assets"] = _get(
        "/api/v1/assets",
        "getAssets",
        "The asset ids an operator declared a mission profile for.",
        tags=["mission"],
        description=(
            "The only legitimate source for an asset selector: a client that "
            "hardcoded `gw-a`/`gw-b` would offer assets this deployment never "
            "declared and hide assets it did.\n\n"
            "Declaration is explicit. `configured: false` with an empty list means "
            "no mission profile file was supplied to this store, which is not a "
            "claim that the network has no assets -- assets are never inferred "
            "from traffic, addresses or ML output. `store_asset_id` is the asset "
            "this store was started with, the one the custody explanation reports."
        ),
        responses={
            "200": {
                "description": "The declared asset ids.",
                "content": {_JSON: {"schema": _ref("AssetList")}},
            },
            **_ERROR_RESPONSES,
        })
    paths["/api/v1/assets/{asset_id}/context"] = _get(
        "/api/v1/assets/{asset_id}/context",
        "getAssetContext",
        "One asset's mission context, at a stated technical risk.",
        tags=["mission"],
        description=(
            "The mission-context surface addressed by a *selected* asset. The "
            "custody route publishes the same document, but only for the asset the "
            "store was started with, so a caller cannot ask about any other "
            "declared asset.\n\n"
            "This route computes nothing itself: it reads a technical "
            "risk/severity pair from the store and passes them, with the "
            "`asset_id` from the path, to the same `mission_context()` the "
            "custody chain uses. Selecting an asset does not re-score anything "
            "and does not rebind the store -- `store_asset_id` is unchanged, and "
            "the custody explanation keeps reporting the startup asset.\n\n"
            "The technical risk being contextualised is stated in the response "
            "(`technical_risk`, `technical_severity`, `technical_risk_source`, "
            "`assessment_id`), because the same asset contextualises a different "
            "score against a different assessment. Omitting `assessment_id` uses "
            "the store's highest-risk assessment and says so via "
            "`technical_risk_source: store_highest_risk`.\n\n"
            "An asset with no declared profile is not an error: `mission_context` "
            "answers `status: not_configured` with a reason, `profile` and `risk` "
            "null and no assumed criticality, so absent context can never be read "
            "as benign context."
        ),
        params=[
            _param("asset_id", "path", _STR, "Declared asset id.", required=True),
            _param("assessment_id", "query", _STR,
                   "Contextualise against this assessment instead of the store's "
                   "highest-risk assessment. 404 when it is not in this store."),
        ],
        responses={
            "200": {
                "description": "The asset's mission context.",
                "content": {_JSON: {"schema": _ref("AssetContext")}},
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
                "MissionContext": {
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
                "AssetList": {
                    "type": "object",
                    "description": (
                        "The declared asset ids, for a selector. `configured: false` "
                        "with an empty `assets` array means no mission profile file "
                        "was supplied to this store -- not that the network has no "
                        "assets."
                    ),
                    "required": ["configured", "store_asset_id", "assets",
                                 "count", "total"],
                    "properties": {
                        "api": _STR,
                        "read_only": {"type": "boolean", "const": True},
                        "configured": {"type": "boolean"},
                        "reason": {"type": "string", "nullable": True},
                        "store_asset_id": {
                            "type": "string",
                            "nullable": True,
                            "description": (
                                "The asset this store was started with (`--asset-id`), "
                                "which is the one the custody explanation reports. "
                                "Unaffected by any asset selected elsewhere."
                            ),
                        },
                        "schema_version": _STR,
                        "context_source": _STR,
                        "source": {
                            "type": "string",
                            "nullable": True,
                            "description": "Repository-relative profile path; never absolute.",
                        },
                        "source_sha256": {"type": "string", "nullable": True},
                        "assets": {
                            "type": "array",
                            "items": _STR,
                            "description": "Declared asset ids, sorted.",
                        },
                        "count": {"type": "integer", "minimum": 0},
                        "total": {"type": "integer", "minimum": 0},
                    },
                },
                "AssetContext": {
                    "type": "object",
                    "description": (
                        "One selected asset's mission context, plus the technical "
                        "risk it was contextualised against. Read-only: selecting an "
                        "asset neither re-scores anything nor rebinds the store."
                    ),
                    "required": ["asset_id", "assessment_id",
                                 "technical_risk_source", "technical_risk",
                                 "technical_severity", "mission_context"],
                    "properties": {
                        "api": _STR,
                        "read_only": {"type": "boolean", "const": True},
                        "asset_id": {
                            "type": "string",
                            "description": "The selected asset, echoed from the path.",
                        },
                        "assessment_id": {
                            "type": "string",
                            "nullable": True,
                            "description": (
                                "The assessment whose risk was contextualised; null "
                                "when the store's highest-risk assessment was used."
                            ),
                        },
                        "technical_risk_source": {
                            "type": "string",
                            "enum": ["assessment_header", "store_highest_risk"],
                            "description": (
                                "How `technical_risk`/`technical_severity` were "
                                "chosen. Published so a reader can tell a "
                                "caller-directed result from a store default."
                            ),
                        },
                        "technical_risk": {"type": "integer", "minimum": 0},
                        "technical_severity": _STR,
                        "mission_context": _ref("MissionContext"),
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
                        # Extracted to a named component so the asset-context route
                        # documents the identical shape instead of a second copy.
                        "mission_context": {
                            "allOf": [_ref("MissionContext")],
                            "nullable": True,
                            "description": (
                                "Externally supplied asset context and the "
                                "contextualized risk it produced, for the asset this "
                                "store was started with. The same document is served "
                                "per selected asset at "
                                "`/api/v1/assets/{asset_id}/context`."
                            ),
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
            },
                "ApiHealth": {
                    "type": "object",
                    "description": (
                        "Liveness of the analytics API itself. It reports the "
                        "store it serves and states, as data, that the surface "
                        "is adapter-only: it consumes Phase 4-7 outputs and "
                        "never recomputes a score, severity, comparison or "
                        "explanation."
                    ),
                    "required": ["status", "service", "read_only"],
                    "properties": {
                        "status": {"type": "string", "const": "ok"},
                        "service": _STR,
                        "api_schema_version": _STR,
                        "store_version": _STR,
                        "total_assessments": {"type": "integer", "minimum": 0},
                        "read_only": {"type": "boolean", "const": True},
                        "note": {
                            "type": "string",
                            "description": "The adapter-only contract, in the producer's words.",
                        },
                    },
                },
                "AssessmentSubResourceResponse": {
                    "type": "object",
                    "description": (
                        "Envelope shared by every "
                        "`/api/assessments/{id}/{sub-resource}` route: which "
                        "assessment, which resource, and the product document "
                        "under `data`. Each route narrows `resource` to a "
                        "constant and `data` to its product schema with "
                        "`allOf`."
                    ),
                    "required": ["assessment_id", "resource", "data"],
                    "properties": {
                        "assessment_id": _STR,
                        "resource": {
                            "type": "string",
                            "description": "The sub-resource name exactly as it appears in the path.",
                        },
                        "data": {
                            "type": "object",
                            "description": (
                                "The product document. Its schema is named by "
                                "the route that returns it."
                            ),
                        },
                    },
                },
                "AssessmentBundle": {
                    "type": "object",
                    "description": (
                        "One full assessment. `expected`, `observed` and "
                        "`ipsec_state` are the inputs the analysis ran on; "
                        "every analytical product (`correlation`, `ml`, `risk`, "
                        "`xai`, `evidence`, `sa`, `crypto_evidence`, "
                        "`replay_assessment`, `metadata_exposure`, "
                        "`threat_matrix`, `report`, `executive_report`) carries "
                        "the Phase-1 contract: `producer`, `state`, `reason` "
                        "and `source`."
                    ),
                    "required": [
                        "assessment_id", "slot", "scenario", "dataset_run_id",
                        "identity", "expected", "observed", "correlation",
                        "risk", "report", "executive_report",
                    ],
                    "properties": {
                        "assessment_id": _STR,
                        "slot": _STR,
                        "scenario": {
                            "type": "string",
                            "description": "The scenario text this assessment was registered for.",
                        },
                        "dataset_run_id": _STR,
                        "identity": _free(
                            "Assessment identity: run id, sequence, experiment, "
                            "attempt and window index."
                        ),
                        "expected": _ref("ExpectedConfiguration"),
                        "observed": _ref("ObservedStateDocument"),
                        "ipsec_state": _ref("ObservedStateDocument"),
                        "correlation": _ref("CorrelationProduct"),
                        "ml": _ref("MlProduct"),
                        "risk": _ref("RiskProduct"),
                        "xai": _ref("XaiProduct"),
                        "evidence": _ref("EvidenceProduct"),
                        "sa": _ref("SaProduct"),
                        "crypto_evidence": _ref("CryptoEvidenceProduct"),
                        "replay_assessment": _ref("ReplayProduct"),
                        "metadata_exposure": _ref("MetadataExposureProduct"),
                        "threat_matrix": _ref("ThreatMatrixProduct"),
                        "report": _ref("TechnicalReport"),
                        "executive_report": _ref("ExecutiveReport"),
                        "sources": {
                            "type": "array",
                            "description": (
                                "Artifacts this bundle was built from, with "
                                "their digests and roles."
                            ),
                            "items": {"type": "object"},
                        },
                    },
                },
                "ExpectedConfiguration": {
                    "type": "object",
                    "description": (
                        "The configured side: what the materialized plan asks "
                        "for. It is an input to the analysis, so it carries no "
                        "Phase-1 contract keys and no runtime claim."
                    ),
                    "required": ["mode", "address_family", "ike", "esp",
                                 "traffic", "configuration_id"],
                    "properties": {
                        "mode": {"type": "string", "description": "Encapsulation mode as configured."},
                        "address_family": {"type": "string"},
                        "ike": _free("Configured IKE proposal (version, integrity, DH group)."),
                        "esp": _free(
                            "Configured ESP proposal: encryption, integrity, "
                            "DH group, PFS."
                        ),
                        "traffic": _free("Configured traffic profile and related traffic expectations."),
                        "capture_filter": _STR,
                        "configuration_id": _STR,
                        "security_posture": {
                            "type": "string",
                            "description": "Band the plan configures (STRONG/GOOD/MEDIUM/WEAK/WORST as recorded).",
                        },
                    },
                },
                "ObservedStateDocument": {
                    "type": "object",
                    "description": (
                        "The observed IPsec state exactly as the state builder "
                        "recorded it. Returned by `/observed` and by "
                        "`/ipsec-state`, which is the same document: the "
                        "configured side of that comparison is `/expected`. An "
                        "input to the analysis, never a product of it."
                    ),
                    "required": ["present", "timestamp_ns"],
                    "properties": {
                        "present": {
                            "type": "boolean",
                            "description": "False when no state snapshot was attached to this assessment.",
                        },
                        "timestamp_ns": {"type": "integer", "minimum": 0},
                        "endpoints": _free("Outer source/destination pair, when the snapshot recorded one."),
                        "active": {"type": "boolean"},
                        "tunnel_seen": {
                            "type": "boolean",
                            "description": (
                                "Any traffic was observed. It does NOT "
                                "establish tunnel mode and is never used to."
                            ),
                        },
                        "packets_seen": {"type": "integer", "minimum": 0},
                        "bytes_seen": {"type": "integer", "minimum": 0},
                        "packets_a_to_b": {"type": "integer", "minimum": 0},
                        "packets_b_to_a": {"type": "integer", "minimum": 0},
                        "bytes_a_to_b": {"type": "integer", "minimum": 0},
                        "bytes_b_to_a": {"type": "integer", "minimum": 0},
                        "ike_seen": {"type": "boolean"},
                        "ike_nat_t_seen": {"type": "boolean"},
                        "esp_seen": {"type": "boolean"},
                        "ah_seen": {"type": "boolean"},
                        "observed_ike_activity": {"type": "boolean"},
                        "last_ike_timestamp_ns": {"type": ["integer", "null"]},
                        "last_ike_nat_t_timestamp_ns": {"type": ["integer", "null"]},
                        "last_esp_timestamp_ns": {"type": ["integer", "null"]},
                        "last_ah_timestamp_ns": {"type": ["integer", "null"]},
                        "spis": _list(
                            "Per-SPI observation: spi, direction (A_TO_B or "
                            "B_TO_A), packet counts and sequence progression.",
                            {"type": "object"},
                        ),
                        "transitions": _list(
                            "Recorded observation transitions, each naming the "
                            "event it came from.",
                            {"type": "object"},
                        ),
                        "observation_start_ns": {"type": ["integer", "null"]},
                        "last_packet_timestamp_ns": {"type": ["integer", "null"]},
                        "active_timeout_ms": {"type": ["integer", "null"]},
                        "outer_endpoint_pairs": _ANY("Recorded outer endpoint pairs, or null when none was recorded."),
                        "spi_less_esp_packets": _ANY("Count of ESP packets with no SPI, or null when not recorded."),
                        "sa_snapshots": _ANY("Recorded SA snapshots, or null when the snapshot carries none."),
                        "sa_groups": _ANY("Recorded bidirectional SA groups, or null when none was resolved."),
                    },
                },
                "CorrelationProduct": _product(
                    "Phase 4 comparison of the configured plan against the "
                    "observed snapshot. `status` is the Phase-4 vocabulary; "
                    "`state` is the Phase-1 state of the product itself, and "
                    "each row carries its own `state` and `verdict`.",
                    {
                        "status": {
                            "type": "string",
                            "enum": ["MATCH", "MISMATCH", "UNKNOWN",
                                     "NOT_APPLICABLE"],
                            "description": "Overall comparison status reported by the engine.",
                        },
                        "rows": _list(
                            "One row per compared variable, sorted by variable.",
                            _ref("CorrelationRow"),
                        ),
                        "status_counts": _free(
                            "Counts keyed by the four comparison statuses."
                        ),
                        "metadata": _free(
                            "Engine metadata passed through verbatim: "
                            "comparison engine version, rules executed, "
                            "observation completeness, ml_evaluated."
                        ),
                    },
                    required=sorted(_CONTRACT) + ["status", "rows"],
                ),
                "CorrelationRow": {
                    "type": "object",
                    "description": (
                        "One compared variable. `verdict` is the brief's name "
                        "for this row's `status`: the same canonical value "
                        "carried twice, never a second decision."
                    ),
                    "required": ["variable", "status", "verdict", "state"],
                    "properties": {
                        "variable": _STR,
                        "status": {
                            "type": "string",
                            "enum": ["MATCH", "MISMATCH", "UNKNOWN",
                                     "NOT_APPLICABLE"],
                        },
                        "verdict": {
                            "type": "string",
                            "enum": ["MATCH", "MISMATCH", "UNKNOWN",
                                     "NOT_APPLICABLE"],
                            "description": "Alias of `status`, under the brief's name for it.",
                        },
                        "expected_value": _ANY("Configured side of this comparison."),
                        "observed_value": _ANY("Observed side of this comparison; null means no runtime value was recorded."),
                        "configured_value": _ANY(
                            "The expected side under the brief's name; equal to "
                            "`expected_value`."
                        ),
                        "comparison_rule": {"type": ["string", "null"]},
                        "reason": {"type": ["string", "null"]},
                        "state": dict(_STATE_FIELD),
                        "runtime_observable": {
                            "type": "boolean",
                            "description": (
                                "True when this observation actually produced "
                                "a value for the variable."
                            ),
                        },
                        "evidence_source": {"type": ["string", "null"]},
                        "evidence_refs": _list(
                            "Evidence references the comparison cited.",
                            {"type": "object"},
                        ),
                    },
                },
                "MlProduct": _product(
                    "ML-derived evidence with its transparency block. It is "
                    "model-derived inference (state INFERRED when present): it "
                    "never overrides an observation and is never a protocol "
                    "observation itself.",
                    {
                        "present": {"type": "boolean"},
                        "model": {"type": ["string", "null"]},
                        "model_version": {"type": ["string", "null"]},
                        "traffic_class": {"type": ["string", "null"]},
                        "predicted_class": {
                            "type": ["string", "null"],
                            "description": "The canonical class the model predicted, or null.",
                        },
                        "classification_confidence": {"type": ["number", "null"]},
                        "probabilities": {
                            "type": ["object", "null"],
                            "description": (
                                "The full probability vector keyed by class "
                                "when the producer supplied one; null is never "
                                "a guessed distribution."
                            ),
                        },
                        "classes": {
                            "type": ["array", "null"],
                            "items": _STR,
                            "description": (
                                "The class names the probability vector is "
                                "indexed by, only when a full vector exists "
                                "whose keys are exactly the six canonical "
                                "traffic profiles; null otherwise."
                            ),
                        },
                        "inference_status": {
                            "type": "string",
                            "enum": ["NOT_EXECUTED", "COMPLETED", "INCOMPLETE"],
                            "description": "What happened to inference, never how good the model is.",
                        },
                        "provenance": {
                            "type": ["object", "null"],
                            "description": (
                                "Where the result came from, copied verbatim "
                                "from the producer's extras: source, bridge, "
                                "window id, artifact digest and the like."
                            ),
                        },
                        "predicted_vs_policy": _ref("PredictedVsPolicy"),
                        "anomaly": _ANY("Always null: the model has no anomaly capability."),
                        "anomaly_score": _ANY("Always null: the model has no anomaly capability."),
                    },
                    required=sorted(_CONTRACT) + ["present", "inference_status"],
                ),
                "PredictedVsPolicy": {
                    "type": "object",
                    "description": (
                        "Predicted class vs the configured traffic profile, "
                        "using the Phase-4 status vocabulary because this is a "
                        "comparison of two recorded values."
                    ),
                    "required": ["status", "predicted_class",
                                 "policy_expected_class", "reason"],
                    "properties": {
                        "status": {
                            "type": "string",
                            "enum": ["MATCH", "MISMATCH", "UNKNOWN",
                                     "NOT_APPLICABLE"],
                        },
                        "predicted_class": {"type": ["string", "null"]},
                        "policy_expected_class": {"type": ["string", "null"]},
                        "compared_against": _STR,
                        "reason": _STR,
                    },
                },
                "RiskProduct": _product(
                    "Phase 6 risk assessment. Every score, severity and "
                    "finding is the risk engine's own; this document copies "
                    "them and never recomputes any of them.",
                    {
                        "schema_version": _STR,
                        "risk_engine_version": _STR,
                        "risk_policy_version": _STR,
                        "overall_score": {
                            "type": "integer",
                            "minimum": 0,
                            "maximum": 100,
                        },
                        "severity": {
                            "type": "string",
                            "enum": ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"],
                        },
                        "identity": _free("Assessment identity as the risk engine recorded it."),
                        "findings": _list(
                            "Risk findings in engine order, each with its own "
                            "state, evidence and score contribution.",
                            _ref("RiskFinding"),
                        ),
                        "evidence_refs": _list(
                            "Evidence references the assessment consumed.",
                            _ref("EvidenceReference"),
                        ),
                        "score_detail": _free(
                            "Per-category score contributions under the "
                            "per-category cap, as the engine recorded them."
                        ),
                        "metadata": _free(
                            "Risk engine metadata: evidence policy, unknown "
                            "handling, rules executed, expected configuration "
                            "and replay evidence."
                        ),
                    },
                    required=sorted(_CONTRACT) + [
                        "overall_score", "severity", "findings",
                    ],
                ),
                "RiskFinding": {
                    "type": "object",
                    "description": (
                        "One risk finding. `state` says why the finding's "
                        "value holds; `evidence` is the structured block of "
                        "what backs it; severity and score belong to the risk "
                        "engine alone."
                    ),
                    "required": ["finding_id", "rule_id", "severity", "score",
                                 "state", "evidence"],
                    "properties": {
                        "finding_id": _STR,
                        "rule_id": _STR,
                        "category": _STR,
                        "severity": {
                            "type": "string",
                            "enum": ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"],
                        },
                        "score": {"type": "number"},
                        "score_added": {
                            "type": "number",
                            "description": "What this finding added after the per-category cap.",
                        },
                        "related_variable": {"type": ["string", "null"]},
                        "condition": {"type": ["string", "null"]},
                        "title": _STR,
                        "description": {"type": ["string", "null"]},
                        "reason": _STR,
                        "configured_value": _ANY("The expected side of this finding."),
                        "expected_value": _ANY("What Phase 4 compared against."),
                        "observed_value": _ANY("The observed counterpart, when one exists."),
                        "source": _STR,
                        "state": dict(_STATE_FIELD),
                        "evidence_type": _STR,
                        "runtime_applicable": {
                            "type": "boolean",
                            "description": (
                                "False for configuration-only findings: no "
                                "runtime evidence could confirm or refute "
                                "them, so none is claimed."
                            ),
                        },
                        "confidence": {"type": ["number", "null"]},
                        "model_version": {"type": ["string", "null"]},
                        "evidence": {
                            "type": "object",
                            "description": (
                                "What backs this finding, structured: type, "
                                "source, state, reference count, the "
                                "references themselves and any limitation."
                            ),
                            "properties": {
                                "evidence_type": _STR,
                                "source": _STR,
                                "state": dict(_STATE_FIELD),
                                "ref_count": {"type": "integer", "minimum": 0},
                                "refs": _list(
                                    "Evidence references this finding cites.",
                                    _ref("EvidenceReference"),
                                ),
                                "limitations": _list(
                                    "What this evidence does not establish.",
                                    _STR,
                                ),
                            },
                        },
                        "evidence_refs": _list(
                            "The same references, at the finding's top level.",
                            _ref("EvidenceReference"),
                        ),
                    },
                },
                "EvidenceReference": {
                    "type": "object",
                    "description": (
                        "An evidence reference as its producer recorded it. "
                        "Artifacts are described by repository-relative source "
                        "path and content digest; a host path never appears."
                    ),
                    "required": ["evidence_id"],
                    "properties": {
                        "evidence_id": _STR,
                        "artifact_type": {"type": ["string", "null"]},
                        "artifact_sha256": {"type": ["string", "null"]},
                        "byte_size": {"type": ["integer", "null"]},
                        "pcap_path": {"type": ["string", "null"]},
                        "source": {"type": ["string", "null"]},
                        "timestamp": {"type": ["integer", "null"]},
                        "sequence": {"type": ["integer", "null"]},
                        "run_id": {"type": ["string", "null"]},
                        "experiment_id": {"type": ["string", "null"]},
                        "window_index": {"type": ["integer", "null"]},
                        "capture_sequence": {"type": ["integer", "null"]},
                        "capture_start_ns": {"type": ["integer", "null"]},
                        "capture_end_ns": {"type": ["integer", "null"]},
                        "packet_start": _ANY("Packet range start, as recorded."),
                        "packet_end": _ANY("Packet range end, as recorded."),
                        "audit_event_reference": {"type": ["string", "null"]},
                    },
                },
                "XaiProduct": _product(
                    "Phase 7 explainability: why the score is what it is, "
                    "per finding and per unknown, in the engine's own words.",
                    {
                        "schema_version": _STR,
                        "identity": _free("Assessment identity as the engine recorded it."),
                        "summary": _free(
                            "Compact summary: score, severity, counts and the "
                            "overall explanation text."
                        ),
                        "finding_explanations": _list(
                            "One explanation per finding, quoting the rule and "
                            "its contribution.",
                            {"type": "object"},
                        ),
                        "ml_explanations": _list(
                            "ML explanations; empty because this backend "
                            "records no ML contribution to score.",
                            {"type": "object"},
                        ),
                        "unknown_explanations": _list(
                            "Why each unknown stayed unknown instead of "
                            "becoming a finding.",
                            {"type": "object"},
                        ),
                        "not_applicable_explanations": _list(
                            "Why each not-applicable variable was not scored.",
                            {"type": "object"},
                        ),
                        "evidence_summary": _free("Evidence the explanations cited."),
                        "score_explanation": _free(
                            "Score decomposition: raw sum, per-category "
                            "totals, contributions and the severity band."
                        ),
                        "metadata": _free(
                            "Engine version, authority, determinism and "
                            "evidence policy."
                        ),
                    },
                    required=sorted(_CONTRACT) + ["summary"],
                ),
                "EvidenceProduct": _product(
                    "The evidence references this assessment's products "
                    "cited, with their sources and the limitation that none "
                    "was invented.",
                    {
                        "total_refs": {"type": "integer", "minimum": 0},
                        "refs": _list(
                            "One entry per reference, as the API projects it "
                            "(path is repository-relative; no host path).",
                            _ref("EvidenceRefView"),
                        ),
                        "sources": _list(
                            "Distinct source names across the references.",
                            _STR,
                        ),
                        "limitation": {
                            "type": ["string", "null"],
                            "description": (
                                "Stated when no reference was recorded; the "
                                "gap is reported, never filled."
                            ),
                        },
                    },
                    required=sorted(_CONTRACT) + ["total_refs", "refs"],
                ),
                "EvidenceRefView": {
                    "type": "object",
                    "description": (
                        "The API projection of one evidence reference: the "
                        "fields a dashboard needs, with no host filesystem "
                        "path."
                    ),
                    "properties": {
                        "pcap_path": {"type": ["string", "null"]},
                        "capture_sequence": {"type": ["integer", "null"]},
                        "audit_event_reference": {"type": ["string", "null"]},
                        "source": {"type": ["string", "null"]},
                        "timestamp": {"type": ["integer", "null"]},
                    },
                },
                "SaProduct": _product(
                    "Security associations from the recorded SPI state: "
                    "establishment, direction, packet counts, sequence "
                    "progression and first/last observed packet, with "
                    "lifetime and rekey reported NOT_AVAILABLE where the "
                    "observation path records none.",
                    {
                        "associations": _list(
                            "One entry per security association, each with "
                            "spi, direction, sequence, lifetime and rekey "
                            "blocks carrying their own state.",
                            {"type": "object"},
                        ),
                        "summary": _free(
                            "Counts and observation window derived from the "
                            "same snapshot."
                        ),
                        "limitations": _list(
                            "What this product does not establish.",
                            _STR,
                        ),
                    },
                    required=sorted(_CONTRACT) + ["associations"],
                ),
                "CryptoEvidenceProduct": _product(
                    "Per-property runtime evidence for the configured "
                    "cryptography: what a capture can establish at runtime, "
                    "what is configuration only, and why. A property that is "
                    "not observable reports its configured value beside a "
                    "NOT_AVAILABLE state, never as if it had been seen.",
                    {
                        "properties": _list(
                            "One entry per property: configured value, "
                            "runtime value, runtime_observable, evidence "
                            "source, state and reason.",
                            {"type": "object"},
                        ),
                        "by_property": _free(
                            "The same entries keyed by property name."
                        ),
                        "runtime_established": _list(
                            "Properties this capture actually established.",
                            _STR,
                        ),
                        "limitations": _list(
                            "What the capture cannot establish about the "
                            "negotiated cryptography.",
                            _STR,
                        ),
                    },
                    required=sorted(_CONTRACT) + ["properties"],
                ),
                "ReplayProduct": _product(
                    "Replay-window assessment over the recorded sequence "
                    "journal: duplicates, backward steps, gaps and the "
                    "evidence level behind each. A gap is never reported as "
                    "a replay.",
                    {
                        "status": {
                            "type": "string",
                            "enum": ["OBSERVED", "NO_EVIDENCE",
                                     "INSUFFICIENT_DATA"],
                        },
                        "duplicate_sequences": {"type": "integer", "minimum": 0},
                        "backward_sequences": {"type": "integer", "minimum": 0},
                        "sequence_gaps": {"type": "integer", "minimum": 0},
                        "highest_sequence": {"type": ["integer", "null"]},
                        "per_spi": _list(
                            "Per-SPI sequence assessment with its own state, "
                            "status and reason.",
                            {"type": "object"},
                        ),
                        "evidence": _list(
                            "The sequence aggregates the assessment read.",
                            {"type": "object"},
                        ),
                        "limitations": _list(
                            "What the sequence evidence cannot establish.",
                            _STR,
                        ),
                    },
                    required=sorted(_CONTRACT) + ["status"],
                ),
                "MetadataExposureProduct": _product(
                    "What an on-path observer can actually read from this "
                    "capture, dimension by dimension. These are "
                    "observation-level statements: they carry no severity and "
                    "no score, because the risk engine is the only scorer.",
                    {
                        "risk_level": {
                            "type": "string",
                            "enum": ["HIGH", "MEDIUM", "LOW", "NONE"],
                            "description": "Chosen by the documented ladder, which is published beside it.",
                        },
                        "risk_ladder": _list(
                            "The ladder that produced `risk_level`, in "
                            "evaluation order.",
                            {"type": "object"},
                        ),
                        "observable_metadata": _list(
                            "Every dimension this product classifies, each "
                            "with its own state, exposure and reason.",
                            _ref("MetadataDimension"),
                        ),
                        "findings": _list(
                            "Observation-level exposure findings (EXPOSED / "
                            "NOT_EXPOSED / NOT_OBSERVABLE), unscored.",
                            {"type": "object"},
                        ),
                        "evidence": _list(
                            "The observation each finding rests on.",
                            {"type": "object"},
                        ),
                        "limitations": _list(
                            "What an observable dimension does and does not "
                            "claim.",
                            _STR,
                        ),
                    },
                    required=sorted(_CONTRACT) + [
                        "risk_level", "observable_metadata",
                    ],
                ),
                "MetadataDimension": {
                    "type": "object",
                    "description": (
                        "One metadata dimension: whether this sensor can see "
                        "it, the value it recorded, and why the state is what "
                        "it is. Not observable is never the same as safe."
                    ),
                    "required": ["dimension", "observable", "state",
                                 "exposure", "reason"],
                    "properties": {
                        "dimension": _STR,
                        "observable": {"type": "boolean"},
                        "value": _ANY("The value this sensor recorded, or null when it recorded none."),
                        "state": dict(_STATE_FIELD),
                        "source": _STR,
                        "reason": _STR,
                        "exposure": {
                            "type": "string",
                            "enum": ["EXPOSED", "NOT_EXPOSED", "NOT_OBSERVABLE"],
                        },
                    },
                },
                "ThreatMatrixProduct": _product(
                    "Every finding mapped onto exactly one threat row, with "
                    "evidence, impact and the recommendation cell quoted from "
                    "the response rule registry. No threat appears here that "
                    "no finding produced.",
                    {
                        "entries": _list(
                            "One row per finding, in finding order.",
                            _ref("ThreatMatrixEntry"),
                        ),
                        "categories": _list(
                            "Every threat category with its entry count, so "
                            "an absent category is visible rather than "
                            "missing.",
                            {"type": "object"},
                        ),
                        "entry_count": {"type": "integer", "minimum": 0},
                        "limitations": _list(
                            "What the matrix does not establish, including "
                            "that an empty matrix means 'no finding'.",
                            _STR,
                        ),
                    },
                    required=sorted(_CONTRACT) + ["entries", "entry_count"],
                ),
                "ThreatMatrixEntry": {
                    "type": "object",
                    "description": (
                        "One threat row. Severity is copied from the finding "
                        "and never recomputed; the recommendation is quoted "
                        "from the registry, and says so when no rule is "
                        "registered."
                    ),
                    "required": ["finding", "threat", "rule_id", "recommendation"],
                    "properties": {
                        "finding": {
                            "type": "string",
                            "description": "Finding id, or the dimension name for a metadata exposure row.",
                        },
                        "threat": {
                            "type": "string",
                            "enum": [
                                "Cryptographic weakness",
                                "Configuration weakness",
                                "Protocol weakness",
                                "Traffic anomaly",
                                "Replay anomaly",
                                "Metadata exposure",
                                "Evidence gap",
                                "Unclassified threat",
                            ],
                        },
                        "severity": {"type": ["string", "null"]},
                        "title": {"type": ["string", "null"]},
                        "category": _STR,
                        "rule_id": _STR,
                        "impact": {"type": ["string", "null"]},
                        "evidence": _free("Evidence quoted from the finding or the metadata product."),
                        "finding_source": {"type": ["string", "null"]},
                        "severity_source": {"type": ["string", "null"]},
                        "recommendation": {
                            "type": "object",
                            "description": (
                                "The remediation cell: response rule id, "
                                "action, priority, approval and "
                                "authorization requirements, and the "
                                "prescribed text."
                            ),
                            "properties": {
                                "text": {"type": ["string", "null"]},
                                "source": {"type": ["string", "null"]},
                                "response_rule_id": {"type": ["string", "null"]},
                                "action": {"type": ["string", "null"]},
                                "priority": {"type": ["string", "null"]},
                                "authorization_requirement": {"type": ["string", "null"]},
                                "approval_requirement": {"type": ["string", "null"]},
                                "policy_dependency": {"type": ["string", "null"]},
                                "limitations": _list(
                                    "What this recommendation does not authorise.",
                                    _STR,
                                ),
                            },
                        },
                    },
                },
                "TechnicalReport": _product(
                    "The analyst document: fourteen numbered sections over the "
                    "same evidence as the bundle, from the executive summary "
                    "through risk evidence and limitations to evidence and "
                    "provenance. Sections are assembled, never re-derived.",
                    {
                        "assessment_id": _STR,
                        "sections": _list(
                            "Sections in document order; each heading starts "
                            "with its 1-based number and names the product the "
                            "paragraphs came from.",
                            _ref("ReportSection"),
                        ),
                        "limitations": _list(
                            "What the report does not establish.",
                            _STR,
                        ),
                    },
                    required=sorted(_CONTRACT) + ["assessment_id", "sections"],
                ),
                "ReportSection": {
                    "type": "object",
                    "required": ["heading", "paragraphs", "product"],
                    "properties": {
                        "heading": {
                            "type": "string",
                            "description": "Numbered heading, e.g. `1. Executive summary`.",
                        },
                        "paragraphs": _list(
                            "Quoted text. A value unknown in its source "
                            "product is unknown here.",
                            _STR,
                        ),
                        "product": {
                            "type": "string",
                            "description": "The product this section was taken from.",
                        },
                    },
                },
                "ExecutiveReport": _product(
                    "The brief's five executive questions, answered from the "
                    "same products as the technical report, keyed by the "
                    "question names the brief uses.",
                    {
                        "assessment_id": _STR,
                        "answers": {
                            "type": "object",
                            "description": "One entry per executive question, keyed by question name.",
                            "properties": {
                                question: _ref("ExecutiveAnswer")
                                for question in EXECUTIVE_QUESTIONS
                            },
                            "required": list(EXECUTIVE_QUESTIONS),
                            "additionalProperties": False,
                        },
                        "limitations": _list(
                            "What an executive answer does not establish.",
                            _STR,
                        ),
                    },
                    required=sorted(_CONTRACT) + ["assessment_id", "answers"],
                ),
                "ExecutiveAnswer": {
                    "type": "object",
                    "description": (
                        "One answer: the question, the state it was answered "
                        "in, its statements and the evidence behind them. An "
                        "absent answer is reported, never guessed."
                    ),
                    "required": ["question", "state", "statements",
                                 "evidence", "answered"],
                    "properties": {
                        "question": {
                            "type": "string",
                            "enum": list(EXECUTIVE_QUESTIONS),
                        },
                        "state": dict(_STATE_FIELD),
                        "statements": _list(
                            "The answer itself, one sentence per line.",
                            _STR,
                        ),
                        "evidence": _list(
                            "Where the answer came from, named per statement "
                            "group.",
                            _STR,
                        ),
                        "answered": {
                            "type": "boolean",
                            "description": (
                                "False only when no statement could be made "
                                "from the evidence available."
                            ),
                        },
                    },
                },
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
