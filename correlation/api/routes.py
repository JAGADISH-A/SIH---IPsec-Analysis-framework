"""PHASE 8 — API route handlers (pure functions, no I/O).

Implements the Phase-8 REST contract:

    GET /api/health
    GET /api/assessments
    GET /api/assessments/{id}
    GET /api/assessments/{id}/{expected|observed|correlation|risk|xai|ml|
                            evidence|ipsec-state|sa|crypto-evidence|replay|
                            metadata-exposure|threat-matrix|report|
                            executive-report}

Unknown assessment ids and unknown sub-resources yield a structured 404.
Method handling is left to the HTTP layer (405). Everything is JSON: the
handlers return plain dicts that ``json.dumps`` serializes deterministically.

Error envelope, pagination envelope and the ``ApiError`` type live here because
they are the shared vocabulary of every route module in this package.  The
``/api/v1`` surface reuses them unchanged; see
``correlation/api/v1.py`` for its route list and ``openapi.py`` for the
machine-readable contract.
"""

from typing import Any, Dict, List, Optional

from .adapters import parse_assessment_id

#: The sub-resources of ``/api/assessments/{id}``, in contract order.
#:
#: The names are what a client puts in the URL; ``SUB_RESOURCE_KEYS`` maps
#: them onto the key the bundle stores the product under, so a URL vocabulary
#: that reads well (``crypto-evidence``) and a payload vocabulary that reads
#: well as an object key (``crypto_evidence``) never have to be the same
#: string. Anything not in the mapping is its own key.
SUB_RESOURCES = (
    "expected",
    "observed",
    "correlation",
    "risk",
    "xai",
    "ml",
    "evidence",
    "ipsec-state",
    "sa",
    "crypto-evidence",
    "replay",
    "metadata-exposure",
    "threat-matrix",
    "report",
    "executive-report",
)

SUB_RESOURCE_KEYS = {
    "ipsec-state": "ipsec_state",
    "crypto-evidence": "crypto_evidence",
    "replay": "replay_assessment",
    "metadata-exposure": "metadata_exposure",
    "threat-matrix": "threat_matrix",
    "executive-report": "executive_report",
}


class ApiError(Exception):
    """Carries an HTTP status code + structured payload.

    The wire shape is::

        {"error": {"code": "...", "message": "...", "detail": "...", "request_id": "..."}}

    ``detail`` is retained from the original Phase-8 contract and is the human
    message; ``message`` is an explicit alias so a frontend can read either.
    ``code`` is the stable machine-readable discriminator a client should
    branch on, and ``request_id`` correlates a browser-visible failure with the
    server log line for the same request.

    ``request_id`` is filled in by the transport when it is absent, so handler
    code stays transport-agnostic and is still unit testable.

    ``extra`` adds machine-readable fields to the error object (e.g. the
    candidate ids that made a lookup ambiguous).  It is merged before
    ``request_id`` and can never overwrite ``code``/``message``/``detail``, so a
    handler cannot disguise an error by setting one of those.  Callers that pass
    nothing extra produce the byte-identical payload they always did.
    """

    def __init__(
        self,
        status: int,
        code: str,
        detail: str,
        request_id: Optional[str] = None,
        extra: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(detail)
        self.status = status
        self.code = code
        self.detail = detail
        self.request_id = request_id
        self.extra: Dict[str, Any] = dict(extra or {})

    def payload(self, request_id: Optional[str] = None) -> Dict[str, Any]:
        rid = self.request_id or request_id
        error: Dict[str, Any] = {
            key: value
            for key, value in self.extra.items()
            if key not in ("code", "message", "detail", "request_id")
        }
        error.update(
            {
                "code": self.code,
                "message": self.detail,
                "detail": self.detail,
            }
        )
        if rid:
            error["request_id"] = rid
        return {"error": error}


#: Pagination contract shared by every list endpoint.
#:
#: ``DEFAULT_PAGE_LIMIT`` is deliberately conservative: these responses are
#: read whole into memory by a browser before rendering, and the audit journal
#: in particular can be large.  ``MAX_PAGE_LIMIT`` bounds a single request so a
#: client cannot ask for the entire journal in one page.
DEFAULT_PAGE_LIMIT = 100
MAX_PAGE_LIMIT = 5000


def page_params(
    params: Optional[Dict[str, Any]] = None,
    default_limit: int = DEFAULT_PAGE_LIMIT,
    max_limit: int = MAX_PAGE_LIMIT,
) -> tuple:
    """Validate ``limit``/``offset`` into ``(limit, offset)``.

    Raises :class:`ApiError` 400 on a bad value rather than silently coercing
    it: a client that sends ``limit=abc`` and receives 200 with a default page
    size will paginate incorrectly without ever knowing why.

    ``offset`` beyond the end of the result set is NOT an error; it yields an
    empty page, which is how a client detects it has walked off the end.
    """
    params = params or {}

    def _positive_int(name: str, default: int) -> int:
        raw = params.get(name)
        if raw is None or raw == "":
            return default
        if isinstance(raw, bool):
            raise ApiError(
                400, "invalid_query_parameter", f"{name} must be an integer"
            )
        if isinstance(raw, int):
            value = raw
        else:
            try:
                value = int(str(raw).strip())
            except (TypeError, ValueError):
                raise ApiError(
                    400, "invalid_query_parameter",
                    f"{name} must be an integer, got {raw!r}",
                ) from None
        return value

    limit = _positive_int("limit", default_limit)
    if limit < 1:
        raise ApiError(
            400, "invalid_query_parameter", f"limit must be >= 1, got {limit}"
        )
    limit = min(limit, max_limit)

    offset = _positive_int("offset", 0)
    if offset < 0:
        raise ApiError(
            400, "invalid_query_parameter", f"offset must be >= 0, got {offset}"
        )
    return limit, offset


def paginate(items: List[Any], limit: int, offset: int) -> tuple:
    """Return ``(page, total)`` for an already-materialised list.

    ``total`` is the count BEFORE paging, so a client can compute the number of
    pages without a second request.
    """
    total = len(items)
    return items[offset:offset + limit], total


def paged_envelope(
    api: str,
    items: List[Any],
    limit: int,
    offset: int,
    key: str = "items",
    **extra: Any,
) -> Dict[str, Any]:
    """The standard list response.

    ``key`` names the array so an existing endpoint keeps its historical array
    name (``events``, ``runs``, ``evidence``) while every list still reports
    ``limit``/``offset``/``total``/``count`` uniformly.
    """
    page, total = paginate(items, limit, offset)
    body: Dict[str, Any] = {
        "api": api,
        key: page,
        "count": len(page),
        "total": total,
        "limit": limit,
        "offset": offset,
        "has_more": offset + len(page) < total,
    }
    body.update(extra)
    return body


def _bundle_or_404(store, assessment_id) -> Dict[str, Any]:
    if parse_assessment_id(assessment_id) is None:
        raise ApiError(404, "invalid_assessment_id", "assessment id has an invalid format")
    bundle = store.bundles.get(assessment_id)
    if bundle is None:
        raise ApiError(404, "assessment_not_found", f"no assessment {assessment_id!r}")
    return bundle


def handle_health(store) -> Dict[str, Any]:
    return {
        "status": "ok",
        "service": "sihcolayer-phase8-dashboard-api",
        "api_schema_version": "v1",
        "store_version": store.overview["store_version"],
        "total_assessments": store.overview["total_assessments"],
        "read_only": True,
        "note": (
            "adapter-only API: consumes Phase-4/5/6/7 outputs; it never "
            "recomputes scores, severities, comparisons or explanations"
        ),
    }


def handle_assessments(store, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """List endpoint: overview + deterministic table headers (no full bodies).

    Paginates with ``limit``/``offset``.  The ``headers`` array name and the
    ``overview`` block are unchanged, so an existing consumer reading either
    keeps working; ``limit``/``offset``/``total``/``count``/``has_more`` are
    added so a client can page instead of assuming the list is complete.
    """
    limit, offset = page_params(params)
    page, total = paginate(store.headers, limit, offset)
    return {
        "api": "assessments",
        "overview": dict(store.overview),
        "headers": [dict(h) for h in page],
        "count": len(page),
        "total": total,
        "limit": limit,
        "offset": offset,
        "has_more": offset + len(page) < total,
    }


def handle_assessment(store, assessment_id) -> Dict[str, Any]:
    return _bundle_or_404(store, assessment_id)


def handle_sub_resource(store, assessment_id, resource) -> Dict[str, Any]:
    if resource not in SUB_RESOURCES:
        raise ApiError(
            404,
            "unknown_resource",
            f"unknown sub-resource {resource!r}; expected one of {SUB_RESOURCES}",
        )
    bundle = _bundle_or_404(store, assessment_id)
    key = SUB_RESOURCE_KEYS.get(resource, resource)
    return {
        "assessment_id": bundle["assessment_id"],
        "resource": resource,
        "data": bundle.get(key),
    }


def handle_get(
    store, path: str, params: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """Dispatch one GET path; raises ApiError for unknown/invalid routes.

    ``params`` is the parsed query string.  The Phase-8 contract is path-only
    apart from ``/api/assessments`` pagination, so passing ``None`` (the
    default) reproduces the original behaviour exactly.
    """
    if path == "/api/health":
        return handle_health(store)
    if path == "/api/assessments":
        return handle_assessments(store, params)
    prefix = "/api/assessments/"
    if path.startswith(prefix):
        remainder = path[len(prefix):]
        parts = remainder.split("/")
        assessment_id = parts[0]
        if len(parts) == 1 and assessment_id:
            return handle_assessment(store, assessment_id)
        if len(parts) == 2 and assessment_id and parts[1]:
            return handle_sub_resource(store, assessment_id, parts[1])
        raise ApiError(404, "invalid_route", f"unknown route {path!r}")
    raise ApiError(404, "unknown_route", f"unknown route {path!r}")


def serializable(store) -> Dict[str, Any]:
    """The full snapshot (list + every detail bundle) for static export."""
    return {
        "api_schema_version": "v1",
        "overview": dict(store.overview),
        "headers": [dict(h) for h in store.headers],
        "assessments": {key: dict(b) for key, b in store.bundles.items()},
    }