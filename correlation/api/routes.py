"""PHASE 8 — API route handlers (pure functions, no I/O).

Implements the Phase-8 REST contract:

    GET /api/health
    GET /api/assessments
    GET /api/assessments/{id}
    GET /api/assessments/{id}/{expected|observed|correlation|risk|xai|ml|
                            evidence|ipsec-state}

Unknown assessment ids and unknown sub-resources yield a structured 404.
Method handling is left to the HTTP layer (405). Everything is JSON: the
handlers return plain dicts that ``json.dumps`` serializes deterministically.
"""

from typing import Any, Dict, Optional

from .adapters import parse_assessment_id

SUB_RESOURCES = (
    "expected",
    "observed",
    "correlation",
    "risk",
    "xai",
    "ml",
    "evidence",
    "ipsec-state",
)


class ApiError(Exception):
    """Carries an HTTP status code + structured payload."""

    def __init__(self, status: int, code: str, detail: str) -> None:
        super().__init__(detail)
        self.status = status
        self.code = code
        self.detail = detail

    def payload(self) -> Dict[str, Any]:
        return {"error": {"code": self.code, "detail": self.detail}}


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


def handle_assessments(store) -> Dict[str, Any]:
    """List endpoint: overview + deterministic table headers (no full bodies)."""
    return {
        "api": "assessments",
        "overview": dict(store.overview),
        "headers": [dict(h) for h in store.headers],
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
    key = "ipsec_state" if resource == "ipsec-state" else resource
    return {
        "assessment_id": bundle["assessment_id"],
        "resource": resource,
        "data": bundle.get(key),
    }


def handle_get(store, path: str) -> Dict[str, Any]:
    """Dispatch one GET path; raises ApiError for unknown/invalid routes."""
    if path == "/api/health":
        return handle_health(store)
    if path == "/api/assessments":
        return handle_assessments(store)
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