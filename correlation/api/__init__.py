"""PHASE 8 — Security Analyst Dashboard API.

Read-only adapter layer exposing the Phase-4/5/6/7 outputs to the dashboard
frontend over the Phase-8 REST contract. This package is stdlib-only and
transport agnostic: ``routes.handle_get`` can also be mounted behind FastAPI.

See PHASE_8_DASHBOARD_REPORT.md and PHASE_8_UI_DATA_MAPPING.md.
"""

from .adapters import (  # noqa: F401
    API_SCHEMA_VERSION,
    STORE_VERSION,
    assessment_bundle,
    assessment_id_for,
    correlation_to_view,
    evidence_to_view,
    expected_to_view,
    finding_to_view,
    header_view,
    identity_to_view,
    ml_to_view,
    observed_to_view,
    parse_assessment_id,
    risk_to_view,
    xai_to_view,
)
from .routes import ApiError, handle_get, serializable  # noqa: F401
from .store import AssessmentStore, build_store  # noqa: F401

__all__ = [
    "API_SCHEMA_VERSION",
    "STORE_VERSION",
    "assessment_bundle",
    "assessment_id_for",
    "correlation_to_view",
    "evidence_to_view",
    "expected_to_view",
    "finding_to_view",
    "header_view",
    "identity_to_view",
    "ml_to_view",
    "observed_to_view",
    "parse_assessment_id",
    "risk_to_view",
    "xai_to_view",
    "ApiError",
    "handle_get",
    "serializable",
    "AssessmentStore",
    "build_store",
]