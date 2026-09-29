"""Read-only drift routes.

Three GETs, no state, no side effects:

    GET /api/v1/drift
        What this dataset run was compared against, and the per-assessment
        outcomes.
    GET /api/v1/drift/baselines
        The validated baselines this store knows about, disclosed as records
        with both digests.
    GET /api/v1/assessments/{assessment_id}/drift
        The comparison for one assessment.

Nothing here accepts a request body, an action, or a write. A baseline is
established out of band by the drift layer and read here; this surface cannot
create, amend or delete one, which is the same read-only contract the custody
and evidence surfaces keep.

The most important thing these routes say is what they did **not** do. A store
with no baseline reports ``configured: false`` with a reason, rather than an
empty result that a client could mistake for "no drift found".
"""

from typing import Any, Dict, Optional

from ..drift import describe_canonicalization
from .routes import ApiError

DRIFT_PATH = "/api/v1/drift"
DRIFT_BASELINES_PATH = "/api/v1/drift/baselines"
ASSESSMENT_DRIFT_SUFFIX = "/drift"


def is_drift_path(path: str) -> bool:
    """Whether ``path`` is one of this module's routes."""
    return (
        path == DRIFT_PATH
        or path == DRIFT_BASELINES_PATH
        or path.startswith(DRIFT_PATH + "/")
    )


def _parse_assessment_drift(remainder: str) -> Optional[str]:
    """The assessment id from an ``/assessments/{id}/drift`` remainder."""
    if not remainder.endswith(ASSESSMENT_DRIFT_SUFFIX):
        return None
    assessment_id = remainder[: -len(ASSESSMENT_DRIFT_SUFFIX)]
    if not assessment_id or "/" in assessment_id:
        return None
    return assessment_id


def handle_drift(store) -> Dict[str, Any]:
    """The drift surface of the whole store."""
    if store is None:
        raise ApiError(503, "store_unavailable", "the assessment store is not available")
    summary = store.drift_summary()
    return {
        "api": "drift",
        "read_only": True,
        **summary,
    }


def handle_drift_baselines(store) -> Dict[str, Any]:
    """Every validated baseline this store knows about.

    With no registry the list is empty and ``configured`` is False: an empty
    list means "no baseline was declared", never "no drift exists".
    """
    if store is None:
        raise ApiError(503, "store_unavailable", "the assessment store is not available")
    registry = getattr(store, "baselines", None)
    if registry is None:
        return {
            "api": "drift-baselines",
            "read_only": True,
            "configured": False,
            "reason": (
                "no validated baseline registry was supplied to this store; "
                "baselines are established explicitly by the drift layer and are "
                "never inferred from the most recent observation"
            ),
            "persistent": False,
            "baseline_ids": [],
            "baselines": [],
            "canonicalization": describe_canonicalization(),
        }
    return {
        "api": "drift-baselines",
        "read_only": True,
        "configured": True,
        "reason": None,
        "persistent": registry.persistent,
        "baseline_ids": list(registry.ids()),
        "baselines": [record.to_dict() for record in registry.all()],
        "canonicalization": describe_canonicalization(),
    }


def handle_assessment_drift(store, assessment_id: str) -> Dict[str, Any]:
    """The drift comparison for one assessment.

    404 when the assessment is unknown. A known assessment with no comparison
    is reported as ``not_configured`` -- the difference between "there is no
    such assessment" and "this assessment was not compared" is preserved.
    """
    if store is None:
        raise ApiError(503, "store_unavailable", "the assessment store is not available")
    if not assessment_id:
        raise ApiError(404, "invalid_assessment_id", "assessment id is required")
    if assessment_id not in store.bundles:
        raise ApiError(
            404, "assessment_not_found", f"no assessment {assessment_id!r}"
        )
    drift = store.drift_for(assessment_id)
    if drift is None:
        return {
            "api": "drift",
            "read_only": True,
            "assessment_id": assessment_id,
            "status": "not_configured",
            "drift_detected": False,
            "reason": (
                "no validated baseline was configured for this store, so no "
                "longitudinal comparison was made for this assessment and no "
                "drift is claimed"
            ),
            "baseline": None,
            "current": None,
            "changed_fields": [],
            "unchanged_variables": [],
            "unknown_variables": [],
            "drift_categories": [],
            "risk": None,
        }
    return {
        "api": "drift",
        "read_only": True,
        "assessment_id": assessment_id,
        **drift.to_dict(),
    }
