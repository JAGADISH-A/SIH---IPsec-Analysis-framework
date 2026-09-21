"""Expected-vs-ML comparison outcomes (Phase 5).

ML output is compared against the EXPECTED ``traffic.profile`` as a SEPARATE
audit observation — its outcomes NEVER enter ``CorrelationResult.matches /
mismatches / unknowns`` and NEVER influence the protocol comparison status.

Outcome variables (distinct from the protocol canonical variables):

    ML_TRAFFIC_CLASSIFICATION
        MATCH           ML classification == expected profile
        MISMATCH        ML classification disagrees (documented as inference,
                        never as an authoritative protocol observation)
        UNKNOWN         no valid ML classification available (no ML result, or
                        the model produced no canonical traffic class)
        NOT_APPLICABLE  no expected profile to compare against

    ML_ANOMALY
        NOT_APPLICABLE  no anomaly verdict available (model lacks the seam)
        MATCH           an anomaly verdict exists and is recorded (observation
                        semantics, NOT agreement, NOT a risk conclusion)
"""

from typing import Any, Dict, Optional

from ..models import (
    CORRELATION_STATUS_MATCH,
    CORRELATION_STATUS_MISMATCH,
    CORRELATION_STATUS_NOT_APPLICABLE,
    CORRELATION_STATUS_UNKNOWN,
    MLResult,
)

SOURCE_ML = "ml"


def _ml_class(ml_result: Optional[MLResult]) -> Optional[str]:
    if ml_result is None:
        return None
    return ml_result.traffic_class


def _outcome(
    *,
    variable: str,
    status: str,
    expected_profile: Optional[str],
    ml_traffic_class: Optional[str],
    reason: str,
    ml_result: Optional[MLResult],
) -> Dict[str, Any]:
    data: Dict[str, Any] = {
        "variable": variable,
        "source": SOURCE_ML,
        "status": status,
        "expected_profile": expected_profile,
        "ml_traffic_class": ml_traffic_class,
        "is_authoritative_observation": False,
        "reason": reason,
    }
    if ml_result is not None:
        data["model_version"] = ml_result.model_version
        data["classification_confidence"] = ml_result.classification_confidence
    return data


def compare_expected_profile_to_ml(
    expected_profile: Optional[str], ml_result: Optional[MLResult]
) -> Dict[str, Any]:
    """Compare the expected traffic profile against the ML classification.

    Deterministic, never merged into protocol mismatch outcomes, always
    labeled ``source = "ml"`` with the model version.
    """
    if expected_profile is None:
        return _outcome(
            variable="ML_TRAFFIC_CLASSIFICATION",
            status=CORRELATION_STATUS_NOT_APPLICABLE,
            expected_profile=None,
            ml_traffic_class=_ml_class(ml_result),
            reason="no expected traffic profile defined; nothing to compare",
            ml_result=ml_result,
        )
    if ml_result is None:
        return _outcome(
            variable="ML_TRAFFIC_CLASSIFICATION",
            status=CORRELATION_STATUS_UNKNOWN,
            expected_profile=expected_profile,
            ml_traffic_class=None,
            reason="no ML classification output available (no model present)",
            ml_result=None,
        )
    if ml_result.traffic_class is None:
        reason = ml_result.extras.get(
            "unmapped_label",
            "ML model produced no canonical traffic class",
        )
        return _outcome(
            variable="ML_TRAFFIC_CLASSIFICATION",
            status=CORRELATION_STATUS_UNKNOWN,
            expected_profile=expected_profile,
            ml_traffic_class=None,
            reason=reason,
            ml_result=ml_result,
        )
    if ml_result.traffic_class == expected_profile:
        return _outcome(
            variable="ML_TRAFFIC_CLASSIFICATION",
            status=CORRELATION_STATUS_MATCH,
            expected_profile=expected_profile,
            ml_traffic_class=ml_result.traffic_class,
            reason=(
                "ML traffic classification matches the expected profile. "
                "Recorded as supporting inference evidence only - never as an "
                "authoritative protocol observation."
            ),
            ml_result=ml_result,
        )
    return _outcome(
        variable="ML_TRAFFIC_CLASSIFICATION",
        status=CORRELATION_STATUS_MISMATCH,
        expected_profile=expected_profile,
        ml_traffic_class=ml_result.traffic_class,
        reason=(
            f"ML traffic classification ({ml_result.traffic_class!r}) differs "
            f"from the expected profile ({expected_profile!r}). ML output is a "
            "model inference and cannot override observed protocol evidence."
        ),
        ml_result=ml_result,
    )


def ml_anomaly_observation(ml_result: Optional[MLResult]) -> Dict[str, Any]:
    """Record an ML anomaly verdict as a source-labeled observation.

    The anomaly verdict is a single-sourced ML observation; it has no
    expected-value side, so ``MATCH`` here means "a verdict exists and is
    recorded" (explicitly NOT agreement and NOT a risk conclusion). When the
    model has no anomaly capability the seam reports ``NOT_APPLICABLE`` with a
    reason — the absence is represented, never fabricated.
    """
    if ml_result is None:
        return {
            "variable": "ML_ANOMALY",
            "source": SOURCE_ML,
            "status": CORRELATION_STATUS_NOT_APPLICABLE,
            "anomaly": None,
            "anomaly_score": None,
            "model_version": None,
            "observation_recorded": False,
            "reason": "no ML result available; anomaly cannot be evaluated",
        }
    if ml_result.anomaly is None and ml_result.anomaly_score is None:
        return {
            "variable": "ML_ANOMALY",
            "source": SOURCE_ML,
            "status": CORRELATION_STATUS_NOT_APPLICABLE,
            "anomaly": None,
            "anomaly_score": None,
            "model_version": ml_result.model_version,
            "observation_recorded": False,
            "reason": (
                "anomaly capability unavailable in the model; anomaly and "
                "anomaly_score are intentionally not evaluated"
            ),
        }
    if ml_result.anomaly is None:
        reason = (
            f"anomaly score {ml_result.anomaly_score!r} recorded but the model "
            "provided no verdict; no risk conclusion is drawn"
        )
    else:
        reason = (
            f"anomaly verdict recorded: flag={ml_result.anomaly!r}, "
            f"score={ml_result.anomaly_score!r}. An ML observation only - NOT a "
            "security risk conclusion and never an authoritative protocol "
            "observation."
        )
    return {
        "variable": "ML_ANOMALY",
        "source": SOURCE_ML,
        "status": CORRELATION_STATUS_MATCH,
        "anomaly": ml_result.anomaly,
        "anomaly_score": ml_result.anomaly_score,
        "model_version": ml_result.model_version,
        "observation_recorded": True,
        "reason": reason,
    }


def ml_comparisons(
    expected_profile: Optional[str], ml_result: Optional[MLResult]
) -> list:
    """All ML-related outcomes for one correlation, in fixed order."""
    return [
        compare_expected_profile_to_ml(expected_profile, ml_result),
        ml_anomaly_observation(ml_result),
    ]