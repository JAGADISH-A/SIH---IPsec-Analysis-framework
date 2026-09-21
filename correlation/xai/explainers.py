"""Deterministic explainer functions (Phase 7).

Pure functions that turn one existing structured object (a Phase-6
``RiskFinding`` or a Phase-5 ``MLResult``) into an explanation. They perform no
risk computation and invent no evidence. Ordering is preserved from inputs;
the engine sorts multi-item outputs deterministically before serialization.
"""

from typing import Any, Optional, Sequence, Tuple

from ..models.ml import MLResult
from ..risk.models import RiskFinding
from .models import (
    EXPLANATION_CATEGORY_ML,
    EXPLANATION_CATEGORY_LIMITATION,
    MLExplanation,
    PROVENANCE_ML_RESULT,
    PROVENANCE_RISK_FINDING,
    FindingExplanation,
)
from .templates import (
    contributing_factors,
    explanation_categories,
    generic_why,
    limitations,
    ml_anomaly_explanation,
    ml_anomaly_limitations,
    ml_classification_explanation,
    ml_classification_limitations,
)

ML_EXPLANATION_KIND_CLASSIFICATION = "classification"
ML_EXPLANATION_KIND_ANOMALY = "anomaly"


def explain_finding(
    finding: RiskFinding,
    evidence_refs: Sequence = (),
) -> FindingExplanation:
    """One deterministic FindingExplanation from one RiskFinding (read-only)."""
    refs = tuple(
        dict(ev.to_dict()) for ev in finding.evidence_refs
    )
    if refs:
        chosen = refs
    else:
        chosen = tuple(dict(ev.to_dict()) for ev in evidence_refs)
    return FindingExplanation(
        provenance=PROVENANCE_RISK_FINDING,
        finding_id=finding.finding_id,
        rule_id=finding.rule_id,
        title=finding.title,
        severity=finding.severity,
        category=finding.category,
        related_variable=finding.related_variable,
        description=finding.description,
        why_it_was_flagged=generic_why(finding),
        expected=finding.expected_value,
        observed=finding.observed_value,
        condition=finding.condition,
        reason=finding.reason,
        source=finding.source,
        evidence_type=finding.evidence_type,
        evidence_refs=chosen,
        confidence=finding.confidence,
        model_version=finding.model_version,
        contributing_factors=contributing_factors(finding),
        explanation_categories=explanation_categories(finding),
        limitations=limitations(finding),
    )


def explain_ml_classification(
    ml_result: MLResult,
    evidence_refs: Sequence = (),
) -> Optional[MLExplanation]:
    """Explain the model's traffic classification when one was produced."""
    if ml_result.traffic_class is None:
        return None
    return MLExplanation(
        provenance=PROVENANCE_ML_RESULT,
        explanation_kind=ML_EXPLANATION_KIND_CLASSIFICATION,
        model_version=ml_result.model_version,
        traffic_class=ml_result.traffic_class,
        classification_confidence=ml_result.classification_confidence,
        anomaly=None,
        anomaly_score=None,
        explanation=ml_classification_explanation(
            ml_result.traffic_class,
            ml_result.classification_confidence,
            ml_result.model_version,
        ),
        explanation_categories=(EXPLANATION_CATEGORY_ML,),
        limitations=ml_classification_limitations(),
        evidence_refs=tuple(
            dict(ev.to_dict()) for ev in evidence_refs
        ),
    )


def explain_ml_anomaly(
    ml_result: MLResult,
    evidence_refs: Sequence = (),
) -> Optional[MLExplanation]:
    """Explain the model's anomaly verdict only when one was produced."""
    if ml_result.anomaly is None:
        return None
    return MLExplanation(
        provenance=PROVENANCE_ML_RESULT,
        explanation_kind=ML_EXPLANATION_KIND_ANOMALY,
        model_version=ml_result.model_version,
        traffic_class=None,
        classification_confidence=None,
        anomaly=ml_result.anomaly,
        anomaly_score=ml_result.anomaly_score,
        explanation=ml_anomaly_explanation(
            ml_result.anomaly,
            ml_result.anomaly_score,
            ml_result.model_version,
        ),
        explanation_categories=(
            EXPLANATION_CATEGORY_ML,
            EXPLANATION_CATEGORY_LIMITATION,
        ),
        limitations=ml_anomaly_limitations(),
        evidence_refs=tuple(
            dict(ev.to_dict()) for ev in evidence_refs
        ),
    )


def explain_ml_result(
    ml_result: MLResult,
    *,
    classification_evidence_refs: Sequence = (),
    anomaly_evidence_refs: Sequence = (),
) -> Tuple[MLExplanation, ...]:
    """Deterministic ordered ML explanations (classification then anomaly).

    ``classification_evidence_refs`` / ``anomaly_evidence_refs`` carry the
    evidence references attached to the corresponding Phase-6 ML findings so
    the explanation cites only refs that actually supported that decision.
    """
    explained: list = []
    classification = explain_ml_classification(ml_result, classification_evidence_refs)
    if classification is not None:
        explained.append(classification)
    anomaly = explain_ml_anomaly(ml_result, anomaly_evidence_refs)
    if anomaly is not None:
        explained.append(anomaly)
    return tuple(explained)