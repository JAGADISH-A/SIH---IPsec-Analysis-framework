"""Score explanation builder (Phase 7).

Consumes ``RiskAssessment.overall_score``, ``.severity``,
``.risk_policy_version`` and (when available) ``metadata.score_detail`` and
explains them WITHOUT recomputing anything. No scoring function from the
Phase-6 package is called here; the score and severity are authoritative and
are only copied.
"""

from typing import Any, Dict, Optional, Tuple

from ..risk.models import RiskAssessment
from .models import PROVENANCE_RISK_ASSESSMENT, ScoreExplanation
from .templates import score_explanation_text


def build_score_explanation(assessment: RiskAssessment) -> ScoreExplanation:
    """One deterministic ScoreExplanation from a RiskAssessment (read-only)."""
    meta = dict(assessment.metadata or {})
    score_detail = meta.get("score_detail")
    ml = meta.get("ml") or {}

    contributions: Tuple[Dict[str, Any], ...] = ()
    per_category_totals: Tuple[Tuple[str, int], ...] = ()
    band: Optional[Tuple[str, int, int]] = None
    raw_sum: Optional[int] = None

    if isinstance(score_detail, dict):
        raw_sum = score_detail.get("raw_sum")
        band_raw = score_detail.get("severity_band")
        if isinstance(band_raw, (list, tuple)) and len(band_raw) == 3:
            band = (
                str(band_raw[0]),
                int(band_raw[1]),
                int(band_raw[2]),
            )
        contributions = tuple(
            dict(c)
            for c in (score_detail.get("contributions") or [])
            if isinstance(c, dict)
        )
        per_category_totals = tuple(
            (str(k), int(v))
            for k, v in (score_detail.get("per_category_totals") or [])
        )

    explanation = score_explanation_text(
        assessment.overall_score,
        assessment.severity,
        assessment.risk_policy_version,
        len(assessment.findings),
        bool(ml.get("ml_present", False)),
    )
    return ScoreExplanation(
        provenance=PROVENANCE_RISK_ASSESSMENT,
        score=assessment.overall_score,
        severity=assessment.severity,
        severity_band=band,
        risk_policy_version=assessment.risk_policy_version,
        raw_sum=raw_sum,
        contributions=contributions,
        per_category_totals=per_category_totals,
        explanation=explanation,
        score_unchanged=True,
        severity_unchanged=True,
    )