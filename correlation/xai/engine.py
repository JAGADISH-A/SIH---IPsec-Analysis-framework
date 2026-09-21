"""ExplainabilityEngine (Phase 7) — deterministic, read-only XAI orchestrator.

The engine consumes the authoritative Phase-6 ``RiskAssessment`` (required)
and may enrich from the original ``CorrelationResult`` / ``MLResult`` /
``EvidenceRef`` inputs used to build it. It EXPLAINS existing decisions only:

* it never changes risk scores, severities, comparison results, ML results or
  findings;
* it never fabricates evidence, PCAP paths, timestamps, audit ids or analyst
  conclusions;
* it preserves the MATCH / MISMATCH / UNKNOWN / NOT_APPLICABLE distinction and
  never describes missing evidence as a vulnerability;
* output is fully deterministic (fixed ordering; no time, randomness, network
  or LLM).

The risk score/severity are authoritative; the charge of the Phase-7 layer
here is to explain them from ``metadata.score_detail`` without recomputation.
"""

from dataclasses import dataclass
from typing import Any, Dict, Optional, Sequence, Tuple, Union

from ..models import (
    CorrelationIdentity,
    CorrelationResult,
    EvidenceRef,
    ExpectedState,
    MLResult,
)
from ..models.correlation import (
    CORRELATION_STATUS_MATCH,
    CORRELATION_STATUS_NOT_APPLICABLE,
)
from ..risk.models import RiskAssessment
from .evidence import build_evidence_summary
from .explainers import (
    explain_finding,
    explain_ml_result,
)
from .models import (
    XAI_ENGINE_VERSION,
    XAI_SCHEMA_VERSION,
    EXPLANATION_CATEGORY_LIMITATION,
    ExplainabilityResult,
    ExplainabilitySummary,
    GapExplanation,
    PROVENANCE_CORRELATION_RESULT,
)
from .score_explanation import build_score_explanation
from .templates import (
    not_applicable_explanation_text,
    not_applicable_limitations,
    overall_explanation_text,
    unknown_explanation_text,
    unknown_limitations,
)


def _as_evidence_refs(outcome: Dict[str, Any]) -> Tuple[EvidenceRef, ...]:
    """Rebuild existing EvidenceRefs from an outcome payload (never invented)."""
    refs: list = []
    for item in outcome.get("evidence_refs") or []:
        if not isinstance(item, dict):
            continue
        try:
            refs.append(EvidenceRef.from_dict(item))
        except (ValueError, TypeError, KeyError):
            continue
    return tuple(refs)


def _collect_finding_refs(assessment: RiskAssessment) -> Tuple[EvidenceRef, ...]:
    refs: list = []
    for finding in assessment.findings:
        refs.extend(finding.evidence_refs)
    return tuple(refs)


def _collect_outcome_refs(correlation: Optional[CorrelationResult]) -> Tuple[EvidenceRef, ...]:
    if correlation is None:
        return ()
    refs: list = []
    for outcome in (
        list(getattr(correlation, "matches", []))
        + list(getattr(correlation, "mismatches", []))
        + list(getattr(correlation, "unknowns", []))
        + list(getattr(correlation, "not_applicable", []))
    ):
        refs.extend(_as_evidence_refs(outcome))
    return tuple(refs)


def _ml_finding_refs(assessment: RiskAssessment, rule_id: str) -> Tuple[EvidenceRef, ...]:
    refs: list = []
    for finding in assessment.findings:
        if finding.rule_id == rule_id:
            refs.extend(finding.evidence_refs)
    return tuple(refs)


def _resolve_ml_result(correlation: Optional[CorrelationResult], ml_result: Optional[MLResult]) -> Optional[MLResult]:
    if ml_result is not None:
        if not isinstance(ml_result, MLResult):
            raise TypeError("ml_result must be an MLResult or None")
        return ml_result
    if correlation is None:
        return None
    stored = correlation.metadata.get("ml", {}).get("ml_result")
    if not stored:
        return None
    return MLResult.from_dict(stored)


@dataclass(frozen=True)
class ExplainabilityEngine:
    """Deterministic explainability engine (stateless)."""

    def explain(
        self,
        assessment: RiskAssessment,
        correlation: Optional[CorrelationResult] = None,
        ml_result: Optional[MLResult] = None,
        evidence_refs: Sequence = (),
        expected: Optional[ExpectedState] = None,
    ) -> ExplainabilityResult:
        """Explain one authoritative RiskAssessment (read-only).

        ``assessment`` is required and authoritative. The optional
        ``correlation`` / ``ml_result`` / ``evidence_refs`` reproduce the
        inputs the risk engine consumed, so explanations can cite the original
        verdicts and evidence without recomputing anything.
        """
        if not isinstance(assessment, RiskAssessment):
            raise TypeError("assessment must be a RiskAssessment")
        if correlation is not None and not isinstance(correlation, CorrelationResult):
            raise TypeError("correlation must be a CorrelationResult or None")
        if expected is not None and not isinstance(expected, ExpectedState):
            raise TypeError("expected must be an ExpectedState or None")
        for ref in evidence_refs:
            if not isinstance(ref, EvidenceRef):
                raise TypeError("evidence_refs must contain EvidenceRef objects")

        # ---- read-only inputs ---------------------------------------------
        assessment_refs: tuple = tuple(assessment.evidence_refs)
        provided = _resolve_ml_result(correlation, ml_result)

        # ---- finding explanations (order == assessment finding order) ----
        finding_explanations = tuple(
            explain_finding(finding, evidence_refs=assessment_refs)
            for finding in assessment.findings
        )

        # ---- ML explanations (evidence = refs on the ML finding only) -----
        ml_explanations = ()
        if provided is not None:
            ml_explanations = explain_ml_result(
                provided,
                classification_evidence_refs=_ml_finding_refs(
                    assessment, "ml.classification.disagreement"
                ),
                anomaly_evidence_refs=_ml_finding_refs(assessment, "ml.anomaly"),
            )

        # ---- UNKNOWN / NOT_APPLICABLE gap explanations --------------------
        unknown_explanations: list = []
        not_applicable_explanations: list = []
        ml_evaluated = False
        correlation_status: Optional[str] = None
        if correlation is not None:
            correlation_status = correlation.status
            ml_evaluated = bool(correlation.metadata.get("ml_evaluated", False))
            for outcome in getattr(correlation, "unknowns", []):
                variable = outcome.get("variable")
                if not variable:
                    continue
                unknown_explanations.append(
                    GapExplanation(
                        provenance=PROVENANCE_CORRELATION_RESULT,
                        status=outcome.get("status", "UNKNOWN"),
                        variable=variable,
                        expected_value=outcome.get("expected_value"),
                        reason=outcome.get("reason") or "",
                        explanation=unknown_explanation_text(
                            variable, outcome.get("reason")
                        ),
                        explanation_categories=(EXPLANATION_CATEGORY_LIMITATION,),
                        limitations=unknown_limitations(variable),
                    )
                )
            for outcome in getattr(correlation, "not_applicable", []):
                variable = outcome.get("variable")
                if not variable:
                    continue
                not_applicable_explanations.append(
                    GapExplanation(
                        provenance=PROVENANCE_CORRELATION_RESULT,
                        status=outcome.get("status", "NOT_APPLICABLE"),
                        variable=variable,
                        expected_value=outcome.get("expected_value"),
                        reason=outcome.get("reason") or "",
                        explanation=not_applicable_explanation_text(variable),
                        explanation_categories=(EXPLANATION_CATEGORY_LIMITATION,),
                        limitations=not_applicable_limitations(variable),
                    )
                )
        unknown_explanations = tuple(unknown_explanations)
        not_applicable_explanations = tuple(not_applicable_explanations)

        # ---- evidence summary (union of existing refs, no fabrication) ----
        evidence = build_evidence_summary(
            assessment_refs,
            tuple(evidence_refs),
            finding_refs=_collect_finding_refs(assessment)
            + _collect_outcome_refs(correlation),
        )

        # ---- score explanation (copied, never recomputed) ------------------
        score_explanation = build_score_explanation(assessment)

        categories = sorted(
            {
                cat
                for explanation in finding_explanations
                for cat in explanation.explanation_categories
            }
            | {
                cat
                for explanation in ml_explanations
                for cat in explanation.explanation_categories
            }
            | {
                cat
                for explanation in unknown_explanations + not_applicable_explanations
                for cat in explanation.explanation_categories
            }
        )

        meta = dict(assessment.metadata or {})
        summary = ExplainabilitySummary(
            overall_score=assessment.overall_score,
            severity=assessment.severity,
            risk_policy_version=assessment.risk_policy_version,
            finding_explanations=len(finding_explanations),
            ml_explanations=len(ml_explanations),
            unknown_explanations=len(unknown_explanations),
            not_applicable_explanations=len(not_applicable_explanations),
            evidence_refs=evidence.total_refs,
            overall_explanation=overall_explanation_text(
                assessment.overall_score,
                assessment.severity,
                assessment.risk_policy_version,
                len(finding_explanations),
                len(ml_explanations),
                len(unknown_explanations),
                len(not_applicable_explanations),
            ),
        )

        metadata: Dict[str, Any] = {
            "explainability_engine_version": XAI_ENGINE_VERSION,
            "input_summary": {
                "assessment_schema_version": assessment.schema_version,
                "assessment_risk_engine_version": assessment.risk_engine_version,
                "correlation_status": correlation_status,
                "correlation_supplied": correlation is not None,
                "ml_present": provided is not None,
                "ml_evaluated": ml_evaluated,
                "expected_state_supplied": expected is not None,
                "findings_count": len(assessment.findings),
            },
            "explanation_categories_present": categories,
            "unknown_handling": dict(meta.get("unknown_handling") or {}),
            "evidence_policy": dict(meta.get("evidence_policy") or {}),
            "authority": {
                "score_unchanged": True,
                "severity_unchanged": True,
                "findings_read_only": True,
                "correlation_read_only": correlation is not None,
                "ml_read_only": provided is not None,
                "note": (
                    "The explainability engine consumes existing Phase-4/5/6 "
                    "outputs and never recomputes, overrides, or fabricates "
                    "authoritative results."
                ),
            },
            "deterministic": True,
        }

        return ExplainabilityResult(
            schema_version=XAI_SCHEMA_VERSION,
            identity=assessment.identity,
            summary=summary,
            finding_explanations=finding_explanations,
            ml_explanations=ml_explanations,
            unknown_explanations=unknown_explanations,
            not_applicable_explanations=not_applicable_explanations,
            evidence_summary=evidence,
            score_explanation=score_explanation,
            metadata=metadata,
        )