"""Phase 9 — response planner.

The planner CONSUMES the already-produced Phase-4/5/6/7 outputs and a
``ResponsePolicy`` and PRODUCES a ``ResponsePlan`` — it NEVER executes anything
and never makes network changes. Every decision (action, priority, gates,
expiry) is derived from the policy + traceability registry, never hard-coded.

Inputs:

    RiskAssessment (required)
    ExplainabilityResult / CorrelationResult / MLResult / EvidenceRef (optional)
    ResponsePolicy (required)
    clock  (optional; deterministic in production via a fixed demo clock)

UNKNOWN variables (evidence gaps) aggregate into a single
``CAPTURE_EVIDENCE`` recommendation; NOT_APPLICABLE variables produce NO
security response.
"""

from dataclasses import dataclass
from typing import Any, Dict, Optional, Sequence, Tuple

from ..models import (
    CORRELATION_STATUS_NOT_APPLICABLE,
    CORRELATION_STATUS_UNKNOWN,
    CorrelationResult,
    EvidenceRef,
    MLResult,
)
from ..risk.models import (
    SOURCE_ML,
    SEVERITY_RANK,
    RiskAssessment,
    RiskFinding,
)
from ..xai.models import ExplainabilityResult
from .models import (
    PRIORITY_LOW,
    STATUS_RECOMMENDED,
    ResponsePlan,
    ResponseRecommendation,
    expiring_copy,
)
from .policy import ResponsePolicy
from .rules import traceability_for


@dataclass(frozen=True)
class PlanningContext:
    """Everything the planner may read (all validated by the engine/callers)."""

    assessment: RiskAssessment
    xai: Optional[ExplainabilityResult] = None
    correlation: Optional[CorrelationResult] = None
    ml_result: Optional[MLResult] = None
    evidence_refs: Tuple[EvidenceRef, ...] = ()
    policy: ResponsePolicy = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if not isinstance(self.assessment, RiskAssessment):
            raise TypeError("assessment must be a RiskAssessment")
        if self.policy is None:
            raise TypeError("policy is required")
        if not isinstance(self.policy, ResponsePolicy):
            raise TypeError("policy must be a ResponsePolicy")
        if self.correlation is not None and not isinstance(self.correlation, CorrelationResult):
            raise TypeError("correlation must be a CorrelationResult or None")
        if self.ml_result is not None and not isinstance(self.ml_result, MLResult):
            raise TypeError("ml_result must be an MLResult or None")
        if not isinstance(self.evidence_refs, (tuple, list)):
            raise ValueError("evidence_refs must be a tuple/list")


def _rationale(
    finding: RiskFinding,
    action: str,
    policy: ResponsePolicy,
    provenance: str,
) -> str:
    trace = traceability_for(finding.rule_id)
    rule_ref = trace.get("rule_id", "RESP-DEFAULT-000")
    if provenance == "RESPONSE_ML":
        return (
            f"Response rule {rule_ref}: finding {finding.rule_id} is "
            f"model-derived evidence under {policy.policy_version}; action "
            f"{action} is capped by ml_handling and can never block traffic "
            f"(model_version={finding.model_version or 'n/a'})."
        )
    if provenance == "RESPONSE_EVIDENCE_GAP":
        return (
            f"Response rule {rule_ref}: the authoritative observation for "
            f"{finding.related_variable or finding.rule_id} was UNKNOWN; the "
            f"policy recommends {action} to close the evidence gap, never a "
            f"blocking action."
        )
    if provenance == "RESPONSE_DEFAULT":
        return (
            f"Severity default action under {policy.policy_version} maps "
            f"{finding.rule_id} ({finding.severity}) to {action}."
        )
    return (
        f"Response rule {rule_ref} under {policy.policy_version} maps "
        f"{finding.rule_id} ({finding.severity}) to {action} with analyst "
        f"approval."
    )


def _recommendation(
    finding: RiskFinding,
    assessment: RiskAssessment,
    *,
    policy: ResponsePolicy,
    now_ns: Optional[int],
    is_ml: bool,
) -> ResponseRecommendation:
    action = policy.action_for(finding.rule_id, finding.severity)
    provenance = "RESPONSE_POLICY"
    if is_ml:
        capped = policy.cap_for_ml(action)
        if capped != action:
            provenance = "RESPONSE_ML"
        action = capped

    requirements = policy.requirements_for(finding.rule_id, action)
    approval_required = bool(requirements.get("approval_required", False))
    authorization_required = bool(requirements.get("authorization_required", False))
    required_roles = tuple(requirements.get("required_roles") or ("ANALYST",))
    priority = policy.priority_for(finding.rule_id, finding.severity)

    trace = traceability_for(finding.rule_id)
    limitations = list(trace.get("limitations") or [])
    if action in ("ISOLATE_FLOW", "BLOCK_FLOW", "TERMINATE_SESSION",
                  "RENEGOTIATE_SESSION", "REQUIRE_RECONFIGURATION"):
        limitations.append(
            "High-impact logical action: execution requires policy "
            "authorization + authorized role + analyst approval; disabled in "
            "Phase 9 (dry-run only)."
        )

    reason = finding.reason or trace.get("condition", f"finding {finding.rule_id}")
    return ResponseRecommendation(
        recommendation_id=f"RR-{finding.finding_id}",
        assessment_identity=assessment.identity,
        finding_id=finding.finding_id,
        rule_id=finding.rule_id,
        action=action,
        priority=priority,
        reason=reason,
        rationale=_rationale(finding, action, policy, provenance),
        severity=finding.severity,
        risk_score=assessment.overall_score,
        policy_version=policy.policy_version,
        authorization_required=authorization_required,
        approval_required=approval_required,
        required_roles=required_roles,
        expires_at=expiring_copy(now_ns, now_ns, policy.expiry_ns) if now_ns is not None else None,
        evidence_refs=finding.evidence_refs,
        limitations=tuple(limitations),
        status=STATUS_RECOMMENDED,
        provenance=provenance,
    )


def _unknown_gap_recommendation(
    assessment: RiskAssessment,
    unknown_count: int,
    *,
    policy: ResponsePolicy,
    now_ns: Optional[int],
) -> ResponseRecommendation:
    handle = policy.unknown_handling
    action = handle.get("action", "CAPTURE_EVIDENCE")
    requirements = policy.requirements_for("evidence.unknown.gap", action)
    finding = RiskFinding(
        finding_id="REVIEW-UNKNOWN-EVIDENCE",
        rule_id="evidence.unknown.gap",
        category="INSUFFICIENT_EVIDENCE",
        severity="INFO",
        title="UNKNOWN observation evidence gap",
        description=f"{unknown_count} UNKNOWN correlation variable(s) had no authoritative observation.",
        reason=(
            "At least one comparison outcome had status UNKNOWN; evidence is "
            "missing, NOT a mismatch and never a vulnerability."
        ),
        condition="correlation.unknowns[*].status == UNKNOWN",
        source="CORRELATION",
        evidence_type="observation",
        related_variable="correlation.unknowns[]",
    )
    return ResponseRecommendation(
        recommendation_id="RR-UNKNOWN-EVIDENCE-GAP",
        assessment_identity=assessment.identity,
        finding_id=finding.finding_id,
        rule_id="evidence.unknown.gap",
        action=action,
        priority=handle.get("priority", PRIORITY_LOW),
        reason=finding.reason,
        rationale=_rationale(finding, action, policy, "RESPONSE_EVIDENCE_GAP"),
        severity="INFO",
        risk_score=assessment.overall_score,
        policy_version=policy.policy_version,
        authorization_required=bool(
            requirements.get("authorization_required", handle.get("authorization_required", False))
        ),
        approval_required=bool(
            requirements.get("approval_required", handle.get("approval_required", True))
        ),
        required_roles=tuple(handle.get("required_roles") or ("ANALYST",)),
        expires_at=expiring_copy(now_ns, now_ns, policy.expiry_ns) if now_ns is not None else None,
        evidence_refs=(),
        limitations=(
            "UNKNOWN is an evidence gap; it never becomes a MISMATCH and never "
            "triggers a blocking response.",
        ),
        status=STATUS_RECOMMENDED,
        provenance="RESPONSE_EVIDENCE_GAP",
    )


def plan(ctx: PlanningContext, *, clock: Optional[Any] = None) -> ResponsePlan:
    """Produce the deterministic ResponsePlan for one assessment."""
    if not isinstance(ctx, PlanningContext):
        raise TypeError("plan() expects a PlanningContext")
    assessment = ctx.assessment
    now_ns = clock() if clock is not None else None

    findings = sorted(
        assessment.findings,
        key=lambda finding: (SEVERITY_RANK[finding.severity], finding.finding_id),
    )
    recommendations: list = []
    for finding in findings:
        is_ml = finding.source == SOURCE_ML
        recommendations.append(
            _recommendation(finding, assessment, policy=ctx.policy, now_ns=now_ns, is_ml=is_ml)
        )

    unknown_count = 0
    if ctx.correlation is not None:
        distinct = set()
        for outcome in ctx.correlation.unknowns:
            status = outcome.get("status") if isinstance(outcome, dict) else None
            variable = outcome.get("variable") if isinstance(outcome, dict) else None
            if status == CORRELATION_STATUS_UNKNOWN and variable is not None:
                distinct.add(variable)
        unknown_count = len(distinct)

    if unknown_count and ctx.policy.unknown_handling.get("recommend", True):
        recommendations.append(
            _unknown_gap_recommendation(
                assessment, unknown_count, policy=ctx.policy, now_ns=now_ns
            )
        )

    def rec_key(rec: ResponseRecommendation) -> Tuple[int, str]:
        widths = {
            "NO_ACTION": 0, "ALERT_ONLY": 1, "REQUIRE_REVIEW": 2,
            "CAPTURE_EVIDENCE": 3, "ISOLATE_FLOW": 4, "BLOCK_FLOW": 5,
            "TERMINATE_SESSION": 6, "RENEGOTIATE_SESSION": 7,
            "REQUIRE_RECONFIGURATION": 8,
        }
        return (widths.get(rec.action, 9), rec.recommendation_id)

    ordered = tuple(sorted(recommendations, key=rec_key))
    return ResponsePlan(
        assessment_identity=assessment.identity,
        policy_version=ctx.policy.policy_version,
        recommendations=ordered,
        requires_approval=any(rec.approval_required for rec in ordered),
        requires_authorization=any(rec.authorization_required for rec in ordered),
        generated_deterministically=True,
        limitations=ctx.policy.plan_limitations,
    )