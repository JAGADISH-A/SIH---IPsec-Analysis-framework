"""Phase 9 — ResponseEngine: state machine + lifecycle orchestration.

The engine drives every recommendation through an EXPLICIT, validated state
machine (``validate_transition``) and appends audit events to an append-only
ledger. The separation of concerns is preserved end to end:

    DETECTION -> RISK -> RECOMMENDATION -> AUTHORIZATION -> APPROVAL ->
    EXECUTION (dry-run) -> RESULT

Nothing here collapses those stages; nothing here performs a real network
operation; nothing auto-executes on severity / ML anomaly / finding presence.
"""

from dataclasses import dataclass
from typing import Any, Callable, List, Optional, Sequence, Tuple

from ..models import (
    CORRELATION_STATUS_UNKNOWN,
    CorrelationResult,
    EvidenceRef,
    MLResult,
)
from ..risk.models import RiskAssessment
from ..xai.models import ExplainabilityResult
from .approval import (
    approve as _approve,
    reject as _reject,
    request_approval as _request_approval,
)
from .audit import AuditLedger
from .authorization import authorize as _authorize
from .executor import DryRunExecutor, ResponseExecutor
from .models import (
    APPROVAL_PENDING,
    EVENT_APPROVAL_REQUESTED,
    EVENT_APPROVED,
    EVENT_AUTHORIZATION_CHECKED,
    EVENT_CANCELLED,
    EVENT_DRY_RUN_EXECUTED,
    EVENT_EXECUTION_FAILED,
    EVENT_EXECUTION_REQUESTED,
    EVENT_EXECUTION_SUCCEEDED,
    EVENT_EXPIRED,
    EVENT_RECOMMENDATION_CREATED,
    EVENT_REJECTED,
    STATUS_APPROVED,
    STATUS_AUTHORIZED,
    STATUS_CANCELLED,
    STATUS_DENIED,
    STATUS_DRY_RUN,
    STATUS_EXECUTION_REQUESTED,
    STATUS_EXPIRED,
    STATUS_NOT_EVALUATED,
    STATUS_PENDING_APPROVAL,
    STATUS_RECOMMENDED,
    STATUS_REJECTED,
    STATUS_SUCCEEDED,
    STATUS_FAILED,
    ApprovalError,
    ApprovalRequest,
    AuthorizationContext,
    AuthorizationDecision,
    ExecutionRequest,
    ExecutionResult,
    ExpiredError,
    ResponsePlan,
    ResponseRecommendation,
    ResponseStateError,
    is_high_impact,
    validate_transition,
)
from .planner import PlanningContext, plan as make_plan
from .policy import ResponsePolicy

# ---------------------------------------------------------------------------
# deterministic demo clock
# ---------------------------------------------------------------------------

DEMO_CLOCK_NS = 1_800_000_000_000_000_000


def demo_clock() -> int:
    """Deterministic fixed clock (no current-time dependence in the plan)."""
    return DEMO_CLOCK_NS


# ---------------------------------------------------------------------------
# engine
# ---------------------------------------------------------------------------


@dataclass
class ResponseEngine:
    """Deterministic orchestrator. ``clock`` must be an int-returning callable."""

    policy: ResponsePolicy = None  # type: ignore[assignment]
    clock: Callable[[], Optional[int]] = demo_clock
    ledger: AuditLedger = None  # type: ignore[assignment]
    executor: ResponseExecutor = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self.policy is None:
            self.policy = ResponsePolicy.default()
        if not isinstance(self.policy, ResponsePolicy):
            raise TypeError("policy must be a ResponsePolicy")
        if not callable(self.clock):
            raise TypeError("clock must be callable")
        if self.ledger is None:
            self.ledger = AuditLedger(engine_version="v1")
        if not isinstance(self.ledger, AuditLedger):
            raise TypeError("ledger must be an AuditLedger")
        if self.executor is None:
            self.executor = DryRunExecutor()
        if not isinstance(self.executor, ResponseExecutor):
            raise TypeError("executor must be a ResponseExecutor")

    def _now(self) -> Optional[int]:
        return self.clock()

    def _append(
        self,
        *,
        recommendation: "ResponseRecommendation",
        event_type: str,
        principal: str,
        reason: str = "",
        approval: "Optional[ApprovalRequest]" = None,
        previous_status: "Optional[str]" = None,
        new_status: "Optional[str]" = None,
        action: "Optional[str]" = None,
    ) -> None:
        self.ledger.append(
            timestamp=self._now(),
            assessment_identity=recommendation.assessment_identity,
            event_type=event_type,
            principal=principal,
            reason=reason,
            policy_version=self.policy.policy_version,
            recommendation_id=recommendation.recommendation_id,
            approval_id=approval.approval_id if approval else None,
            action=action if action is not None else recommendation.action,
            previous_status=previous_status,
            new_status=new_status,
            evidence_refs=recommendation.evidence_refs,
        )

    # -- planning -----------------------------------------------------------

    def plan(
        self,
        assessment: RiskAssessment,
        *,
        xai: Optional[ExplainabilityResult] = None,
        correlation: Optional[CorrelationResult] = None,
        ml_result: Optional[MLResult] = None,
        evidence_refs: Sequence = (),
        emit_events: bool = True,
    ) -> ResponsePlan:
        """Build a plan and (by default) append RECOMMENDATION_CREATED events.

        ``emit_events`` may be disabled by callers that seed a pre-built plan
        (e.g. the deterministic dashboard store) to avoid duplicate events.
        """
        if not isinstance(assessment, RiskAssessment):
            raise TypeError("assessment must be a RiskAssessment")
        ctx = PlanningContext(
            assessment=assessment,
            xai=xai,
            correlation=correlation,
            ml_result=ml_result,
            evidence_refs=tuple(evidence_refs),
            policy=self.policy,
        )
        plan = make_plan(ctx, clock=self.clock)
        if emit_events:
            for recommendation in plan.recommendations:
                self._append(
                    recommendation=recommendation,
                    event_type=EVENT_RECOMMENDATION_CREATED,
                    principal="system:planner",
                    reason=(
                        f"recommended {recommendation.action} for "
                        f"{recommendation.finding_id}"
                    ),
                    previous_status=STATUS_NOT_EVALUATED,
                    new_status=STATUS_RECOMMENDED,
                )
        return plan

    # -- state helpers ------------------------------------------------------

    def _transition(self, recommendation: ResponseRecommendation, to_status: str) -> None:
        validate_transition(recommendation.status, to_status)
        recommendation.status = to_status

    # -- approval -----------------------------------------------------------

    def request_approval(
        self,
        recommendation: ResponseRecommendation,
        commanded_by: str,
        reason: str = "",
    ) -> ApprovalRequest:
        """Create the PENDING approval request (status must be RECOMMENDED)."""
        now = self._now()
        try:
            approval = _request_approval(
                recommendation, commanded_by, reason,
                now_ns=now, policy=self.policy,
            )
        except ApprovalError:
            raise
        if recommendation.status != STATUS_RECOMMENDED:
            raise ResponseStateError(recommendation.status, STATUS_PENDING_APPROVAL)
        self._transition(recommendation, STATUS_PENDING_APPROVAL)
        self._append(
            recommendation=recommendation,
            event_type=EVENT_APPROVAL_REQUESTED,
            principal=commanded_by,
            reason=reason or f"approval requested by {commanded_by}",
            approval=approval,
            previous_status=STATUS_RECOMMENDED,
            new_status=STATUS_PENDING_APPROVAL,
        )
        return approval

    def approve(
        self,
        approval: ApprovalRequest,
        recommendation: ResponseRecommendation,
        commanded_by: str,
        *,
        roles: Sequence[str],
    ) -> ApprovalRequest:
        now = self._now()
        approved = _approve(
            approval, recommendation, commanded_by,
            roles=tuple(roles), now_ns=now, policy=self.policy,
        )
        self._transition(recommendation, STATUS_APPROVED)
        self._append(
            recommendation=recommendation,
            event_type=EVENT_APPROVED,
            principal=commanded_by,
            reason=f"approved by {commanded_by}",
            approval=approved,
            previous_status=STATUS_PENDING_APPROVAL,
            new_status=STATUS_APPROVED,
        )
        return approved

    def reject(
        self,
        approval: ApprovalRequest,
        recommendation: ResponseRecommendation,
        commanded_by: str,
        rejection_reason: str,
    ) -> ApprovalRequest:
        now = self._now()
        rejected = _reject(
            approval, recommendation, commanded_by,
            rejection_reason=rejection_reason, now_ns=now,
        )
        self._transition(recommendation, STATUS_REJECTED)
        self._append(
            recommendation=recommendation,
            event_type=EVENT_REJECTED,
            principal=commanded_by,
            reason=rejection_reason,
            approval=rejected,
            previous_status=STATUS_PENDING_APPROVAL,
            new_status=STATUS_REJECTED,
        )
        return rejected

    # -- authorization ------------------------------------------------------

    def authorize(
        self,
        recommendation: ResponseRecommendation,
        context: AuthorizationContext,
    ) -> AuthorizationDecision:
        """Check + record an explicit authorization decision.

        On denial the recommendation transitions to DENIED. On approval the
        recommendation advances to AUTHORIZED ONLY when its gates are met:
        approval-required actions must first be APPROVED.
        """
        decision = _authorize(context, recommendation.action, self.policy)
        prior = recommendation.status
        if prior == STATUS_AUTHORIZED:
            self._append(
                recommendation=recommendation,
                event_type=EVENT_AUTHORIZATION_CHECKED,
                principal=context.principal_id,
                reason=decision.reason,
                previous_status=STATUS_AUTHORIZED,
                new_status=STATUS_AUTHORIZED,
            )
            return decision
        if not decision.authorized:
            if prior != STATUS_DENIED:
                self._transition(recommendation, STATUS_DENIED)
            self._append(
                recommendation=recommendation,
                event_type=EVENT_AUTHORIZATION_CHECKED,
                principal=context.principal_id,
                reason=decision.reason,
                previous_status=prior,
                new_status=STATUS_DENIED,
            )
            raise ApprovalError(
                f"authorization denied for {context.principal_id} on "
                f"{recommendation.action}: {decision.reason}"
            )
        if recommendation.approval_required and prior != STATUS_APPROVED:
            raise ResponseStateError(
                prior,
                STATUS_AUTHORIZED,
                # friendly message appended by the exception itself
            )
        self._transition(recommendation, STATUS_AUTHORIZED)
        self._append(
            recommendation=recommendation,
            event_type=EVENT_AUTHORIZATION_CHECKED,
            principal=context.principal_id,
            reason=decision.reason,
            previous_status=prior,
            new_status=STATUS_AUTHORIZED,
        )
        return decision

    # -- execution (dry-run) ------------------------------------------------

    def execute_dry_run(
        self,
        recommendation: ResponseRecommendation,
        context: AuthorizationContext,
        commanded_by: str,
        reason: str = "",
    ) -> Tuple[ExecutionResult, ResponseRecommendation]:
        """Validate gates, then run the executor (dry-run only in Phase 9)."""
        now = self._now()
        if now is not None and recommendation.is_expired(now):
            raise ExpiredError(
                f"recommendation {recommendation.recommendation_id} has expired"
            )
        prior = recommendation.status
        gated = recommendation.approval_required or recommendation.authorization_required
        if gated and prior != STATUS_AUTHORIZED:
            raise ResponseStateError(prior, STATUS_DRY_RUN)

        decision = self.authorize(recommendation, context)

        request = ExecutionRequest(
            execution_id=f"EXEC-{recommendation.recommendation_id}",
            recommendation_id=recommendation.recommendation_id,
            action=recommendation.action,
            executor_type="dry-run",
            requested_by=commanded_by,
            issued_at=now,
        )
        self._transition(recommendation, STATUS_EXECUTION_REQUESTED)
        self._append(
            recommendation=recommendation,
            event_type=EVENT_EXECUTION_REQUESTED,
            principal=commanded_by,
            reason=reason or f"execution requested by {commanded_by}",
            previous_status=STATUS_AUTHORIZED,
            new_status=STATUS_EXECUTION_REQUESTED,
        )

        result = self.executor.execute(
            request,
            recommendation=recommendation,
            authorization=decision,
            approval_status=(
                "APPROVED"
                if recommendation.approval_required
                else "NOT_REQUIRED"
            ),
            now_ns=now,
            policy=self.policy,
            evidence_refs=recommendation.evidence_refs,
            simulate_would_execute=is_high_impact(recommendation.action),
        )
        self._transition(recommendation, STATUS_DRY_RUN)
        self._append(
            recommendation=recommendation,
            event_type=EVENT_DRY_RUN_EXECUTED,
            principal=commanded_by,
            reason=result.message,
            previous_status=STATUS_EXECUTION_REQUESTED,
            new_status=STATUS_DRY_RUN,
        )
        final_status = STATUS_SUCCEEDED if result.success else STATUS_FAILED
        self._transition(recommendation, final_status)
        self._append(
            recommendation=recommendation,
            event_type=(
                EVENT_EXECUTION_SUCCEEDED if result.success
                else EVENT_EXECUTION_FAILED
            ),
            principal=commanded_by,
            reason=result.message,
            previous_status=STATUS_DRY_RUN,
            new_status=final_status,
        )
        return result, recommendation

    def cancel(
        self,
        recommendation: ResponseRecommendation,
        commanded_by: str,
        reason: str = "",
    ) -> ResponseRecommendation:
        prior = recommendation.status
        self._transition(recommendation, STATUS_CANCELLED)
        self._append(
            recommendation=recommendation,
            event_type=EVENT_CANCELLED,
            principal=commanded_by,
            reason=reason or "cancelled by operator",
            previous_status=prior,
            new_status=STATUS_CANCELLED,
        )
        return recommendation

    # -- expiry -------------------------------------------------------------

    def expire(self, plan: ResponsePlan) -> List[str]:
        """Expire all eligible recommendations (injected clock only)."""
        now = self._now()
        if now is None:
            return []
        expired = []
        for recommendation in plan.recommendations:
            if recommendation.status not in (
                STATUS_RECOMMENDED, STATUS_PENDING_APPROVAL, STATUS_APPROVED,
                STATUS_AUTHORIZED, STATUS_EXECUTION_REQUESTED,
            ):
                continue
            if recommendation.is_expired(now):
                prior = recommendation.status
                self._transition(recommendation, STATUS_EXPIRED)
                self._append(
                    recommendation=recommendation,
                    event_type=EVENT_EXPIRED,
                    principal="system:expiry",
                    reason=(
                        f"recommendation expired at {recommendation.expires_at}"
                    ),
                    previous_status=prior,
                    new_status=STATUS_EXPIRED,
                )
                expired.append(recommendation.recommendation_id)
        return expired


def plain_clock(now_ns: Optional[int] = None) -> Callable[[], Optional[int]]:
    """Return a clock that yields the same value every call (deterministic)."""

    def _clock() -> Optional[int]:
        return now_ns

    return _clock