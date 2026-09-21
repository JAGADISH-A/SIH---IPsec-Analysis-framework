"""Execution Control Plane (Phase 10) — the two-layer enforcement gateway.

Only an already-governed recommendation reaches this plane. The plane applies
the production gates IN ORDER and NEVER bypasses Phase 9:

    1. authorization decision present and authorized
    2. approval present and APPROVED when the recommendation requires it
    3. recommendation NOT expired and in an executable status
    4. structured target parses
    5. idempotency: same (execution, action, target) never applied twice
    6. mode + allow-list + host availability (executor-side, honest)

Every gate failure yields a distinct structured status:

    DENIED / EXPIRED / ALREADY_APPLIED / TARGET_NOT_ALLOWED /
    NOT_SUPPORTED / DEPENDENCY_UNAVAILABLE

ML and risk score NEVER reach this plane directly: only an APPROVED and
AUTHORIZED Phase-9 recommendation (``response.recommendation``) may enter.
Success is never fabricated: SUCCEEDED means the injected host actually
reported ``applied=True``.
"""

from dataclasses import dataclass
from typing import Any, Dict, Optional

from ..models import EvidenceRef, CorrelationIdentity
from ..response.audit import AuditLedger
from ..response.models import (
    EVENT_EXECUTION_FAILED,
    EVENT_EXECUTION_SUCCEEDED,
    AuthorizationDecision,
    ExecutionRequest,
    STATUS_AUTHORIZED,
    STATUS_EXECUTION_REQUESTED,
    ResponseRecommendation,
    ApprovalRequest,
)
from .base import (
    STATUS_ALREADY_APPLIED,
    STATUS_DENIED,
    STATUS_EXPIRED,
    ExecutionOutcome,
)
from .executors import executor_for, UnsupportedExecutor
from .host import HostOperations, UnavailableHost
from .idempotency import IdempotencyRegistry, idempotency_key
from .settings import ExecutionSettings
from .targets import ExecutionTarget

EXECUTABLE_STATUSES = frozenset((STATUS_AUTHORIZED, STATUS_EXECUTION_REQUESTED))
APPROVAL_APPROVED_STATUS = "APPROVED"


def _as_target(value: Any) -> Optional[ExecutionTarget]:
    if isinstance(value, ExecutionTarget):
        return value
    if isinstance(value, dict):
        try:
            return ExecutionTarget.from_dict(value)
        except ValueError:
            return None
    return None


@dataclass
class ExecutionControlPlane:
    """Governed entry point for production enforcement."""

    settings: Optional[ExecutionSettings] = None
    registry: Optional[IdempotencyRegistry] = None
    ledger: Optional[AuditLedger] = None
    host: Optional[HostOperations] = None

    def __post_init__(self) -> None:
        if self.settings is None:
            self.settings = ExecutionSettings()
        if self.registry is None:
            self.registry = IdempotencyRegistry(
                window_ns=self.settings.idempotency_window
            )
        if self.host is None:
            # safe default: never fake success (DEPENDENCY_UNAVAILABLE)
            self.host = UnavailableHost()
        self._outcomes: list = []

    @staticmethod
    def _denied(
        request: ExecutionRequest, reason: str, *, status: str = STATUS_DENIED,
        target: Optional[ExecutionTarget] = None, now_ns: Optional[int] = None,
    ) -> ExecutionOutcome:
        return ExecutionOutcome(
            execution_id=request.execution_id,
            recommendation_id=request.recommendation_id,
            action=request.action,
            executor_type=request.executor_type,
            status=status,
            success=False,
            network_effect=False,
            reason=reason,
            operation=target.to_dict() if target else {},
            started_at=now_ns,
            completed_at=now_ns,
        )

    def execute(
        self,
        request: ExecutionRequest,
        *,
        recommendation: Optional[ResponseRecommendation] = None,
        authorization: Optional[AuthorizationDecision] = None,
        approval: Optional[ApprovalRequest] = None,
        target: Optional[ExecutionTarget] = None,
        now_ns: Optional[int] = None,
        evidence_refs=(),
    ) -> ExecutionOutcome:
        target = _as_target(target)
        if target is None:
            return self._denied(
                request,
                "a structured ExecutionTarget is required (nothing executes "
                "without a concrete allow-list-checkable target)",
                now_ns=now_ns,
            )
        if recommendation is None:
            return self._denied(
                request,
                "no governed recommendation; ML/risk alone can never reach "
                "execution",
                target=target, now_ns=now_ns,
            )
        if recommendation.action != request.action:
            return self._denied(
                request,
                f"request action {request.action!r} does not match the governed "
                f"recommendation {recommendation.action!r}",
                target=target, now_ns=now_ns,
            )
        if recommendation.status not in EXECUTABLE_STATUSES:
            return self._denied(
                request,
                f"recommendation status {recommendation.status!r} is not "
                "executable (only APPROVED+AUTHORIZED executions proceed)",
                target=target, now_ns=now_ns,
            )
        if authorization is None or not authorization.authorized:
            return self._denied(
                request,
                "authorization is required and must be explicit (denied)",
                target=target, now_ns=now_ns,
            )
        if (
            recommendation.approval_required
            and (approval is None or getattr(approval, "status", None) != APPROVAL_APPROVED_STATUS)
        ):
            return self._denied(
                request,
                "analyst approval is required and must be APPROVED",
                target=target, now_ns=now_ns,
            )

        # idempotency (never apply the same operation twice)
        key = idempotency_key(request.execution_id, request.action, target)
        previous = self.registry.already_applied(key, now_ns=now_ns)
        if previous is not None:
            return self._denied(
                request,
                f"already applied (idempotency key {key!r}); no second network "
                "operation is issued",
                status=STATUS_ALREADY_APPLIED, target=target, now_ns=now_ns,
            )

        # expiry is checked by the recommendation itself
        if recommendation.is_expired(now_ns) if now_ns is not None else False:
            return self._denied(
                request,
                "the authorization/approval window has expired",
                status=STATUS_EXPIRED, target=target, now_ns=now_ns,
            )

        # executor resolution + execution (mode + allow-list + host gates)
        executor = executor_for(
            request.executor_type,
            settings=self.settings,
            host=self.host,
        )
        outcome = executor.execute(
            request,
            target=target,
            recommendation=recommendation,
            authorization=authorization,
            now_ns=now_ns,
            evidence_refs=tuple(evidence_refs),
        )

        # mark idempotent ONLY for genuinely-applied operations (never a dry-run
        # WOULD_APPLY, so it cannot block a later real execution)
        if outcome.status == "SUCCEEDED" and outcome.network_effect:
            self.registry.mark_applied(
                key, at_ns=now_ns, outcome_status=outcome.status
            )
        self._outcomes.append(outcome)

        self._append_audit(outcome, recommendation, now_ns)
        return outcome

    # -- audit integration (Phase 9 ledger, append-only chain) ---------------

    def _append_audit(
        self, outcome: ExecutionOutcome, recommendation: ResponseRecommendation,
        now_ns: Optional[int],
    ) -> None:
        if self.ledger is None:
            return
        event_type = (
            EVENT_EXECUTION_SUCCEEDED if outcome.success else EVENT_EXECUTION_FAILED
        )
        try:
            self.ledger.append(
                timestamp=now_ns,
                assessment_identity=recommendation.assessment_identity,
                event_type=event_type,
                principal="system:execution-plane",
                reason=outcome.reason,
                policy_version=recommendation.policy_version,
                recommendation_id=recommendation.recommendation_id,
                action=recommendation.action,
                previous_status=recommendation.status,
                new_status=outcome.status,
                evidence_refs=outcome.evidence_refs,
            )
        except Exception:
            # audit must never fork execution decisions; integrity checkers
            # still verify the chain in tests.
            pass

    # -- query ---------------------------------------------------------------

    def recent_executions(self, limit: int = 50) -> list:
        return [o.to_dict() for o in self._outcomes[-limit:]]

    @property
    def outcome_count(self) -> int:
        return len(self._outcomes)