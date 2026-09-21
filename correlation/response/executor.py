"""Phase 9 — controlled execution interface.

``ResponseExecutor`` is the abstraction (validate / execute / cancel). Phase 9
ships ONLY ``DryRunExecutor``: it validates the request, verifies the approval
state, produces a deterministic ``ExecutionResult`` and performs NO network
operation. Real network mechanics (iptables/nftables/XDP/eBPF/swanctl/…)
belong to Phase 10 production adapters — nothing in this module ever invokes
``subprocess``, ``os.system``, shell commands, SSH or remote execution.

Dry-run semantics:

* REQUIRE_REVIEW / ALERT_ONLY dry-run     -> status DRY_RUN, message
  ``NO_NETWORK_ACTION``, network_effect False;
* strong action fully authorized+approved -> status DRY_RUN, message
  ``WOULD_EXECUTE``, network_effect False (clearly stating NO actual network
  effect).
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, Optional, Sequence

from .authorization import AuthorizationDecision
from .models import (
    ExecutionRequest,
    ExecutionResult,
    ExecutorError,
    ResponseRecommendation,
    STATUS_CANCELLED,
    STATUS_DRY_RUN,
)
from .policy import ResponsePolicy

EXECUTOR_TYPE_DRY_RUN = "dry-run"
PRODUCTION_EXECUTOR = "phase-10"


class ResponseExecutor(ABC):
    """Controlled execution abstraction (Phase 10 provides real adapters)."""

    @abstractmethod
    def validate(self, request: ExecutionRequest, **context: Any) -> Dict[str, Any]:
        """Validate a request; return a deterministic validation dict."""

    @abstractmethod
    def execute(self, request: ExecutionRequest, **context: Any) -> ExecutionResult:
        """Execute (dry-run in Phase 9) and return a deterministic result."""

    @abstractmethod
    def cancel(self, request: ExecutionRequest, **context: Any) -> ExecutionResult:
        """Cancel the execution; never a network operation in Phase 9."""


class DryRunExecutor(ResponseExecutor):
    """The only executor in Phase 9. Always ``network_effect == False``."""

    executor_type = EXECUTOR_TYPE_DRY_RUN

    def __init__(self) -> None:
        self.validations: int = 0

    # -- validation ---------------------------------------------------------

    def _decision(
        self,
        request: ExecutionRequest,
        *,
        recommendation: Optional[ResponseRecommendation] = None,
        authorization: Optional[AuthorizationDecision] = None,
        approval_status: Optional[str] = None,
        now_ns: Optional[int] = None,
        policy: Optional[ResponsePolicy] = None,
    ) -> Dict[str, Any]:
        reasons: Dict[str, Any] = {}
        if policy is None:
            raise ExecutorError("policy is required for dry-run validation")
        if recommendation is not None:
            if recommendation.action != request.action:
                reasons["action_mismatch"] = (
                    f"request action {request.action} != recommendation "
                    f"{recommendation.action}"
                )
            if now_ns is not None and recommendation.is_expired(now_ns):
                reasons["expired"] = "the recommendation has expired"
            if recommendation.approval_required and approval_status != "APPROVED":
                reasons["approval"] = "analyst approval is required and not APPROVED"
        if authorization is not None and not authorization.authorized:
            reasons["authorization"] = authorization.reason
        if recommendation is not None and recommendation.authorization_required and authorization is None:
            reasons["authorization_missing"] = (
                "an authorization decision is required for this action"
            )
        validated = not reasons
        return {
            "execution_id": request.execution_id,
            "recommendation_id": request.recommendation_id,
            "action": request.action,
            "executor_type": request.executor_type,
            "validated": validated,
            "network_effect": False,
            "reasons": reasons,
            "message": "validated" if validated else "validation failed",
        }

    def validate(self, request: ExecutionRequest, **context: Any) -> Dict[str, Any]:
        if request.executor_type != self.executor_type:
            raise ExecutorError(
                f"DryRunExecutor cannot execute {request.executor_type!r}"
            )
        self.validations += 1
        decision_kwargs = {
            key: context[key]
            for key in (
                "recommendation", "authorization", "approval_status", "now_ns", "policy",
            )
            if key in context
        }
        return self._decision(request, **decision_kwargs)

    # -- execution -----------------------------------------------------------

    def execute(self, request: ExecutionRequest, **context: Any) -> ExecutionResult:
        decision = self.validate(request, **context)
        if not decision["validated"]:
            raise ExecutorError(
                f"dry-run rejected for {request.recommendation_id}: "
                f"{decision['reasons']}"
            )
        started = context.get("now_ns") if context.get("now_ns") is not None else None
        # A WOULD_EXECUTE dry-run still performs NO network action (Phase 9).
        message = (
            "WOULD_EXECUTE (dry-run: no real network operation is performed)"
            if context.get("simulate_would_execute")
            else "NO_NETWORK_ACTION (dry-run: execution validated only)"
        )
        return ExecutionResult(
            execution_id=request.execution_id,
            recommendation_id=request.recommendation_id,
            action=request.action,
            status=STATUS_DRY_RUN,
            executor_type=self.executor_type,
            started_at=started,
            completed_at=started,
            success=True,
            message=message,
            network_effect=False,
            evidence_refs=tuple(context.get("evidence_refs") or ()),
        )

    def cancel(self, request: ExecutionRequest, **context: Any) -> ExecutionResult:
        now = context.get("now_ns")
        return ExecutionResult(
            execution_id=f"{request.execution_id}-C",
            recommendation_id=request.recommendation_id,
            action=request.action,
            status=STATUS_CANCELLED,
            executor_type=self.executor_type,
            started_at=now,
            completed_at=now,
            success=False,
            message="CANCELLED (dry-run executor: no network action was performed)",
            network_effect=False,
            evidence_refs=tuple(context.get("evidence_refs") or ()),
        )