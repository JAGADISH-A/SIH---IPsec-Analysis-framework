"""Phase 10 — controlled production execution (base contract).

Two-layer enforcement architecture:

    Governance (Phase 9)            Production (Phase 10)
    --------------------            -----------------------
    risk -> plan -> approval        ExecutionControlPlane (gates)
    -> authorization -> issued       survives because:
                                        mode gate       DRY_RUN default,
                                                        enable_production=false
                                        target gate     allowed_testbed_targets
                                                        allow-list
                                        idempotency     (execution, action,
                                                        target) never twice
                                        expiry gate     never after expires_at
                                        executor        structured operation
                                                        descriptors only, no
                                                        arbitrary shell/SSH

Status vocabulary (strict superset of Phase 9 terminal statuses):

    SUCCEEDED / FAILED / DENIED / EXPIRED / CANCELLED
    ALREADY_APPLIED / NOT_SUPPORTED / TARGET_NOT_ALLOWED
    DEPENDENCY_UNAVAILABLE

Guarantees:

* ML NEVER produces an execution; risk score alone never triggers an action;
  every execution trace links back to the APPROVED+AUTHORIZED recommendation;
* no arbitrary ``subprocess`` / ``os.system`` / shell / SSH; operations are
  structured descriptors consumed by an injected ``HostOperations``;
* the default host is UNAVAILABLE: production mode without an explicit,
  allow-listed host adapter returns ``DEPENDENCY_UNAVAILABLE`` (never a fake
  SUCCEEDED);
* deterministic: injected now/timestamps, no ``now()``/random/UUID.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, Optional, Sequence, Tuple

from ..models import EvidenceRef

# ---------------------------------------------------------------------------
# execution statuses
# ---------------------------------------------------------------------------

STATUS_SUCCESS = "SUCCEEDED"
STATUS_FAILED = "FAILED"
STATUS_DENIED = "DENIED"
STATUS_EXPIRED = "EXPIRED"
STATUS_CANCELLED = "CANCELLED"
STATUS_ALREADY_APPLIED = "ALREADY_APPLIED"
STATUS_NOT_SUPPORTED = "NOT_SUPPORTED"
STATUS_TARGET_NOT_ALLOWED = "TARGET_NOT_ALLOWED"
STATUS_DEPENDENCY_UNAVAILABLE = "DEPENDENCY_UNAVAILABLE"

EXECUTION_STATUSES = (
    STATUS_SUCCESS,
    STATUS_FAILED,
    STATUS_DENIED,
    STATUS_EXPIRED,
    STATUS_CANCELLED,
    STATUS_ALREADY_APPLIED,
    STATUS_NOT_SUPPORTED,
    STATUS_TARGET_NOT_ALLOWED,
    STATUS_DEPENDENCY_UNAVAILABLE,
)

TERMINAL_STATUSES = EXECUTION_STATUSES

CLOSED_STATUSES = frozenset({
    STATUS_SUCCESS,
    STATUS_FAILED,
    STATUS_ALREADY_APPLIED,
    STATUS_DENIED,
    STATUS_EXPIRED,
    STATUS_CANCELLED,
    STATUS_NOT_SUPPORTED,
    STATUS_TARGET_NOT_ALLOWED,
    STATUS_DEPENDENCY_UNAVAILABLE,
})


def validate_execution_status(value: Any) -> str:
    if value not in EXECUTION_STATUSES:
        raise ValueError(
            f"execution status must be one of {EXECUTION_STATUSES}, got {value!r}"
        )
    return value


def is_success(status: str) -> bool:
    return status == STATUS_SUCCESS


# ---------------------------------------------------------------------------
# outcome
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ExecutionOutcome:
    """Structured outcome of one controlled production execution."""

    execution_id: str
    recommendation_id: str
    action: str
    executor_type: str
    status: str
    success: bool
    network_effect: bool
    reason: str
    operation: Dict[str, Any] = field(default_factory=dict)
    started_at: Optional[int] = None
    completed_at: Optional[int] = None
    evidence_refs: Tuple[EvidenceRef, ...] = field(default_factory=tuple)
    extras: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        from ..response.models import validate_action

        if not isinstance(self.execution_id, str) or not self.execution_id.strip():
            raise ValueError("execution_id must be a non-empty string")
        if not isinstance(self.recommendation_id, str) or not self.recommendation_id.strip():
            raise ValueError("recommendation_id must be a non-empty string")
        validate_action(self.action)
        if not isinstance(self.executor_type, str) or not self.executor_type.strip():
            raise ValueError("executor_type must be a non-empty string")
        validate_execution_status(self.status)
        if not isinstance(self.success, bool):
            raise ValueError("success must be a bool")
        if not isinstance(self.network_effect, bool):
            raise ValueError("network_effect must be a bool")
        if not isinstance(self.reason, str):
            raise ValueError("reason must be a string")
        if not isinstance(self.operation, dict):
            raise ValueError("operation must be a dict")
        if not isinstance(self.extras, dict):
            raise ValueError("extras must be a dict")
        for now in (self.started_at, self.completed_at):
            if now is not None and not isinstance(now, int):
                raise ValueError("timestamps must be ints or None")
        if not isinstance(self.evidence_refs, (tuple, list)):
            raise ValueError("evidence_refs must be a tuple/list")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "execution_id": self.execution_id,
            "recommendation_id": self.recommendation_id,
            "action": self.action,
            "executor_type": self.executor_type,
            "status": self.status,
            "success": self.success,
            "network_effect": self.network_effect,
            "reason": self.reason,
            "operation": dict(self.operation),
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "evidence_refs": [ref.to_dict() for ref in self.evidence_refs],
            "extras": dict(self.extras),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ExecutionOutcome":
        return cls(
            execution_id=data["execution_id"],
            recommendation_id=data["recommendation_id"],
            action=data["action"],
            executor_type=data["executor_type"],
            status=data["status"],
            success=bool(data.get("success")),
            network_effect=bool(data.get("network_effect")),
            reason=data.get("reason") or "",
            operation=dict(data.get("operation") or {}),
            started_at=data.get("started_at"),
            completed_at=data.get("completed_at"),
            evidence_refs=tuple(
                EvidenceRef.from_dict(ref) for ref in data.get("evidence_refs") or []
            ),
            extras=dict(data.get("extras") or {}),
        )


# ---------------------------------------------------------------------------
# executor ABC
# ---------------------------------------------------------------------------


class ProductionExecutor(ABC):
    """Structured-operation executor (XDP / firewall / swanctl adapters)."""

    executor_type = "phase-10"

    @abstractmethod
    def validate(self, request, **context: Any) -> Dict[str, Any]:
        """Return a deterministic validation dict (no side effects)."""

    @abstractmethod
    def execute(self, request, **context: Any) -> ExecutionOutcome:
        """Execute the structured operation (through the injected host)."""

    @abstractmethod
    def cancel(self, request, **context: Any) -> ExecutionOutcome:
        """Cancel; returns a deterministic outcome (no side effects)."""

    def operation_descriptor(self, request, **context: Any) -> Dict[str, Any]:
        """Structured-only description of what WOULD happen (never a command)."""
        raise NotImplementedError