"""Phase 9 — Response & Policy Enforcement domain models.

Converts existing security findings into controlled, auditable RESPONSE
recommendations. Critical safety constraint honored throughout: the layer
NEVER executes a real network operation, never auto-blocks traffic, and never
treats ML anomaly as proof of malicious activity. Every phase-9 action is a
LOGICAL response document (action vocabulary below); actual network mechanics
belong to Phase 10 production adapters.

Design rules enforced here (Phase 9 brief):

* finite, versioned vocabularies: response actions, response statuses,
  approval statuses, roles, priorities — validated at construction time;
* structured decisions only (no free-form text as the only source);
* a recommendation always records the finding/rule it derives from, the
  policy version, authorization/approval requirements, expiry, and evidence;
* deterministic IDs (no UUIDs); timestamps are injected (clock provider);
* every lifecycle step is representable as an append-only audit event.
"""

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Dict, Optional, Tuple

from ..models._base import JsonModel
from ..models.evidence import EvidenceRef
from ..models.identity import CorrelationIdentity
from ..risk.models import SEVERITIES, SEVERITY_CRITICAL, SEVERITY_HIGH

RESPONSE_SCHEMA_VERSION = "v1"
RESPONSE_ENGINE_VERSION = "v1"

# ---------------------------------------------------------------------------
# finite vocabularies
# ---------------------------------------------------------------------------

# Logical response actions (Phase 9 vocabulary). These are DOCUMENTS, not
# network operations; network semantics arrive with Phase 10 executors.
ACTION_NO_ACTION = "NO_ACTION"
ACTION_ALERT_ONLY = "ALERT_ONLY"
ACTION_REQUIRE_REVIEW = "REQUIRE_REVIEW"
ACTION_CAPTURE_EVIDENCE = "CAPTURE_EVIDENCE"
ACTION_ISOLATE_FLOW = "ISOLATE_FLOW"
ACTION_BLOCK_FLOW = "BLOCK_FLOW"
ACTION_TERMINATE_SESSION = "TERMINATE_SESSION"
ACTION_RENEGOTIATE_SESSION = "RENEGOTIATE_SESSION"
ACTION_REQUIRE_RECONFIGURATION = "REQUIRE_RECONFIGURATION"

RESPONSE_ACTIONS = (
    ACTION_NO_ACTION,
    ACTION_ALERT_ONLY,
    ACTION_REQUIRE_REVIEW,
    ACTION_CAPTURE_EVIDENCE,
    ACTION_ISOLATE_FLOW,
    ACTION_BLOCK_FLOW,
    ACTION_TERMINATE_SESSION,
    ACTION_RENEGOTIATE_SESSION,
    ACTION_REQUIRE_RECONFIGURATION,
)


def validate_action(value: Any) -> str:
    if value not in RESPONSE_ACTIONS:
        raise ValueError(
            f"action must be one of {RESPONSE_ACTIONS}, got {value!r}"
        )
    return value


# Response recommendation statuses (the state machine lives in engine.py).
STATUS_NOT_EVALUATED = "NOT_EVALUATED"
STATUS_RECOMMENDED = "RECOMMENDED"
STATUS_PENDING_APPROVAL = "PENDING_APPROVAL"
STATUS_APPROVED = "APPROVED"
STATUS_REJECTED = "REJECTED"
STATUS_AUTHORIZED = "AUTHORIZED"
STATUS_DENIED = "DENIED"
STATUS_DRY_RUN = "DRY_RUN"
STATUS_EXECUTION_REQUESTED = "EXECUTION_REQUESTED"
STATUS_EXECUTING = "EXECUTING"
STATUS_SUCCEEDED = "SUCCEEDED"
STATUS_FAILED = "FAILED"
STATUS_CANCELLED = "CANCELLED"
STATUS_EXPIRED = "EXPIRED"

RESPONSE_STATUSES = (
    STATUS_NOT_EVALUATED,
    STATUS_RECOMMENDED,
    STATUS_PENDING_APPROVAL,
    STATUS_APPROVED,
    STATUS_REJECTED,
    STATUS_AUTHORIZED,
    STATUS_DENIED,
    STATUS_DRY_RUN,
    STATUS_EXECUTION_REQUESTED,
    STATUS_EXECUTING,
    STATUS_SUCCEEDED,
    STATUS_FAILED,
    STATUS_CANCELLED,
    STATUS_EXPIRED,
)

TERMINAL_STATUSES = (
    STATUS_SUCCEEDED,
    STATUS_FAILED,
    STATUS_CANCELLED,
    STATUS_EXPIRED,
    STATUS_REJECTED,
    STATUS_DENIED,
)


# Explicit state machine. Only these transitions are legal; any other change
# raises ResponseStateError (engine.py drives all status changes through
# validate_transition).
RESPONSE_TRANSITIONS: Dict[str, Tuple[str, ...]] = {
    STATUS_NOT_EVALUATED: (STATUS_RECOMMENDED,),
    STATUS_RECOMMENDED: (
        STATUS_PENDING_APPROVAL,
        STATUS_APPROVED,
        STATUS_AUTHORIZED,
        STATUS_DENIED,
        STATUS_EXECUTION_REQUESTED,
        STATUS_CANCELLED,
        STATUS_EXPIRED,
    ),
    STATUS_PENDING_APPROVAL: (
        STATUS_APPROVED,
        STATUS_REJECTED,
        STATUS_DENIED,
        STATUS_CANCELLED,
        STATUS_EXPIRED,
    ),
    STATUS_APPROVED: (
        STATUS_AUTHORIZED,
        STATUS_DENIED,
        STATUS_CANCELLED,
        STATUS_EXPIRED,
    ),
    STATUS_AUTHORIZED: (
        STATUS_EXECUTION_REQUESTED,
        STATUS_DENIED,
        STATUS_CANCELLED,
        STATUS_EXPIRED,
    ),
    STATUS_EXECUTION_REQUESTED: (
        STATUS_DRY_RUN,
        STATUS_EXECUTING,
        STATUS_CANCELLED,
        STATUS_FAILED,
        STATUS_EXPIRED,
    ),
    STATUS_DRY_RUN: (
        STATUS_SUCCEEDED,
        STATUS_FAILED,
        STATUS_CANCELLED,
    ),
    STATUS_EXECUTING: (
        STATUS_DRY_RUN,
        STATUS_SUCCEEDED,
        STATUS_FAILED,
        STATUS_CANCELLED,
    ),
}


def validate_transition(current: str, attempted: str) -> None:
    """Reject any status change not declared in RESPONSE_TRANSITIONS."""
    validate_status(current)
    validate_status(attempted)
    if current in RESPONSE_TRANSITIONS and attempted in RESPONSE_TRANSITIONS[current]:
        return
    raise ResponseStateError(current, attempted)


def validate_status(value: Any) -> str:
    if value not in RESPONSE_STATUSES:
        raise ValueError(
            f"status must be one of {RESPONSE_STATUSES}, got {value!r}"
        )
    return value


# Approval statuses (approval.py orchestrates approvals, not booleans).
APPROVAL_PENDING = "PENDING"
APPROVAL_APPROVED = "APPROVED"
APPROVAL_REJECTED = "REJECTED"
APPROVAL_EXPIRED = "EXPIRED"

APPROVAL_STATUSES = (
    APPROVAL_PENDING,
    APPROVAL_APPROVED,
    APPROVAL_REJECTED,
    APPROVAL_EXPIRED,
)


def validate_approval_status(value: Any) -> str:
    if value not in APPROVAL_STATUSES:
        raise ValueError(
            f"approval status must be one of {APPROVAL_STATUSES}, got {value!r}"
        )
    return value


# Roles (PHASE-9 domain-level authorization; NOT real user authentication).
ROLE_VIEWER = "VIEWER"
ROLE_ANALYST = "ANALYST"
ROLE_SECURITY_OPERATOR = "SECURITY_OPERATOR"
ROLE_SECURITY_ADMIN = "SECURITY_ADMIN"

ROLES = (
    ROLE_VIEWER,
    ROLE_ANALYST,
    ROLE_SECURITY_OPERATOR,
    ROLE_SECURITY_ADMIN,
)

ROLE_RANK = {role: index for index, role in enumerate(ROLES)}


def validate_role(value: Any) -> str:
    if value not in ROLES:
        raise ValueError(f"role must be one of {ROLES}, got {value!r}")
    return value


# Priorities.
PRIORITY_INFORMATIONAL = "INFORMATIONAL"
PRIORITY_LOW = "LOW"
PRIORITY_MEDIUM = "MEDIUM"
PRIORITY_HIGH = "HIGH"
PRIORITY_CRITICAL = "CRITICAL"

PRIORITIES = (
    PRIORITY_INFORMATIONAL,
    PRIORITY_LOW,
    PRIORITY_MEDIUM,
    PRIORITY_HIGH,
    PRIORITY_CRITICAL,
)

PRIORITY_RANK = {name: index for index, name in enumerate(PRIORITIES)}


def validate_priority(value: Any) -> str:
    if value not in PRIORITIES:
        raise ValueError(
            f"priority must be one of {PRIORITIES}, got {value!r}"
        )
    return value


# Audit event types.
EVENT_RECOMMENDATION_CREATED = "RECOMMENDATION_CREATED"
EVENT_AUTHORIZATION_CHECKED = "AUTHORIZATION_CHECKED"
EVENT_APPROVAL_REQUESTED = "APPROVAL_REQUESTED"
EVENT_APPROVED = "APPROVED"
EVENT_REJECTED = "REJECTED"
EVENT_EXECUTION_REQUESTED = "EXECUTION_REQUESTED"
EVENT_DRY_RUN_EXECUTED = "DRY_RUN_EXECUTED"
EVENT_EXECUTION_SUCCEEDED = "EXECUTION_SUCCEEDED"
EVENT_EXECUTION_FAILED = "EXECUTION_FAILED"
EVENT_CANCELLED = "CANCELLED"
EVENT_EXPIRED = "EXPIRED"
EVENT_STATUS_CHANGED = "STATUS_CHANGED"

RESPONSE_EVENT_TYPES = (
    EVENT_RECOMMENDATION_CREATED,
    EVENT_AUTHORIZATION_CHECKED,
    EVENT_APPROVAL_REQUESTED,
    EVENT_APPROVED,
    EVENT_REJECTED,
    EVENT_EXECUTION_REQUESTED,
    EVENT_DRY_RUN_EXECUTED,
    EVENT_EXECUTION_SUCCEEDED,
    EVENT_EXECUTION_FAILED,
    EVENT_CANCELLED,
    EVENT_EXPIRED,
    EVENT_STATUS_CHANGED,
)


def validate_event_type(value: Any) -> str:
    if value not in RESPONSE_EVENT_TYPES:
        raise ValueError(
            f"event_type must be one of {RESPONSE_EVENT_TYPES}, got {value!r}"
        )
    return value


# ---------------------------------------------------------------------------
# structured domain errors
# ---------------------------------------------------------------------------


class ResponseDomainError(Exception):
    """Base structured error for the Phase-9 layer."""

    code = "response_domain_error"

    def __init__(self, message: str, *, details: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(message)
        self.details = dict(details or {})

    def payload(self) -> Dict[str, Any]:
        return {"error": {"code": self.code, "detail": str(self), **self.details}}


class ResponseStateError(ResponseDomainError):
    """Invalid status transition (the state machine rejects arbitrary changes)."""

    code = "invalid_transition"

    def __init__(self, current: str, attempted: str):
        super().__init__(
            f"invalid status transition {current} -> {attempted}",
            details={"current_status": current, "attempted_status": attempted},
        )


class AuthorizationError(ResponseDomainError):
    code = "authorization_denied"


class ApprovalError(ResponseDomainError):
    code = "approval_error"


class ExpiredError(ResponseDomainError):
    code = "expired"


class ExecutorError(ResponseDomainError):
    code = "executor_error"


# ---------------------------------------------------------------------------
# model helpers (shared, deterministic)
# ---------------------------------------------------------------------------


def _evidence_tuple(value: Any, name: str) -> Tuple[EvidenceRef, ...]:
    if not isinstance(value, (tuple, list)):
        raise ValueError(f"{name} must be a tuple/list of EvidenceRef")
    result = []
    for item in value:
        if isinstance(item, EvidenceRef):
            result.append(item)
        elif isinstance(item, dict):
            result.append(EvidenceRef.from_dict(item))
        else:
            raise ValueError(f"{name} must contain EvidenceRef objects")
    return tuple(result)


def expiring_copy(now_ns: Optional[int], base_ns: int, default_expiry_ns: int) -> Optional[int]:
    """Deterministic expiry: None clock -> no expiry; else now + window."""
    if now_ns is None:
        return None
    if default_expiry_ns is None or default_expiry_ns <= 0:
        return None
    return now_ns + default_expiry_ns


# ---------------------------------------------------------------------------
# models
# ---------------------------------------------------------------------------


@dataclass
class ResponseRecommendation(JsonModel):
    """One controlled response recommendation for ONE finding.

    Mutable ``status`` only: the engine drives status through the explicit
    transition validator. All decision-relevant fields (action, priority,
    requirements, expiry) are fixed at planning time by the response policy.
    """

    recommendation_id: str
    assessment_identity: CorrelationIdentity
    finding_id: str
    rule_id: str
    action: str
    priority: str
    reason: str
    rationale: str
    severity: str
    risk_score: int
    policy_version: str
    authorization_required: bool
    approval_required: bool
    required_roles: Tuple[str, ...] = (ROLE_ANALYST,)
    expires_at: Optional[int] = None
    evidence_refs: Tuple[EvidenceRef, ...] = field(default_factory=tuple)
    limitations: Tuple[str, ...] = field(default_factory=tuple)
    status: str = STATUS_RECOMMENDED
    provenance: str = "RESPONSE_POLICY"

    def __post_init__(self) -> None:
        if not isinstance(self.recommendation_id, str) or not self.recommendation_id.strip():
            raise ValueError("recommendation_id must be a non-empty string")
        if not isinstance(self.assessment_identity, CorrelationIdentity):
            raise ValueError("assessment_identity must be a CorrelationIdentity")
        for name in ("finding_id", "rule_id", "reason", "rationale",
                     "policy_version"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{name} must be a non-empty string")
        validate_action(self.action)
        validate_priority(self.priority)
        validate_status(self.status)
        if self.severity not in SEVERITIES:
            raise ValueError(f"severity must be one of {SEVERITIES}")
        if not isinstance(self.risk_score, int) or not (0 <= self.risk_score <= 100):
            raise ValueError("risk_score must be an int in [0, 100]")
        if not isinstance(self.authorization_required, bool):
            raise ValueError("authorization_required must be a bool")
        if not isinstance(self.approval_required, bool):
            raise ValueError("approval_required must be a bool")
        for role in self.required_roles:
            validate_role(role)
        if self.expires_at is not None:
            if not isinstance(self.expires_at, int) or self.expires_at < 0:
                raise ValueError("expires_at must be a non-negative int or None")
        if not isinstance(self.limitations, (tuple, list)):
            raise ValueError("limitations must be a tuple/list")
        if self.provenance not in (
            "RESPONSE_POLICY", "RESPONSE_ML", "RESPONSE_EVIDENCE_GAP", "RESPONSE_DEFAULT",
        ):
            raise ValueError(f"unknown provenance {self.provenance!r}")

    def is_expired(self, now_ns: int) -> bool:
        return self.expires_at is not None and now_ns > self.expires_at

    def to_dict(self) -> Dict[str, Any]:
        return {
            "recommendation_id": self.recommendation_id,
            "assessment_identity": self.assessment_identity.to_dict(),
            "finding_id": self.finding_id,
            "rule_id": self.rule_id,
            "action": self.action,
            "priority": self.priority,
            "reason": self.reason,
            "rationale": self.rationale,
            "severity": self.severity,
            "risk_score": self.risk_score,
            "policy_version": self.policy_version,
            "authorization_required": self.authorization_required,
            "approval_required": self.approval_required,
            "required_roles": list(self.required_roles),
            "expires_at": self.expires_at,
            "evidence_refs": [ev.to_dict() for ev in self.evidence_refs],
            "limitations": list(self.limitations),
            "status": self.status,
            "provenance": self.provenance,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ResponseRecommendation":
        return cls(
            recommendation_id=data["recommendation_id"],
            assessment_identity=CorrelationIdentity.from_dict(data["assessment_identity"]),
            finding_id=data["finding_id"],
            rule_id=data["rule_id"],
            action=data["action"],
            priority=data["priority"],
            reason=data["reason"],
            rationale=data["rationale"],
            severity=data["severity"],
            risk_score=data["risk_score"],
            policy_version=data["policy_version"],
            authorization_required=bool(data.get("authorization_required", False)),
            approval_required=bool(data.get("approval_required", False)),
            required_roles=tuple(data.get("required_roles") or (ROLE_ANALYST,)),
            expires_at=data.get("expires_at"),
            evidence_refs=_evidence_tuple(data.get("evidence_refs") or [], "evidence_refs"),
            limitations=tuple(data.get("limitations") or ()),
            status=data.get("status", STATUS_RECOMMENDED),
            provenance=data.get("provenance", "RESPONSE_POLICY"),
        )


@dataclass(frozen=True)
class ResponsePlan(JsonModel):
    """Deterministic output of the planner (a *plan* never executes anything)."""

    assessment_identity: CorrelationIdentity
    policy_version: str
    recommendations: Tuple[ResponseRecommendation, ...] = field(default_factory=tuple)
    requires_approval: bool = False
    requires_authorization: bool = False
    generated_deterministically: bool = True
    limitations: Tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        if not isinstance(self.assessment_identity, CorrelationIdentity):
            raise ValueError("assessment_identity must be a CorrelationIdentity")
        if not isinstance(self.policy_version, str) or not self.policy_version.strip():
            raise ValueError("policy_version must be a non-empty string")
        if not isinstance(self.recommendations, (tuple, list)):
            raise ValueError("recommendations must be a tuple/list")
        for rec in self.recommendations:
            if not isinstance(rec, ResponseRecommendation):
                raise ValueError("recommendations must contain ResponseRecommendation")
        if not isinstance(self.generated_deterministically, bool):
            raise ValueError("generated_deterministically must be a bool")
        if not isinstance(self.limitations, (tuple, list)):
            raise ValueError("limitations must be a tuple/list")

    def by_id(self) -> Dict[str, ResponseRecommendation]:
        return {rec.recommendation_id: rec for rec in self.recommendations}

    def high_impact(self) -> Tuple[ResponseRecommendation, ...]:
        return tuple(
            rec for rec in self.recommendations
            if rec.action in (
                ACTION_ISOLATE_FLOW, ACTION_BLOCK_FLOW,
                ACTION_TERMINATE_SESSION, ACTION_RENEGOTIATE_SESSION,
            )
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "assessment_identity": self.assessment_identity.to_dict(),
            "policy_version": self.policy_version,
            "recommendations": [rec.to_dict() for rec in self.recommendations],
            "requires_approval": self.requires_approval,
            "requires_authorization": self.requires_authorization,
            "generated_deterministically": self.generated_deterministically,
            "limitations": list(self.limitations),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ResponsePlan":
        return cls(
            assessment_identity=CorrelationIdentity.from_dict(data["assessment_identity"]),
            policy_version=data["policy_version"],
            recommendations=tuple(
                ResponseRecommendation.from_dict(rec)
                for rec in data.get("recommendations") or []
            ),
            requires_approval=bool(data.get("requires_approval", False)),
            requires_authorization=bool(data.get("requires_authorization", False)),
            generated_deterministically=bool(data.get("generated_deterministically", True)),
            limitations=tuple(data.get("limitations") or ()),
        )


@dataclass
class ApprovalRequest(JsonModel):
    """Explicit analyst approval request (never a bare boolean)."""

    approval_id: str
    recommendation_id: str
    requested_by: str
    requested_at: Optional[int]
    reason: str
    required_role: str
    status: str = APPROVAL_PENDING
    approved_by: Optional[str] = None
    approved_at: Optional[int] = None
    rejection_reason: Optional[str] = None
    expires_at: Optional[int] = None

    def __post_init__(self) -> None:
        if not isinstance(self.approval_id, str) or not self.approval_id.strip():
            raise ValueError("approval_id must be a non-empty string")
        if not isinstance(self.recommendation_id, str) or not self.recommendation_id.strip():
            raise ValueError("recommendation_id must be a non-empty string")
        if not isinstance(self.requested_by, str) or not self.requested_by.strip():
            raise ValueError("requested_by must be a non-empty string")
        if self.requested_at is not None and (
            not isinstance(self.requested_at, int) or self.requested_at < 0
        ):
            raise ValueError("requested_at must be a non-negative int or None")
        if not isinstance(self.reason, str):
            raise ValueError("reason must be a string")
        validate_role(self.required_role)
        validate_approval_status(self.status)
        if self.approved_by is not None and not isinstance(self.approved_by, str):
            raise ValueError("approved_by must be a string or None")
        if self.rejection_reason is not None and not isinstance(self.rejection_reason, str):
            raise ValueError("rejection_reason must be a string or None")
        if self.expires_at is not None and (
            not isinstance(self.expires_at, int) or self.expires_at < 0
        ):
            raise ValueError("expires_at must be a non-negative int or None")

    def is_expired(self, now_ns: int) -> bool:
        return self.expires_at is not None and now_ns > self.expires_at

    def to_dict(self) -> Dict[str, Any]:
        return {
            "approval_id": self.approval_id,
            "recommendation_id": self.recommendation_id,
            "requested_by": self.requested_by,
            "requested_at": self.requested_at,
            "reason": self.reason,
            "required_role": self.required_role,
            "status": self.status,
            "approved_by": self.approved_by,
            "approved_at": self.approved_at,
            "rejection_reason": self.rejection_reason,
            "expires_at": self.expires_at,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ApprovalRequest":
        return cls(
            approval_id=data["approval_id"],
            recommendation_id=data["recommendation_id"],
            requested_by=data["requested_by"],
            requested_at=data.get("requested_at"),
            reason=data.get("reason") or "",
            required_role=data["required_role"],
            status=data.get("status", APPROVAL_PENDING),
            approved_by=data.get("approved_by"),
            approved_at=data.get("approved_at"),
            rejection_reason=data.get("rejection_reason"),
            expires_at=data.get("expires_at"),
        )


@dataclass(frozen=True)
class AuthorizationContext(JsonModel):
    """Domain-level authorization identity (Phase 9; not user authentication)."""

    principal_id: str
    roles: Tuple[str, ...]
    scope: Optional[str] = None
    allowed_actions: Tuple[str, ...] = field(default_factory=tuple)
    reason: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.principal_id, str) or not self.principal_id.strip():
            raise ValueError("principal_id must be a non-empty string")
        if not isinstance(self.roles, (tuple, list)) or not self.roles:
            raise ValueError("roles must be a non-empty tuple/list")
        for role in self.roles:
            validate_role(role)
        if self.allowed_actions is not None:
            for action in self.allowed_actions:
                validate_action(action)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "principal_id": self.principal_id,
            "roles": list(self.roles),
            "scope": self.scope,
            "allowed_actions": list(self.allowed_actions),
            "reason": self.reason,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AuthorizationContext":
        return cls(
            principal_id=data["principal_id"],
            roles=tuple(data["roles"]),
            scope=data.get("scope"),
            allowed_actions=tuple(data.get("allowed_actions") or ()),
            reason=data.get("reason") or "",
        )


@dataclass(frozen=True)
class AuthorizationDecision(JsonModel):
    """Explicit result of an authorization check (never implicit)."""

    principal_id: str
    action: str
    authorized: bool
    required_roles: Tuple[str, ...]
    granted_roles: Tuple[str, ...]
    reason: str
    policy_version: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.principal_id, str) or not self.principal_id.strip():
            raise ValueError("principal_id must be a non-empty string")
        validate_action(self.action)
        if not isinstance(self.authorized, bool):
            raise ValueError("authorized must be a bool")
        for role in self.required_roles + self.granted_roles:
            validate_role(role)
        if not isinstance(self.reason, str):
            raise ValueError("reason must be a string")
        if self.policy_version is not None and not isinstance(self.policy_version, str):
            raise ValueError("policy_version must be a string")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "principal_id": self.principal_id,
            "action": self.action,
            "authorized": self.authorized,
            "required_roles": list(self.required_roles),
            "granted_roles": list(self.granted_roles),
            "reason": self.reason,
            "policy_version": self.policy_version,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AuthorizationDecision":
        return cls(
            principal_id=data["principal_id"],
            action=data["action"],
            authorized=bool(data["authorized"]),
            required_roles=tuple(data.get("required_roles") or ()),
            granted_roles=tuple(data.get("granted_roles") or ()),
            reason=data.get("reason") or "",
            policy_version=data.get("policy_version") or "",
        )


@dataclass(frozen=True)
class ExecutionRequest(JsonModel):
    """Controlled execution request (dry-run in Phase 9)."""

    execution_id: str
    recommendation_id: str
    action: str
    executor_type: str
    requested_by: str
    issued_at: Optional[int] = None

    def __post_init__(self) -> None:
        if not isinstance(self.execution_id, str) or not self.execution_id.strip():
            raise ValueError("execution_id must be a non-empty string")
        if not isinstance(self.recommendation_id, str) or not self.recommendation_id.strip():
            raise ValueError("recommendation_id must be a non-empty string")
        validate_action(self.action)
        if not isinstance(self.executor_type, str) or not self.executor_type.strip():
            raise ValueError("executor_type must be a non-empty string")
        if not isinstance(self.requested_by, str) or not self.requested_by.strip():
            raise ValueError("requested_by must be a non-empty string")
        if self.issued_at is not None and self.issued_at < 0:
            raise ValueError("issued_at must be a non-negative int or None")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "execution_id": self.execution_id,
            "recommendation_id": self.recommendation_id,
            "action": self.action,
            "executor_type": self.executor_type,
            "requested_by": self.requested_by,
            "issued_at": self.issued_at,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ExecutionRequest":
        return cls(
            execution_id=data["execution_id"],
            recommendation_id=data["recommendation_id"],
            action=data["action"],
            executor_type=data["executor_type"],
            requested_by=data["requested_by"],
            issued_at=data.get("issued_at"),
        )


@dataclass(frozen=True)
class ExecutionResult(JsonModel):
    """Outcome of one execution attempt.

    Phase 9: ``executor_type == "dry-run"`` and ``network_effect == False``
    ALWAYS. The result explicitly states that no network operation occurred.
    """

    execution_id: str
    recommendation_id: str
    action: str
    status: str
    executor_type: str
    started_at: Optional[int] = None
    completed_at: Optional[int] = None
    success: bool = False
    message: str = ""
    network_effect: bool = False
    evidence_refs: Tuple[EvidenceRef, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        if not isinstance(self.execution_id, str) or not self.execution_id.strip():
            raise ValueError("execution_id must be a non-empty string")
        if not isinstance(self.recommendation_id, str) or not self.recommendation_id.strip():
            raise ValueError("recommendation_id must be a non-empty string")
        validate_action(self.action)
        validate_status(self.status)
        if not isinstance(self.executor_type, str) or not self.executor_type.strip():
            raise ValueError("executor_type must be a non-empty string")
        if not isinstance(self.success, bool):
            raise ValueError("success must be a bool")
        if not isinstance(self.message, str):
            raise ValueError("message must be a string")
        if not isinstance(self.network_effect, bool):
            raise ValueError("network_effect must be a bool")
        if not isinstance(self.evidence_refs, (tuple, list)):
            raise ValueError("evidence_refs must be a tuple/list")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "execution_id": self.execution_id,
            "recommendation_id": self.recommendation_id,
            "action": self.action,
            "status": self.status,
            "executor_type": self.executor_type,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "success": self.success,
            "message": self.message,
            "network_effect": self.network_effect,
            "evidence_refs": [ev.to_dict() for ev in self.evidence_refs],
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ExecutionResult":
        return cls(
            execution_id=data["execution_id"],
            recommendation_id=data["recommendation_id"],
            action=data["action"],
            status=data["status"],
            executor_type=data["executor_type"],
            started_at=data.get("started_at"),
            completed_at=data.get("completed_at"),
            success=bool(data.get("success")),
            message=data.get("message") or "",
            network_effect=bool(data.get("network_effect", False)),
            evidence_refs=_evidence_tuple(data.get("evidence_refs") or [], "evidence_refs"),
        )


@dataclass(frozen=True)
class ResponseAuditEvent(JsonModel):
    """One append-only audit event in the response lifecycle chain.

    ``previous_hash`` / ``event_hash`` form a deterministic SHA-256 chain
    (audit.py). The hashes are computed over the canonical JSON payload that
    EXCLUDES the two hash fields; ``event_hash`` covers ``previous_hash``.
    """

    event_id: str
    timestamp: Optional[int]
    assessment_identity: CorrelationIdentity
    recommendation_id: Optional[str]
    approval_id: Optional[str]
    principal: str
    event_type: str
    action: Optional[str]
    previous_status: Optional[str]
    new_status: Optional[str]
    reason: str
    policy_version: str
    evidence_refs: Tuple[EvidenceRef, ...] = field(default_factory=tuple)
    previous_hash: str = ""
    event_hash: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.event_id, str) or not self.event_id.strip():
            raise ValueError("event_id must be a non-empty string")
        if self.timestamp is not None and not isinstance(self.timestamp, int):
            raise ValueError("timestamp must be an int or None")
        if not isinstance(self.assessment_identity, CorrelationIdentity):
            raise ValueError("assessment_identity must be a CorrelationIdentity")
        if self.recommendation_id is not None and not isinstance(self.recommendation_id, str):
            raise ValueError("recommendation_id must be a string or None")
        if self.approval_id is not None and not isinstance(self.approval_id, str):
            raise ValueError("approval_id must be a string or None")
        if not isinstance(self.principal, str):
            raise ValueError("principal must be a string")
        validate_event_type(self.event_type)
        if self.action is not None:
            validate_action(self.action)
        if self.previous_status is not None:
            validate_status(self.previous_status)
        if self.new_status is not None:
            validate_status(self.new_status)
        if not isinstance(self.reason, str):
            raise ValueError("reason must be a string")
        if self.policy_version is not None and not isinstance(self.policy_version, str):
            raise ValueError("policy_version must be a string")
        if not isinstance(self.evidence_refs, (tuple, list)):
            raise ValueError("evidence_refs must be a tuple/list")
        if not self.event_id.startswith("EVT-"):
            raise ValueError("event_id must start with EVT-")

    def base_dict(self) -> Dict[str, Any]:
        """Canonical payload WITHOUT hash fields (used to compute the chain)."""
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp,
            "assessment_identity": self.assessment_identity.to_dict(),
            "recommendation_id": self.recommendation_id,
            "approval_id": self.approval_id,
            "principal": self.principal,
            "event_type": self.event_type,
            "action": self.action,
            "previous_status": self.previous_status,
            "new_status": self.new_status,
            "reason": self.reason,
            "policy_version": self.policy_version,
            "evidence_refs": [ev.to_dict() for ev in self.evidence_refs],
        }

    def to_dict(self) -> Dict[str, Any]:
        payload = self.base_dict()
        payload["previous_hash"] = self.previous_hash
        payload["event_hash"] = self.event_hash
        return payload

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ResponseAuditEvent":
        return cls(
            event_id=data["event_id"],
            timestamp=data.get("timestamp"),
            assessment_identity=CorrelationIdentity.from_dict(data["assessment_identity"]),
            recommendation_id=data.get("recommendation_id"),
            approval_id=data.get("approval_id"),
            principal=data.get("principal") or "",
            event_type=data["event_type"],
            action=data.get("action"),
            previous_status=data.get("previous_status"),
            new_status=data.get("new_status"),
            reason=data.get("reason") or "",
            policy_version=data.get("policy_version") or "",
            evidence_refs=_evidence_tuple(data.get("evidence_refs") or [], "evidence_refs"),
            previous_hash=data.get("previous_hash") or "",
            event_hash=data.get("event_hash") or "",
        )


def _blank_hash() -> str:
    return "0" * 64


def compute_event_hash(base_payload: Dict[str, Any], previous_hash: str) -> str:
    """Deterministic SHA-256 chain link (hex string).

    ``base_payload`` must be the event's canonical dict WITHOUT the hash keys
    (see ``ResponseAuditEvent.base_dict``); ``previous_hash`` is the previous
    link's ``event_hash`` (``0*64`` for the genesis event).
    """
    canonical = json.dumps(base_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(canonical + b"|" + previous_hash.encode("ascii")).hexdigest()


# Convenience: actions that are always considered high-impact (never executed
# in this layer and never auto-recommended for ML/UNKNOWN inputs).
HIGH_IMPACT_ACTIONS = (
    ACTION_ISOLATE_FLOW,
    ACTION_BLOCK_FLOW,
    ACTION_TERMINATE_SESSION,
    ACTION_RENEGOTIATE_SESSION,
    ACTION_REQUIRE_RECONFIGURATION,
)


def is_high_impact(action: str) -> bool:
    return action in HIGH_IMPACT_ACTIONS