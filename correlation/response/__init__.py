"""Phase 9 — Response & Policy Enforcement Layer.

Deterministic, controlled, auditable response recommendations built from the
Phase-6 risk assessment (plus optional Phase-5 XAI / Phase-4 correlation / ML).
Safety: dry-run only, no real network operations, no auto-blocking, approval
for high-impact actions, UNKNOWN becomes review/capture, NOT_APPLICABLE
becomes no response, and every lifecycle step is an append-only audited event.

Modules:
    models          finite vocabularies + response domain models + hash helper
    policy          versioned response policy (single source of truth for gates)
    rules           RESPONSE_RULE_TRACEABILITY registry (finding rule -> RESP-*)
    authorization   domain roles -> capability checks -> AuthorizationDecision
    approval        analyst approval gate (PENDING/APPROVED/REJECTED/EXPIRED)
    audit           append-only audit ledger with SHA-256 chain
    executor        controlled executor abstraction (dry-run only in Phase 9)
    planner         deterministic ResponsePlan from consumed Phase 4-7 outputs
    engine          state machine + lifecycle orchestration

All timestamps are injected (clock provider); nothing depends on
``datetime.now()`` so every output is reproducible.
"""

from . import (  # noqa: F401
    approval,
    audit,
    authorization,
    executor,
    models,
    planner,
    policy,
    rules,
)
from .engine import (  # noqa: F401
    ResponseEngine,
    demo_clock,
    plain_clock,
)
from .models import (  # noqa: F401
    ACTION_ALERT_ONLY,
    ACTION_BLOCK_FLOW,
    ACTION_CAPTURE_EVIDENCE,
    ACTION_ISOLATE_FLOW,
    ACTION_NO_ACTION,
    ACTION_RENEGOTIATE_SESSION,
    ACTION_REQUIRE_RECONFIGURATION,
    ACTION_REQUIRE_REVIEW,
    ACTION_TERMINATE_SESSION,
    APPROVAL_APPROVED,
    APPROVAL_EXPIRED,
    APPROVAL_PENDING,
    APPROVAL_REJECTED,
    APPROVAL_STATUSES,
    ApprovalError,
    ApprovalRequest,
    AuthorizationContext,
    AuthorizationDecision,
    ExecutionRequest,
    ExecutionResult,
    ExecutorError,
    ExpiredError,
    HIGH_IMPACT_ACTIONS,
    PRIORITIES,
    RESPONSE_ACTIONS,
    RESPONSE_EVENT_TYPES,
    RESPONSE_SCHEMA_VERSION,
    RESPONSE_STATUSES,
    ROLE_ANALYST,
    ROLE_SECURITY_ADMIN,
    ROLE_SECURITY_OPERATOR,
    ROLE_VIEWER,
    ROLES,
    ResponseAuditEvent,
    ResponseDomainError,
    ResponsePlan,
    ResponseRecommendation,
    ResponseStateError,
    STATUS_APPROVED,
    STATUS_AUTHORIZED,
    STATUS_CANCELLED,
    STATUS_DENIED,
    STATUS_DRY_RUN,
    STATUS_EXECUTION_REQUESTED,
    STATUS_EXECUTING,
    STATUS_EXPIRED,
    STATUS_FAILED,
    STATUS_NOT_EVALUATED,
    STATUS_PENDING_APPROVAL,
    STATUS_RECOMMENDED,
    STATUS_REJECTED,
    STATUS_SUCCEEDED,
    compute_event_hash,
    is_high_impact,
)
from .policy import (  # noqa: F401
    DEFAULT_EXPIRY_NS,
    DEFAULT_RESPONSE_POLICY_VERSION,
    ResponsePolicy,
)
from .rules import (  # noqa: F401
    ALL_RESPONSE_RULES,
    RESPONSE_RULE_TRACEABILITY,
    traceability_for,
)

__all__ = [
    "ACTION_ALERT_ONLY",
    "ACTION_BLOCK_FLOW",
    "ACTION_CAPTURE_EVIDENCE",
    "ACTION_ISOLATE_FLOW",
    "ACTION_NO_ACTION",
    "ACTION_RENEGOTIATE_SESSION",
    "ACTION_REQUIRE_RECONFIGURATION",
    "ACTION_REQUIRE_REVIEW",
    "ACTION_TERMINATE_SESSION",
    "ALL_RESPONSE_RULES",
    "APPROVAL_APPROVED",
    "APPROVAL_EXPIRED",
    "APPROVAL_PENDING",
    "APPROVAL_REJECTED",
    "APPROVAL_STATUSES",
    "ApprovalError",
    "ApprovalRequest",
    "AuthorizationContext",
    "AuthorizationDecision",
    "DEFAULT_EXPIRY_NS",
    "DEFAULT_RESPONSE_POLICY_VERSION",
    "ExecutionRequest",
    "ExecutionResult",
    "ExecutorError",
    "ExpiredError",
    "HIGH_IMPACT_ACTIONS",
    "PRIORITIES",
    "RESPONSE_ACTIONS",
    "RESPONSE_EVENT_TYPES",
    "RESPONSE_RULE_TRACEABILITY",
    "RESPONSE_SCHEMA_VERSION",
    "RESPONSE_STATUSES",
    "ROLE_ANALYST",
    "ROLE_SECURITY_ADMIN",
    "ROLE_SECURITY_OPERATOR",
    "ROLE_VIEWER",
    "ROLES",
    "ResponseAuditEvent",
    "ResponseDomainError",
    "ResponseEngine",
    "ResponsePlan",
    "ResponsePolicy",
    "ResponseRecommendation",
    "ResponseStateError",
    "STATUS_APPROVED",
    "STATUS_AUTHORIZED",
    "STATUS_CANCELLED",
    "STATUS_DENIED",
    "STATUS_DRY_RUN",
    "STATUS_EXECUTION_REQUESTED",
    "STATUS_EXECUTING",
    "STATUS_EXPIRED",
    "STATUS_FAILED",
    "STATUS_NOT_EVALUATED",
    "STATUS_PENDING_APPROVAL",
    "STATUS_RECOMMENDED",
    "STATUS_REJECTED",
    "STATUS_SUCCEEDED",
    "compute_event_hash",
    "demo_clock",
    "is_high_impact",
    "plain_clock",
    "traceability_for",
]