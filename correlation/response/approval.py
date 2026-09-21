"""Phase 9 — analyst approval gate.

An explicit ``ApprovalRequest`` (statuses PENDING / APPROVED / REJECTED /
EXPIRED) — never a bare boolean. An action proceeds to execution only when all
of: policy allows the action, authorization permits it, AND (when approval is
required) the approval is APPROVED and not expired.

Safe flows enforced here:

* requesting approval requires the recommendation to be in a state that still
  allows it (RECOMMENDED) — a terminal or already-approved recommendation
  cannot be re-gated;
* approving requires the approving principal to be granted a compatible role
  for the recommendation's action (role check, never the UI alone);
* rejecting records a rejection reason;
* expiry uses the injected clock.
"""

from typing import Any, Dict, Optional, Sequence

from .authorization import role_can
from .models import (
    APPROVAL_APPROVED,
    APPROVAL_EXPIRED,
    APPROVAL_PENDING,
    APPROVAL_REJECTED,
    ApprovalError,
    ApprovalRequest,
    ROLE_RANK,
    ResponseRecommendation,
    STATUS_PENDING_APPROVAL,
    STATUS_RECOMMENDED,
)
from .policy import ResponsePolicy


def approval_id_for(recommendation_id: str) -> str:
    return f"APR-{recommendation_id}"


def request_approval(
    recommendation: ResponseRecommendation,
    commanded_by: str,
    reason: str,
    *,
    now_ns: Optional[int],
    policy: ResponsePolicy,
) -> ApprovalRequest:
    """Create the PENDING approval request for a recommendation.

    Checks status discipline (must be RECOMMENDED and approval must actually be
    required). Raises ``ApprovalError`` otherwise.
    """
    if recommendation.status != STATUS_RECOMMENDED:
        raise ApprovalError(
            f"recommendation {recommendation.recommendation_id} is "
            f"{recommendation.status}; approval may only be requested while "
            f"RECOMMENDED"
        )
    if not recommendation.approval_required:
        raise ApprovalError(
            f"recommendation {recommendation.recommendation_id} does not "
            f"require approval under {policy.policy_version}"
        )
    if not isinstance(commanded_by, str) or not commanded_by.strip():
        raise ValueError("commanded_by must be a non-empty string")
    requirements = policy.requirements_for(recommendation.rule_id, recommendation.action)
    required_roles = tuple(
        requirements.get("required_roles") or ("ANALYST",)
    )
    required_role = min(
        required_roles,
        key=lambda role: ROLE_RANK[role],
    )
    expires_at = None
    if recommendation.expires_at is not None and now_ns is not None:
        expires_at = recommendation.expires_at
    return ApprovalRequest(
        approval_id=approval_id_for(recommendation.recommendation_id),
        recommendation_id=recommendation.recommendation_id,
        requested_by=commanded_by,
        requested_at=now_ns,
        reason=reason or (
            f"Requesting {recommendation.action} approval for "
            f"{recommendation.finding_id} under {policy.policy_version}"
        ),
        required_role=required_role,
        status=APPROVAL_PENDING,
        expires_at=expires_at,
    )


def _check_expired(approval: ApprovalRequest, now_ns: Optional[int]) -> None:
    if now_ns is not None and approval.expires_at is not None and now_ns > approval.expires_at:
        raise ApprovalError(
            f"approval {approval.approval_id} has expired (now={now_ns}, "
            f"expires_at={approval.expires_at})"
        )


def approve(
    approval: ApprovalRequest,
    recommendation: ResponseRecommendation,
    commanded_by: str,
    *,
    roles: Sequence[str],
    now_ns: Optional[int],
    policy: ResponsePolicy,
) -> ApprovalRequest:
    """Approve an approval request (role + status + expiry checked)."""
    roles = tuple(roles)
    _check_expired(approval, now_ns)
    if approval.status != APPROVAL_PENDING:
        raise ApprovalError(
            f"approval {approval.approval_id} is {approval.status}; only "
            f"PENDING approvals can be approved"
        )
    if not recommendation.approval_required:
        raise ApprovalError(
            f"recommendation {recommendation.recommendation_id} does not "
            f"require approval"
        )
    if not any(role_can(role, recommendation.action) for role in roles):
        raise ApprovalError(
            f"principal {commanded_by!r} holdings {list(roles)} cannot approve "
            f"action {recommendation.action}; a {recommendation.required_roles} "
            f"role is required"
        )
    approval.status = APPROVAL_APPROVED
    approval.approved_by = commanded_by
    approval.approved_at = now_ns
    return approval


def reject(
    approval: ApprovalRequest,
    recommendation: ResponseRecommendation,
    commanded_by: str,
    *,
    rejection_reason: str,
    now_ns: Optional[int],
) -> ApprovalRequest:
    """Reject an approval request (only from PENDING)."""
    del commanded_by  # the caller is recorded by the engine in the audit event
    _check_expired(approval, now_ns)
    if approval.status != APPROVAL_PENDING:
        raise ApprovalError(
            f"approval {approval.approval_id} is {approval.status}; only "
            f"PENDING approvals can be rejected"
        )
    if not isinstance(rejection_reason, str) or not rejection_reason.strip():
        raise ValueError("rejection_reason must be a non-empty string")
    approval.status = APPROVAL_REJECTED
    approval.rejection_reason = rejection_reason
    return approval


def expire_approval(
    approval: ApprovalRequest,
    now_ns: int,
) -> ApprovalRequest:
    """Transition a PENDING approval to EXPIRED past its window."""
    if approval.status != APPROVAL_PENDING:
        return approval
    if approval.expires_at is not None and now_ns > approval.expires_at:
        approval.status = APPROVAL_EXPIRED
    return approval


def approval_disposition(approval: Optional[ApprovalRequest]) -> str:
    """Human label for the dashboard approval status."""
    if approval is None:
        return "NOT REQUESTED"
    return approval.status