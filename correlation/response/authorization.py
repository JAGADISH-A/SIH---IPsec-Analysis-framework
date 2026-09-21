"""Phase 9 — authorization model.

Domain-level authorization: a principal (whose role is supplied in the
``AuthorizationContext``) is checked against the ``ResponsePolicy`` gates for a
recommended action. This is NOT real user authentication — that belongs to the
hosting platform. The final decision must satisfy BOTH the policy AND the
authorization context (never the UI/role alone).

Role capability table (default):

    VIEWER                 view recommendations only (no approval / execution)
    ANALYST                approve review / evidence actions
    SECURITY_OPERATOR      approve controlled response actions
    SECURITY_ADMIN         approve high-impact actions

A decision is ``authorized`` only when the principal holds at least one role
that (a) is listed in the policy's ``required_roles`` for the action and
(b) outranks the action's minimum role. Everything is explicit and recorded in
the ``AuthorizationDecision`` document.
"""

from typing import Any, Dict, Sequence, Tuple

from .models import (
    ACTION_ALERT_ONLY,
    ACTION_BLOCK_FLOW,
    ACTION_CAPTURE_EVIDENCE,
    ACTION_ISOLATE_FLOW,
    ACTION_NO_ACTION,
    ACTION_RENEGOTIATE_SESSION,
    ACTION_REQUIRE_RECONFIGURATION,
    ACTION_REQUIRE_REVIEW,
    ACTION_TERMINATE_SESSION,
    AuthorizationContext,
    AuthorizationDecision,
    ROLE_ANALYST,
    ROLE_RANK,
    ROLE_SECURITY_ADMIN,
    ROLE_SECURITY_OPERATOR,
    ROLE_VIEWER,
    ROLES,
    is_high_impact,
    validate_action,
)
from .policy import ResponsePolicy

# Minimum role required per action (analyst-level review/evidence actions are
# executable by ANALYST; controlled / high-impact actions need an operator or
# administrator).
DEFAULT_MIN_ROLE_BY_ACTION: Dict[str, str] = {
    ACTION_NO_ACTION: ROLE_VIEWER,
    ACTION_ALERT_ONLY: ROLE_ANALYST,
    ACTION_REQUIRE_REVIEW: ROLE_ANALYST,
    ACTION_CAPTURE_EVIDENCE: ROLE_ANALYST,
    ACTION_ISOLATE_FLOW: ROLE_SECURITY_OPERATOR,
    ACTION_BLOCK_FLOW: ROLE_SECURITY_OPERATOR,
    ACTION_TERMINATE_SESSION: ROLE_SECURITY_OPERATOR,
    ACTION_RENEGOTIATE_SESSION: ROLE_SECURITY_OPERATOR,
    ACTION_REQUIRE_RECONFIGURATION: ROLE_SECURITY_OPERATOR,
}

# Actions each role may act on at all (VIEWER is view-only except NO_ACTION).
ROLE_CAPABLE_ACTIONS: Dict[str, Tuple[str, ...]] = {
    ROLE_VIEWER: (ACTION_NO_ACTION,),
    ROLE_ANALYST: (
        ACTION_NO_ACTION, ACTION_ALERT_ONLY, ACTION_REQUIRE_REVIEW,
        ACTION_CAPTURE_EVIDENCE,
    ),
    ROLE_SECURITY_OPERATOR: (
        ACTION_NO_ACTION, ACTION_ALERT_ONLY, ACTION_REQUIRE_REVIEW,
        ACTION_CAPTURE_EVIDENCE, ACTION_ISOLATE_FLOW, ACTION_BLOCK_FLOW,
        ACTION_TERMINATE_SESSION, ACTION_RENEGOTIATE_SESSION,
        ACTION_REQUIRE_RECONFIGURATION,
    ),
    ROLE_SECURITY_ADMIN: (
        ACTION_NO_ACTION, ACTION_ALERT_ONLY, ACTION_REQUIRE_REVIEW,
        ACTION_CAPTURE_EVIDENCE, ACTION_ISOLATE_FLOW, ACTION_BLOCK_FLOW,
        ACTION_TERMINATE_SESSION, ACTION_RENEGOTIATE_SESSION,
        ACTION_REQUIRE_RECONFIGURATION,
    ),
}


def role_can(role: str, action: str) -> bool:
    """Whether a single role is allowed to act on an action at all."""
    validate_action(action)
    if role not in ROLES:
        return False
    capable = ROLE_CAPABLE_ACTIONS.get(role, ())
    if action not in capable:
        return False
    # Role must also outrank (or equal) the action's minimum role.
    return ROLE_RANK[role] >= ROLE_RANK[DEFAULT_MIN_ROLE_BY_ACTION[action]]


def min_role_for(action: str) -> str:
    return DEFAULT_MIN_ROLE_BY_ACTION[action]


def allowed_actions_for(roles: Sequence[str]) -> Tuple[str, ...]:
    """Union of every action the principal's roles may act on (stable order)."""
    order = {
        ACTION_NO_ACTION: 0, ACTION_ALERT_ONLY: 1, ACTION_REQUIRE_REVIEW: 2,
        ACTION_CAPTURE_EVIDENCE: 3, ACTION_ISOLATE_FLOW: 4,
        ACTION_BLOCK_FLOW: 5, ACTION_TERMINATE_SESSION: 6,
        ACTION_RENEGOTIATE_SESSION: 7, ACTION_REQUIRE_RECONFIGURATION: 8,
    }
    permitted = set()
    for role in roles:
        if role in ROLE_CAPABLE_ACTIONS:
            permitted.update(ROLE_CAPABLE_ACTIONS[role])
    return tuple(sorted(permitted, key=lambda action: order[action]))


def authorize(
    context: AuthorizationContext,
    action: str,
    policy: ResponsePolicy,
) -> AuthorizationDecision:
    """Evaluate one action against the context + policy and record a decision.

    Both sides must agree: the policy must require actions/roles the context
    grants. ``allowed_actions`` in the context is consulted when non-empty
    (i.e. the principal is explicitly scoped).
    """
    validate_action(action)
    if not isinstance(context, AuthorizationContext):
        raise TypeError("context must be an AuthorizationContext")

    requirements = policy.action_requirements.get(action, {})
    policy_required = tuple(
        requirements.get("required_roles") or (DEFAULT_MIN_ROLE_BY_ACTION[action],)
    )
    authorized_by_role = any(role_can(role, action) for role in context.roles)
    within_scope = True
    if context.allowed_actions and action not in context.allowed_actions:
        within_scope = False

    authorized = authorized_by_role and within_scope
    if not authorized:
        reason = (
            f"action {action} not permitted for principal {context.principal_id}"
            f" (roles={list(context.roles)}"
            + ("" if within_scope else f", scope excludes {action}")
            + ")"
        )
        if not authorized_by_role:
            reason += f"; requires roles compatible with {min_role_for(action)}"
    else:
        reason = (
            f"principal {context.principal_id} holds a role permitted for "
            f"action {action} under {policy.policy_version}"
        )

    granted = tuple(
        role for role in context.roles
        if role in ROLE_CAPABLE_ACTIONS and action in ROLE_CAPABLE_ACTIONS[role]
        and ROLE_RANK[role] >= ROLE_RANK[min_role_for(action)]
    )
    return AuthorizationDecision(
        principal_id=context.principal_id,
        action=action,
        authorized=authorized,
        required_roles=policy_required,
        granted_roles=granted,
        reason=reason,
        policy_version=policy.policy_version,
    )


def auth_context(
    principal_id: str,
    roles: Sequence[str],
    *,
    scope: Any = None,
    reason: str = "",
) -> AuthorizationContext:
    """Build a context, deriving ``allowed_actions`` from the roles."""
    role_tuple = tuple(roles)
    actions = allowed_actions_for(role_tuple)
    return AuthorizationContext(
        principal_id=principal_id,
        roles=role_tuple,
        scope=scope,
        allowed_actions=actions,
        reason=reason or f"roles {list(role_tuple)}",
    )