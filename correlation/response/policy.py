"""Versioned ResponsePolicy for the Phase 9 response & policy layer.

The policy is the SINGLE source of truth for what action a finding maps to and
what gates that action requires. The planner and engine NEVER hard-code policy
decisions:

* ``severity_defaults``   per-severity default action (conservative: nothing
  above REQUIRE_REVIEW by severity alone);
* ``rule_overrides``      per finding rule_id overrides (RESP-PFS-001 -> ...);
* ``action_requirements`` per-action authorization / approval / roles / dry-run;
* ``ml_handling``         ML-derived findings are capped and never block;
* ``unknown_handling``    UNKNOWN evidence gaps become review/capture at most,
                          and NOT_APPLICABLE triggers NO response meaning;
* ``expiry_ns``           recommended documents expire after this window.

Safety invariant: no severity config maps directly to ISOLATE_FLOW /
BLOCK_FLOW / TERMINATE_SESSION / RENEGOTIATE_SESSION / REQUIRE_RECONFIGURATION;
those actions are only reachable through an explicit rule override that is
itself gated by policy authorization + an authorized role + analyst approval.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, Optional, Sequence, Tuple

from ..risk.models import (
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    SEVERITY_INFO,
    SEVERITY_LOW,
    SEVERITY_MEDIUM,
)
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
    PRIORITY_CRITICAL,
    PRIORITY_HIGH,
    PRIORITY_INFORMATIONAL,
    PRIORITY_LOW,
    PRIORITY_MEDIUM,
    RESPONSE_ACTIONS,
    ROLE_ANALYST,
    ROLE_SECURITY_ADMIN,
    ROLE_SECURITY_OPERATOR,
    is_high_impact,
    validate_action,
)

DEFAULT_RESPONSE_POLICY_VERSION = "response-policy-v1"

# Default per-severity actions. Deliberately conservative: severity alone maps
# to review/alert/capture ONLY — never to a blocking action.
DEFAULT_SEVERITY_ACTIONS: Dict[str, str] = {
    SEVERITY_INFO: ACTION_NO_ACTION,
    SEVERITY_LOW: ACTION_ALERT_ONLY,
    SEVERITY_MEDIUM: ACTION_REQUIRE_REVIEW,
    SEVERITY_HIGH: ACTION_REQUIRE_REVIEW,
    SEVERITY_CRITICAL: ACTION_REQUIRE_REVIEW,
}

# Severity -> priority of the recommended action.
DEFAULT_SEVERITY_PRIORITIES: Dict[str, str] = {
    SEVERITY_INFO: PRIORITY_INFORMATIONAL,
    SEVERITY_LOW: PRIORITY_LOW,
    SEVERITY_MEDIUM: PRIORITY_MEDIUM,
    SEVERITY_HIGH: PRIORITY_HIGH,
    SEVERITY_CRITICAL: PRIORITY_CRITICAL,
}

# Per-action execution gates (port of the Phase-9 brief's approval rules).
DEFAULT_ACTION_REQUIREMENTS: Dict[str, Dict[str, Any]] = {
    ACTION_NO_ACTION: {
        "authorization_required": False,
        "approval_required": False,
        "required_roles": (ROLE_ANALYST,),
        "dry_run_only": False,
        "description": "No operator action is warranted (null action).",
    },
    ACTION_ALERT_ONLY: {
        "authorization_required": False,
        "approval_required": False,
        "required_roles": (ROLE_ANALYST,),
        "dry_run_only": False,
        "description": "Surface to the analyst console; no further action.",
    },
    ACTION_REQUIRE_REVIEW: {
        "authorization_required": False,
        "approval_required": True,
        "required_roles": (ROLE_ANALYST,),
        "dry_run_only": False,
        "description": "Re-review the finding and its evidence before proceeding.",
    },
    ACTION_CAPTURE_EVIDENCE: {
        "authorization_required": True,
        "approval_required": True,
        "required_roles": (ROLE_ANALYST, ROLE_SECURITY_OPERATOR),
        "dry_run_only": True,
        "description": "Extend capture/evidence retention around the finding.",
    },
    ACTION_ISOLATE_FLOW: {
        "authorization_required": True,
        "approval_required": True,
        "required_roles": (ROLE_SECURITY_OPERATOR, ROLE_SECURITY_ADMIN),
        "dry_run_only": True,
        "description": "Isolate the flow from the protected network (Phase 10).",
    },
    ACTION_BLOCK_FLOW: {
        "authorization_required": True,
        "approval_required": True,
        "required_roles": (ROLE_SECURITY_OPERATOR, ROLE_SECURITY_ADMIN),
        "dry_run_only": True,
        "description": "Block the flow (Phase 10; never automatic in Phase 9).",
    },
    ACTION_TERMINATE_SESSION: {
        "authorization_required": True,
        "approval_required": True,
        "required_roles": (ROLE_SECURITY_OPERATOR, ROLE_SECURITY_ADMIN),
        "dry_run_only": True,
        "description": "Terminate the affected security association (Phase 10).",
    },
    ACTION_RENEGOTIATE_SESSION: {
        "authorization_required": True,
        "approval_required": True,
        "required_roles": (ROLE_SECURITY_OPERATOR, ROLE_SECURITY_ADMIN),
        "dry_run_only": True,
        "description": "Force renegotiation of the affected SA (Phase 10).",
    },
    ACTION_REQUIRE_RECONFIGURATION: {
        "authorization_required": True,
        "approval_required": True,
        "required_roles": (ROLE_SECURITY_OPERATOR, ROLE_SECURITY_ADMIN),
        "dry_run_only": True,
        "description": "Flag the configuration for reconfiguration (Phase 10).",
    },
}

# ML handling. A model-derived finding can never be promoted to a blocking
# action; the most it can reach is REQUIRE_REVIEW.
DEFAULT_ML_HANDLING: Dict[str, Any] = {
    "max_action": ACTION_REQUIRE_REVIEW,
    "never_block": True,
    "eligible_actions": (ACTION_NO_ACTION, ACTION_ALERT_ONLY, ACTION_REQUIRE_REVIEW),
    "note": (
        "model_version / classification_confidence / anomaly_score are "
        "preserved and never treated as proof of malicious activity"
    ),
}

# UNKNOWN handling. Empirical evidence gaps are recommended for capture/review
# ONLY — never as a blocking scenario. NOT_APPLICABLE becomes NO response.
DEFAULT_UNKNOWN_HANDLING: Dict[str, Any] = {
    "recommend": True,
    "action": ACTION_CAPTURE_EVIDENCE,
    "priority": PRIORITY_LOW,
    "approval_required": True,
    "authorization_required": True,
    "required_roles": (ROLE_ANALYST,),
    "not_applicable_action": ACTION_NO_ACTION,
    "never_block": True,
}

# Default expiry window (nanoseconds): 30 days. Set None to disable.
DEFAULT_EXPIRY_NS: Optional[int] = 30 * 24 * 60 * 60 * 1_000_000_000

# Default rule overrides: keyed by the Phase-6 finding rule_id. Each override
# may set action / priority / approval / authorization / roles / limitations.
DEFAULT_RULE_OVERRIDES: Dict[str, Dict[str, Any]] = {
    # RESP-PFS-001: PFS disabled -> REQUIRE_REVIEW, analyst approval.
    "esp.pfs.disabled": {
        "action": ACTION_REQUIRE_REVIEW,
        "priority": PRIORITY_MEDIUM,
        "approval_required": True,
        "authorization_required": False,
        "required_roles": (ROLE_ANALYST,),
    },
    # RESP-CBC-002: weak ESP cipher family -> REQUIRE_REVIEW.
    "esp.encryption.cbc": {
        "action": ACTION_REQUIRE_REVIEW,
        "priority": PRIORITY_MEDIUM,
        "approval_required": True,
        "authorization_required": False,
        "required_roles": (ROLE_ANALYST,),
    },
    # RESP-DH-003: weak DH group -> REQUIRE_REVIEW.
    "esp.dh_group.weak": {
        "action": ACTION_REQUIRE_REVIEW,
        "priority": PRIORITY_LOW,
        "approval_required": True,
        "authorization_required": False,
        "required_roles": (ROLE_ANALYST,),
    },
    # RESP-MODE-004 / RESP-OBS-MISMATCH-005: confirmed runtime contradiction.
    "correlation.mismatch": {
        "action": ACTION_REQUIRE_REVIEW,
        "priority": PRIORITY_HIGH,
        "approval_required": True,
        "authorization_required": False,
        "required_roles": (ROLE_ANALYST,),
    },
    # RESP-ML-ANOMALY-008: ML anomaly is capped by ml_handling.
    "ml.anomaly": {
        "action": ACTION_REQUIRE_REVIEW,
        "priority": PRIORITY_LOW,
        "approval_required": True,
        "authorization_required": False,
        "required_roles": (ROLE_ANALYST,),
    },
    "ml.classification.disagreement": {
        "action": ACTION_ALERT_ONLY,
        "priority": PRIORITY_LOW,
        "approval_required": False,
        "authorization_required": False,
        "required_roles": (ROLE_ANALYST,),
    },
}

# Plan-level limitations appended to every deterministic plan.
DEFAULT_PLAN_LIMITATIONS: Tuple[str, ...] = (
    "Phase 9 executes dry-run only; no real network operation is performed.",
    "Blocking/isolating actions require explicit policy authorization, an "
    "authorized role, and analyst approval.",
    "ML-derived findings are model-derived evidence and never auto-block traffic.",
)


def _validated_action(value: Any, name: str) -> str:
    action = validate_action(value)
    if action not in RESPONSE_ACTIONS:  # defensive; validate_action covers it
        raise ValueError(f"{name}: unknown action {value!r}")
    return action


@dataclass(frozen=True)
class ResponsePolicy:
    """Versioned, immutable response policy (the engine never hard-codes gates).

    Lookup order for a finding's action:

        1. rule override (``rule_overrides[rule_id]``) when present;
        2. else the per-severity default (``severity_defaults[severity]``);
        3. ML cap applied on top when the finding is model-derived
           (``ml_handling``) — never above REQUIRE_REVIEW;
        4. UNKNOWN evidence gaps are recommended as ``unknown_handling`` only.

    The action requirements (approval / authorization / roles) come from
    ``action_requirements[action]`` (possibly overridden per rule).
    """

    policy_version: str = DEFAULT_RESPONSE_POLICY_VERSION
    severity_defaults: Dict[str, str] = field(
        default_factory=lambda: dict(DEFAULT_SEVERITY_ACTIONS)
    )
    severity_priorities: Dict[str, str] = field(
        default_factory=lambda: dict(DEFAULT_SEVERITY_PRIORITIES)
    )
    rule_overrides: Dict[str, Dict[str, Any]] = field(
        default_factory=lambda: {k: dict(v) for k, v in DEFAULT_RULE_OVERRIDES.items()}
    )
    action_requirements: Dict[str, Dict[str, Any]] = field(
        default_factory=lambda: {k: dict(v) for k, v in DEFAULT_ACTION_REQUIREMENTS.items()}
    )
    ml_handling: Dict[str, Any] = field(
        default_factory=lambda: dict(DEFAULT_ML_HANDLING)
    )
    unknown_handling: Dict[str, Any] = field(
        default_factory=lambda: dict(DEFAULT_UNKNOWN_HANDLING)
    )
    expiry_ns: Optional[int] = DEFAULT_EXPIRY_NS
    plan_limitations: Tuple[str, ...] = DEFAULT_PLAN_LIMITATIONS

    def __post_init__(self) -> None:
        if not isinstance(self.policy_version, str) or not self.policy_version.strip():
            raise ValueError("policy_version must be a non-empty string")
        for severity in self.severity_defaults:
            if severity not in (
                SEVERITY_INFO, SEVERITY_LOW, SEVERITY_MEDIUM,
                SEVERITY_HIGH, SEVERITY_CRITICAL,
            ):
                raise ValueError(f"severity_defaults: unknown severity {severity!r}")
            _validated_action(self.severity_defaults[severity], severity)
        for rule_id, override in self.rule_overrides.items():
            if not isinstance(override, dict):
                raise ValueError(f"rule_overrides[{rule_id}] must be a dict")
            if "action" in override:
                _validated_action(override["action"], rule_id)
        for action, requirements in self.action_requirements.items():
            _validated_action(action, "action_requirements")
            if not isinstance(requirements, dict):
                raise ValueError(f"action_requirements[{action}] must be a dict")
            for flag in ("authorization_required", "approval_required", "dry_run_only"):
                if flag in requirements and not isinstance(requirements[flag], bool):
                    raise ValueError(f"action_requirements[{action}].{flag} must be a bool")
        if not isinstance(self.ml_handling, dict):
            raise ValueError("ml_handling must be a dict")
        try:
            _validated_action(self.ml_handling.get("max_action"), "ml_handling.max_action")
        except (TypeError, ValueError):
            raise ValueError("ml_handling.max_action must be a valid action")
        if not isinstance(self.unknown_handling, dict):
            raise ValueError("unknown_handling must be a dict")
        if self.expiry_ns is not None and (
            not isinstance(self.expiry_ns, int) or self.expiry_ns <= 0
        ):
            raise ValueError("expiry_ns must be a positive int or None")
        if not isinstance(self.plan_limitations, (tuple, list)):
            raise ValueError("plan_limitations must be a tuple/list")

    # -- lookups ------------------------------------------------------------

    def action_for(self, rule_id: str, severity: str) -> str:
        """Primary action lookup (rule override -> severity default)."""
        override = self.rule_overrides.get(rule_id)
        if override and override.get("action"):
            return override["action"]
        return self.severity_defaults[severity]

    def priority_for(self, rule_id: str, severity: str) -> str:
        override = self.rule_overrides.get(rule_id)
        if override and override.get("priority"):
            return override["priority"]
        return self.severity_priorities[severity]

    def requirements_for(self, rule_id: str, action: str) -> Dict[str, Any]:
        """Per-rule requirements with per-action defaults as the base."""
        base = dict(self.action_requirements.get(action, {}))
        override = self.rule_overrides.get(rule_id) or {}
        for key in ("approval_required", "authorization_required",
                    "required_roles", "dry_run_only"):
            if key in override:
                base[key] = override[key]
        return base

    def cap_for_ml(self, action: str) -> str:
        """Cap a model-derived finding's action (never above the ML maximum)."""
        eligible = tuple(self.ml_handling.get("eligible_actions") or ())
        if action in eligible:
            return action
        max_action = self.ml_handling.get("max_action", ACTION_REQUIRE_REVIEW)
        if action in (ACTION_CAPTURE_EVIDENCE,) or is_high_impact(action):
            return max_action
        rank = {ACTION_NO_ACTION: 0, ACTION_ALERT_ONLY: 1,
                ACTION_REQUIRE_REVIEW: 2, ACTION_CAPTURE_EVIDENCE: 3}
        try:
            if rank[action] > rank.get(max_action, 2):
                return max_action
        except KeyError:
            return max_action
        return action

    @classmethod
    def default(cls) -> "ResponsePolicy":
        return cls()

    def with_override(self, rule_id: str, **updates: Any) -> "ResponsePolicy":
        merged = dict(self.rule_overrides)
        entry = dict(merged.get(rule_id) or {})
        entry.update(updates)
        merged[rule_id] = entry
        return ResponsePolicy(
            policy_version=self.policy_version,
            severity_defaults=self.severity_defaults,
            severity_priorities=self.severity_priorities,
            rule_overrides=merged,
            action_requirements=self.action_requirements,
            ml_handling=self.ml_handling,
            unknown_handling=self.unknown_handling,
            expiry_ns=self.expiry_ns,
            plan_limitations=self.plan_limitations,
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "policy_version": self.policy_version,
            "severity_defaults": dict(self.severity_defaults),
            "severity_priorities": dict(self.severity_priorities),
            "rule_overrides": {
                rule_id: dict(override)
                for rule_id, override in self.rule_overrides.items()
            },
            "action_requirements": {
                action: dict(requirements)
                for action, requirements in self.action_requirements.items()
            },
            "ml_handling": dict(self.ml_handling),
            "unknown_handling": dict(self.unknown_handling),
            "expiry_ns": self.expiry_ns,
            "plan_limitations": list(self.plan_limitations),
        }


def default_response_policy_dict() -> Dict[str, Any]:
    return ResponsePolicy.default().to_dict()