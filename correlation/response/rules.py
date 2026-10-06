"""Phase 9 — response rule registry & traceability.

Mirrors the Phase-6 ``RULE_TRACEABILITY`` / Phase-7 ``XAI_TRACEABILITY``
registries: ``RESPONSE_RULE_TRACEABILITY`` is the single source of truth for
mapping a Phase-6/7 finding rule to a response rule, its action, priority,
authorization / approval gates, limitations and policy dependency. The planner
consumes this registry to build deterministic rationales; it never invents
policy decisions.

Security semantics follow the Phase-9 brief:

* RESP-PFS-001 .. RESP-OBS-MISMATCH-005  -> REQUIRE_REVIEW (analyst approval),
* RESP-ML-*     -> capped by ``ml_handling`` (never blocking),
* RESP-UNKNOWN-* -> evidence-gap handling (review/capture ONLY, never block),
* RESP-REPLAY-* -> REQUIRE_REVIEW (analyst approval; anomaly evidence only),
* NOT_APPLICABLE  -> no security response is created.
"""

from typing import Any, Dict

from .models import (
    ACTION_ALERT_ONLY,
    ACTION_CAPTURE_EVIDENCE,
    ACTION_REQUIRE_REVIEW,
    PRIORITY_HIGH,
    PRIORITY_LOW,
    PRIORITY_MEDIUM,
)

# ``RESPONSE_RULE_TRACEABILITY[finding_rule_id]`` -> rule metadata.
# Each rule documents: finding/risk input, condition, action, priority,
# authorization requirement, approval requirement, limitations,
# policy dependency.
RESPONSE_RULE_TRACEABILITY: Dict[str, Dict[str, Any]] = {
    "esp.pfs.disabled": {
        "rule_id": "RESP-PFS-001",
        "finding_rule": "esp.pfs.disabled",
        "finding_id": "RISK-PFS-DISABLED",
        "input": "RiskFinding RISK-PFS-DISABLED (CONFIGURATION_WEAKNESS, MEDIUM)",
        "condition": "Phase-6 finding exists and policy enables response (rule override).",
        "action": ACTION_REQUIRE_REVIEW,
        "priority": PRIORITY_MEDIUM,
        "authorization_requirement": "ANALYST",
        "approval_requirement": "required",
        "limitations": ["Does not establish runtime exploitation."],
        "policy_dependency": "response-policy-v1",
    },
    "esp.encryption.cbc": {
        "rule_id": "RESP-CBC-002",
        "finding_rule": "esp.encryption.cbc",
        "finding_id": "RISK-WEAK-ESP-CRYPTO",
        "input": "RiskFinding RISK-WEAK-ESP-CRYPTO (CONFIGURATION_WEAKNESS, MEDIUM)",
        "condition": "Phase-6 finding exists and policy enables response.",
        "action": ACTION_REQUIRE_REVIEW,
        "priority": PRIORITY_MEDIUM,
        "authorization_requirement": "ANALYST",
        "approval_requirement": "required",
        "limitations": [
            "CBC is a supported configuration in the authoritative model; "
            "review informs reconfiguration, it is not an attack claim."
        ],
        "policy_dependency": "response-policy-v1",
    },
    "esp.dh_group.weak": {
        "rule_id": "RESP-DH-003",
        "finding_rule": "esp.dh_group.weak",
        "finding_id": "RISK-WEAK-DH-GROUP",
        "input": "RiskFinding RISK-WEAK-DH-GROUP (CONFIGURATION_WEAKNESS, LOW)",
        "condition": "Phase-6 finding exists and policy enables response.",
        "action": ACTION_REQUIRE_REVIEW,
        "priority": PRIORITY_LOW,
        "authorization_requirement": "ANALYST",
        "approval_requirement": "required",
        "limitations": [
            "modp2048 is a valid supported rung; review is informational."
        ],
        "policy_dependency": "response-policy-v1",
    },
    "correlation.mismatch": {
        "rule_id": "RESP-MODE-004",
        "finding_rule": "correlation.mismatch",
        "finding_id": "RISK-MODE-MISMATCH / RISK-ESP-PRESENCE / RISK-...",
        "input": "RiskFinding (CONFIGURATION_MISMATCH / PROTOCOL_ANOMALY)",
        "condition": "Confirmed Phase-4 mismatch for a registered security variable.",
        "action": ACTION_REQUIRE_REVIEW,
        "priority": PRIORITY_HIGH,
        "authorization_requirement": "ANALYST",
        "approval_requirement": "required",
        "limitations": [
            "A confirmed contradiction of the expected model; it does not set "
            "an impact on production traffic."
        ],
        "policy_dependency": "response-policy-v1",
    },
    "ml.anomaly": {
        "rule_id": "RESP-ML-ANOMALY-005",
        "finding_rule": "ml.anomaly",
        "finding_id": "RISK-ML-ANOMALY",
        "input": "RiskFinding RISK-ML-ANOMALY (ML_TRAFFIC_ANOMALY, LOW)",
        "condition": "phase-5 MLResult.anomaly=True; capped by policy ml_handling.",
        "action": ACTION_REQUIRE_REVIEW,
        "priority": PRIORITY_LOW,
        "authorization_requirement": "ANALYST",
        "approval_requirement": "required",
        "limitations": [
            "Model-derived evidence only; never establishes malicious activity "
            "and never auto-blocks traffic (model_version / "
            "classification_confidence / anomaly_score preserved without "
            "promotion)."
        ],
        "policy_dependency": "response-policy-v1 + ml_handling",
    },
    "ml.classification.disagreement": {
        "rule_id": "RESP-ML-CLASS-006",
        "finding_rule": "ml.classification.disagreement",
        "finding_id": "RISK-ML-CLASSIFICATION",
        "input": "RiskFinding RISK-ML-CLASSIFICATION (ML_CLASSIFICATION_DISAGREEMENT, LOW)",
        "condition": "phase-5 traffic_class disagreement; informational.",
        "action": ACTION_ALERT_ONLY,
        "priority": PRIORITY_LOW,
        "authorization_requirement": "ANALYST",
        "approval_requirement": "not required",
        "limitations": [
            "A classification disagreement is informational only; confidence is "
            "the model's own probability."
        ],
        "policy_dependency": "response-policy-v1",
    },
    "evidence.insufficient": {
        "rule_id": "RESP-INSUFFICIENT-007",
        "finding_rule": "evidence.insufficient",
        "finding_id": "RISK-INSUFFICIENT-EVIDENCE-<variable>",
        "input": "RiskFinding (INSUFFICIENT_EVIDENCE, INFO) — opt-in only",
        "condition": "policy.unknown_handling enables evidence-gap capture.",
        "action": ACTION_CAPTURE_EVIDENCE,
        "priority": PRIORITY_LOW,
        "authorization_requirement": "ANALYST",
        "approval_requirement": "required",
        "limitations": [
            "Zero score contribution; surfaces an evidence gap only when the "
            "policy opts in."
        ],
        "policy_dependency": "response-policy-v1 + unknown_handling",
    },
    "evidence.unknown.gap": {
        "rule_id": "RESP-UNKNOWN-008",
        "finding_rule": "correlation.unknowns",
        "finding_id": "REVIEW-UNKNOWN-EVIDENCE",
        "input": "CorrelationResult unknowns (status UNKNOWN for one variable)",
        "condition": "UNKNOWN variable exists and policy recommends evidence capture.",
        "action": ACTION_CAPTURE_EVIDENCE,
        "priority": PRIORITY_LOW,
        "authorization_requirement": "ANALYST",
        "approval_requirement": "required",
        "limitations": [
            "UNKNOWN is an evidence gap, never MISMATCH and never a "
            "vulnerability; never a blocking response."
        ],
        "policy_dependency": "response-policy-v1 + unknown_handling",
    },
    "replay.duplicate_sequence": {
        "rule_id": "RESP-REPLAY-009",
        "finding_rule": "replay.duplicate_sequence",
        "finding_id": "RISK-REPLAY-DUPLICATE",
        "input": (
            "RiskFinding RISK-REPLAY-DUPLICATE (PROTOCOL_ANOMALY, LOW) from "
            "the replay assessment of the recorded packet journal"
        ),
        "condition": (
            "replay_evidence.status == 'OBSERVED' and "
            "replay_evidence.duplicate_sequences > 0"
        ),
        "action": ACTION_REQUIRE_REVIEW,
        "priority": PRIORITY_LOW,
        "authorization_requirement": "ANALYST",
        "approval_requirement": "required",
        "limitations": [
            "Duplicate-sequence anomaly evidence from a capture that cannot "
            "distinguish an injected replay from a capture-path artefact; it "
            "is never proof of an attack.",
            "Sequence gaps are not evidence for this rule and never trigger a "
            "response; NO_EVIDENCE, INSUFFICIENT_DATA and a missing replay "
            "product produce no recommendation at all.",
            "Analyst review only: never a blocking or isolating response.",
        ],
        "policy_dependency": "response-policy-v1",
    },
}

# NOT_APPLICABLE never produces a security response; it is not registered here.
ALL_RESPONSE_RULES = tuple(sorted(RESPONSE_RULE_TRACEABILITY.keys()))


def traceability_for(finding_rule_id: str) -> Dict[str, Any]:
    """Return the response rule metadata for a finding rule (or {})."""
    return dict(RESPONSE_RULE_TRACEABILITY.get(finding_rule_id) or {})


def is_registered_response_rule(finding_rule_id: str) -> bool:
    return finding_rule_id in RESPONSE_RULE_TRACEABILITY