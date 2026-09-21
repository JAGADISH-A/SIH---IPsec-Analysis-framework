"""PHASE 6 — Risk Assessment & Security Scoring Engine.

Deterministic risk engine consuming Phase 3/4/5 outputs. See
PHASE_6_RISK_ENGINE_REPORT.md and PHASE_6_RISK_RULE_TRACEABILITY.md.
"""

from .engine import RiskEngine  # noqa: F401
from .findings import deduplicate_findings  # noqa: F401
from .models import (  # noqa: F401
    CATEGORY_CONFIGURATION_MISMATCH,
    CATEGORY_CONFIGURATION_WEAKNESS,
    CATEGORY_INSUFFICIENT_EVIDENCE,
    CATEGORY_ML_CLASSIFICATION_DISAGREEMENT,
    CATEGORY_ML_TRAFFIC_ANOMALY,
    CATEGORY_OBSERVED_MISMATCH,
    CATEGORY_PROTOCOL_ANOMALY,
    SEVERITIES,
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    SEVERITY_INFO,
    SEVERITY_LOW,
    SEVERITY_MEDIUM,
    FINDING_CATEGORIES,
    RISK_SOURCES,
    SOURCE_CORRELATION,
    SOURCE_EVIDENCE,
    SOURCE_EXPECTED_CONFIGURATION,
    SOURCE_ML,
    SOURCE_OBSERVED_PROTOCOL,
    RiskAssessment,
    RiskFinding,
)
from .policy import (  # noqa: F401
    DEFAULT_RISK_POLICY_VERSION,
    RiskPolicy,
    default_policy_dict,
    validate_severity_bands,
)
from .rules import (  # noqa: F401
    RULE_REGISTRY,
    RULE_TRACEABILITY,
    RiskRuleContext,
    run_rules,
)
from .scoring import ScoreResult, score_findings  # noqa: F401

__all__ = [
    "RiskEngine",
    "deduplicate_findings",
    "CATEGORY_CONFIGURATION_MISMATCH",
    "CATEGORY_CONFIGURATION_WEAKNESS",
    "CATEGORY_INSUFFICIENT_EVIDENCE",
    "CATEGORY_ML_CLASSIFICATION_DISAGREEMENT",
    "CATEGORY_ML_TRAFFIC_ANOMALY",
    "CATEGORY_OBSERVED_MISMATCH",
    "CATEGORY_PROTOCOL_ANOMALY",
    "SEVERITIES",
    "SEVERITY_CRITICAL",
    "SEVERITY_HIGH",
    "SEVERITY_INFO",
    "SEVERITY_LOW",
    "SEVERITY_MEDIUM",
    "FINDING_CATEGORIES",
    "RISK_SOURCES",
    "SOURCE_CORRELATION",
    "SOURCE_EVIDENCE",
    "SOURCE_EXPECTED_CONFIGURATION",
    "SOURCE_ML",
    "SOURCE_OBSERVED_PROTOCOL",
    "RiskAssessment",
    "RiskFinding",
    "DEFAULT_RISK_POLICY_VERSION",
    "RiskPolicy",
    "default_policy_dict",
    "validate_severity_bands",
    "RULE_REGISTRY",
    "RULE_TRACEABILITY",
    "RiskRuleContext",
    "run_rules",
    "ScoreResult",
    "score_findings",
]