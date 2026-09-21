"""PHASE 7 — XAI / Explainability Layer.

Deterministic, read-only explanation layer that converts structured Phase 4
correlation / Phase 5 ML / Phase 6 risk facts into human-readable and
machine-readable explanations. It explains EXISTING DECISIONS ONLY: it never
creates vulnerabilities, changes risk scores or severity, overrides comparison
/ ML / risk results, or fabricates evidence, PCAP references, timestamps,
audit ids or analyst conclusions.

See PHASE_7_XAI_REPORT.md and PHASE_7_XAI_TRACEABILITY.md.
"""

from .engine import ExplainabilityEngine  # noqa: F401
from .evidence import build_evidence_summary  # noqa: F401
from .explainers import (  # noqa: F401
    explain_finding,
    explain_ml_anomaly,
    explain_ml_classification,
    explain_ml_result,
)
from .models import (  # noqa: F401
    XAI_ENGINE_VERSION,
    XAI_SCHEMA_VERSION,
    EXPLANATION_CATEGORIES,
    EXPLANATION_CATEGORY_CONFIGURATION,
    EXPLANATION_CATEGORY_CORRELATION,
    EXPLANATION_CATEGORY_EVIDENCE,
    EXPLANATION_CATEGORY_LIMITATION,
    EXPLANATION_CATEGORY_ML,
    EXPLANATION_CATEGORY_OBSERVATION,
    EXPLANATION_CATEGORY_SCORE,
    PROVENANCE_CORRELATION_RESULT,
    PROVENANCE_EVIDENCE,
    PROVENANCE_ML_RESULT,
    PROVENANCE_RISK_ASSESSMENT,
    PROVENANCE_RISK_FINDING,
    PROVENANCE_RISK_POLICY,
    EvidenceSummary,
    ExplainabilityResult,
    ExplainabilitySummary,
    FindingExplanation,
    GapExplanation,
    MLExplanation,
    ScoreExplanation,
)
from .score_explanation import build_score_explanation  # noqa: F401
from .templates import (  # noqa: F401
    EXPLANATION_IDS,
    RULE_TO_XAI_IDS,
    XAI_TRACEABILITY,
)

__all__ = [
    "ExplainabilityEngine",
    "build_evidence_summary",
    "explain_finding",
    "explain_ml_anomaly",
    "explain_ml_classification",
    "explain_ml_result",
    "XAI_ENGINE_VERSION",
    "XAI_SCHEMA_VERSION",
    "EXPLANATION_CATEGORIES",
    "EXPLANATION_CATEGORY_CONFIGURATION",
    "EXPLANATION_CATEGORY_CORRELATION",
    "EXPLANATION_CATEGORY_EVIDENCE",
    "EXPLANATION_CATEGORY_LIMITATION",
    "EXPLANATION_CATEGORY_ML",
    "EXPLANATION_CATEGORY_OBSERVATION",
    "EXPLANATION_CATEGORY_SCORE",
    "PROVENANCE_CORRELATION_RESULT",
    "PROVENANCE_EVIDENCE",
    "PROVENANCE_ML_RESULT",
    "PROVENANCE_RISK_ASSESSMENT",
    "PROVENANCE_RISK_FINDING",
    "PROVENANCE_RISK_POLICY",
    "EvidenceSummary",
    "ExplainabilityResult",
    "ExplainabilitySummary",
    "FindingExplanation",
    "GapExplanation",
    "MLExplanation",
    "ScoreExplanation",
    "build_score_explanation",
    "EXPLANATION_IDS",
    "RULE_TO_XAI_IDS",
    "XAI_TRACEABILITY",
]