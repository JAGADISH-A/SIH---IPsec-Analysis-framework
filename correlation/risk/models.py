"""Risk domain models for the Phase 6 Risk Assessment & Scoring Engine.

The engine consumes Phase 3/4/5 domain objects (``ExpectedState``,
``ObservedState``, ``CorrelationResult``, ``MLResult``) and produces
deterministic ``RiskFinding`` / ``RiskAssessment`` objects.

Design rules enforced here (Phase 6 brief, sections 6-8, 17-19, 27):

* bounded vocabulary everywhere: severities, finding categories, risk sources
  are finite, documented, and validated at construction time;
* structured findings only (no free-form strings as the only representation);
* deterministic finding IDs (no UUIDs); deterministic suffixing for
  duplicates based on the identity/variable;
* every finding carries a ``rule_id`` and ``evidence_type`` so that XAI (a
  later phase) can consume the structured facts;
* ``RiskAssessment`` is JSON-serializable and deterministic.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, Optional, Tuple

from ..models._base import JsonModel
from ..models.evidence import EvidenceRef
from ..models.identity import CorrelationIdentity

RISK_SCHEMA_VERSION = "v1"
RISK_ENGINE_VERSION = "v1"

# ---- finite severity vocabulary (section 7) ---------------------------------
SEVERITY_INFO = "INFO"
SEVERITY_LOW = "LOW"
SEVERITY_MEDIUM = "MEDIUM"
SEVERITY_HIGH = "HIGH"
SEVERITY_CRITICAL = "CRITICAL"

SEVERITIES = (
    SEVERITY_INFO,
    SEVERITY_LOW,
    SEVERITY_MEDIUM,
    SEVERITY_HIGH,
    SEVERITY_CRITICAL,
)

SEVERITY_RANK = {name: index for index, name in enumerate(SEVERITIES)}


def validate_severity(value: Any) -> str:
    if value not in SEVERITIES:
        raise ValueError(
            f"severity must be one of {SEVERITIES}, got {value!r}"
        )
    return value


# ---- finding sources (section 17) -------------------------------------------
SOURCE_EXPECTED_CONFIGURATION = "EXPECTED_CONFIGURATION"
SOURCE_OBSERVED_PROTOCOL = "OBSERVED_PROTOCOL"
SOURCE_CORRELATION = "CORRELATION"
SOURCE_ML = "ML"
SOURCE_EVIDENCE = "EVIDENCE"

RISK_SOURCES = (
    SOURCE_EXPECTED_CONFIGURATION,
    SOURCE_OBSERVED_PROTOCOL,
    SOURCE_CORRELATION,
    SOURCE_ML,
    SOURCE_EVIDENCE,
)


def validate_risk_source(value: Any) -> str:
    if value not in RISK_SOURCES:
        raise ValueError(f"source must be one of {RISK_SOURCES}, got {value!r}")
    return value


# ---- evidence types ----------------------------------------------------------
EVIDENCE_TYPE_CONFIGURATION = "configuration"
EVIDENCE_TYPE_OBSERVATION = "observation"
EVIDENCE_TYPE_CORRELATION = "correlation"
EVIDENCE_TYPE_ML = "ml"
EVIDENCE_TYPE_POLICY = "policy"

EVIDENCE_TYPES = (
    EVIDENCE_TYPE_CONFIGURATION,
    EVIDENCE_TYPE_OBSERVATION,
    EVIDENCE_TYPE_CORRELATION,
    EVIDENCE_TYPE_ML,
    EVIDENCE_TYPE_POLICY,
)


def validate_evidence_type(value: Any) -> str:
    if value not in EVIDENCE_TYPES:
        raise ValueError(f"evidence_type must be one of {EVIDENCE_TYPES}, got {value!r}")
    return value


# ---- finding categories (sections 12-15) ------------------------------------
CATEGORY_CONFIGURATION_WEAKNESS = "CONFIGURATION_WEAKNESS"
CATEGORY_OBSERVED_MISMATCH = "OBSERVED_MISMATCH"
CATEGORY_PROTOCOL_ANOMALY = "PROTOCOL_ANOMALY"
CATEGORY_CONFIGURATION_MISMATCH = "CONFIGURATION_MISMATCH"
CATEGORY_INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"
CATEGORY_ML_TRAFFIC_ANOMALY = "ML_TRAFFIC_ANOMALY"
CATEGORY_ML_CLASSIFICATION_DISAGREEMENT = "ML_CLASSIFICATION_DISAGREEMENT"

FINDING_CATEGORIES = (
    CATEGORY_CONFIGURATION_WEAKNESS,
    CATEGORY_OBSERVED_MISMATCH,
    CATEGORY_PROTOCOL_ANOMALY,
    CATEGORY_CONFIGURATION_MISMATCH,
    CATEGORY_INSUFFICIENT_EVIDENCE,
    CATEGORY_ML_TRAFFIC_ANOMALY,
    CATEGORY_ML_CLASSIFICATION_DISAGREEMENT,
)


def validate_category(value: Any) -> str:
    if value not in FINDING_CATEGORIES:
        raise ValueError(
            f"category must be one of {FINDING_CATEGORIES}, got {value!r}"
        )
    return value


@dataclass(frozen=True)
class RiskFinding(JsonModel):
    """One deterministic security finding.

    Field-by-field the XAI later-phase can consume:

        reason / condition / expected_value / observed_value / source /
        evidence_refs / rule_id   (Phase 6 brief section 32)

    ``confidence`` is only ever the model-provided classification probability
    for ML classification disagreement; authoritative/deterministic findings
    carry ``None`` (they are not probabilities).
    """

    finding_id: str
    rule_id: str
    category: str
    severity: str
    title: str
    description: str
    reason: str
    condition: str
    source: str
    evidence_type: str
    related_variable: Optional[str] = None
    expected_value: Any = None
    observed_value: Any = None
    confidence: Optional[float] = None
    model_version: Optional[str] = None
    evidence_refs: Tuple[EvidenceRef, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        for name in ("finding_id", "rule_id", "title", "description", "reason",
                     "condition"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{name} must be a non-empty string")
        validate_category(self.category)
        validate_severity(self.severity)
        validate_risk_source(self.source)
        validate_evidence_type(self.evidence_type)
        if self.related_variable is not None and (
            not isinstance(self.related_variable, str)
            or not self.related_variable.strip()
        ):
            raise ValueError("related_variable must be a non-empty string or None")
        if self.confidence is not None:
            if not isinstance(self.confidence, (int, float)) or isinstance(
                self.confidence, bool
            ):
                raise ValueError("confidence must be a float or None")
            if not (0.0 <= float(self.confidence) <= 1.0):
                raise ValueError("confidence must be within [0, 1]")
        if self.model_version is not None and (
            not isinstance(self.model_version, str) or not self.model_version.strip()
        ):
            raise ValueError("model_version must be a non-empty string or None")
        if not isinstance(self.evidence_refs, (tuple, list)):
            raise ValueError("evidence_refs must be a tuple/list of EvidenceRef")
        for ev in self.evidence_refs:
            if not isinstance(ev, EvidenceRef):
                raise ValueError("evidence_refs must contain EvidenceRef objects")

    @property
    def dedup_key(self) -> Tuple[str, str, Optional[str]]:
        """Deterministic deduplication identity (section 20).

        ``(category, related_variable, source)`` collapses different rules
        that identify the same underlying issue against the same variable from
        the same source type (e.g. posture / configuration / comparison / ML
        all describing PFS-disabled do not produce duplicate findings).
        """
        return (self.category, self.related_variable, self.source)

    def to_dict(self) -> Dict[str, Any]:
        ordered = [
            ("finding_id", self.finding_id),
            ("rule_id", self.rule_id),
            ("category", self.category),
            ("severity", self.severity),
            ("related_variable", self.related_variable),
            ("condition", self.condition),
            ("title", self.title),
            ("description", self.description),
            ("reason", self.reason),
            ("expected_value", self.expected_value),
            ("observed_value", self.observed_value),
            ("source", self.source),
            ("evidence_type", self.evidence_type),
            ("confidence", self.confidence),
            ("model_version", self.model_version),
            ("evidence_refs", [ev.to_dict() for ev in self.evidence_refs]),
        ]
        return {key: value for key, value in ordered if value is not None or key in (
            "expected_value", "observed_value", "confidence", "model_version",
        )}

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "RiskFinding":
        return cls(
            finding_id=data["finding_id"],
            rule_id=data["rule_id"],
            category=data["category"],
            severity=data["severity"],
            title=data["title"],
            description=data["description"],
            reason=data["reason"],
            condition=data["condition"],
            source=data["source"],
            evidence_type=data["evidence_type"],
            related_variable=data.get("related_variable"),
            expected_value=data.get("expected_value"),
            observed_value=data.get("observed_value"),
            confidence=data.get("confidence"),
            model_version=data.get("model_version"),
            evidence_refs=tuple(
                EvidenceRef.from_dict(ev) for ev in data.get("evidence_refs") or []
            ),
        )


@dataclass(frozen=True)
class RiskAssessment(JsonModel):
    """Deterministic result of one risk assessment.

    ``metadata`` is a structured dictionary the later XAI phase consumes:
    posture context (consumed, never recomputed), score detail, ML handling
    summary, and the documented evidence-policy statement.
    """

    schema_version: str
    risk_engine_version: str
    risk_policy_version: str
    identity: CorrelationIdentity
    overall_score: int
    severity: str
    findings: Tuple[RiskFinding, ...] = field(default_factory=tuple)
    evidence_refs: Tuple[EvidenceRef, ...] = field(default_factory=tuple)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.schema_version, str) or not self.schema_version.strip():
            raise ValueError("schema_version must be a non-empty string")
        if not isinstance(self.risk_engine_version, str) or not self.risk_engine_version.strip():
            raise ValueError("risk_engine_version must be a non-empty string")
        if not isinstance(self.risk_policy_version, str) or not self.risk_policy_version.strip():
            raise ValueError("risk_policy_version must be a non-empty string")
        if not isinstance(self.identity, CorrelationIdentity):
            raise ValueError("identity must be a CorrelationIdentity")
        if not isinstance(self.overall_score, int) or isinstance(self.overall_score, bool):
            raise ValueError("overall_score must be an integer")
        if not (0 <= self.overall_score <= 100):
            raise ValueError(f"overall_score must be within 0-100, got {self.overall_score}")
        validate_severity(self.severity)
        for finding in self.findings:
            if not isinstance(finding, RiskFinding):
                raise ValueError("findings must contain RiskFinding objects")
        for ev in self.evidence_refs:
            if not isinstance(ev, EvidenceRef):
                raise ValueError("evidence_refs must contain EvidenceRef objects")
        if not isinstance(self.metadata, dict):
            raise ValueError("metadata must be a dict")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "risk_engine_version": self.risk_engine_version,
            "risk_policy_version": self.risk_policy_version,
            "identity": self.identity.to_dict(),
            "overall_score": self.overall_score,
            "severity": self.severity,
            "findings": [f.to_dict() for f in self.findings],
            "evidence_refs": [ev.to_dict() for ev in self.evidence_refs],
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "RiskAssessment":
        return cls(
            schema_version=data["schema_version"],
            risk_engine_version=data["risk_engine_version"],
            risk_policy_version=data["risk_policy_version"],
            identity=CorrelationIdentity.from_dict(data["identity"]),
            overall_score=data["overall_score"],
            severity=data["severity"],
            findings=tuple(
                RiskFinding.from_dict(f) for f in data.get("findings") or []
            ),
            evidence_refs=tuple(
                EvidenceRef.from_dict(ev) for ev in data.get("evidence_refs") or []
            ),
            metadata=dict(data.get("metadata") or {}),
        )


def findings_by_id(findings) -> Dict[str, RiskFinding]:
    """Deterministic index (last occurrence wins on duplicate IDs)."""
    ordered: Dict[str, RiskFinding] = {}
    for finding in findings:
        ordered[finding.finding_id] = finding
    return ordered