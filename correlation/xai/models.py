"""Explainability (XAI) domain models for the Phase 7 layer.

The XAI layer EXPLAINS EXISTING DECISIONS ONLY. Every field below is derived
from already-produced structured facts (Phase 4 comparisons, Phase 5 ML
results, Phase 6 risk findings/assessments). Nothing here changes risk scores,
severities, comparison results or ML results, and nothing invents evidence.

Sections of the Phase 7 brief honored here:

* output structure (schema_version / identity / summary / finding_explanations
  / ml_explanations / evidence_summary / score_explanation / metadata);
* XAI output categories (CONFIGURATION_EXPLANATION, OBSERVATION_EXPLANATION,
  CORRELATION_EXPLANATION, ML_EXPLANATION, EVIDENCE_EXPLANATION,
  SCORE_EXPLANATION, LIMITATION);
* data provenance (every explanation carries a ``provenance`` value such as
  RISK_FINDING / ML_RESULT / RISK_ASSESSMENT / CORRELATION_RESULT);
* determinism (fixed vocabularies, no UUIDs, no current-time dependence);
* ``<category>`` etc. are bounded enums validated at construction time like the
  Phase 6 models.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, Optional, Sequence, Tuple

from ..models._base import JsonModel
from ..models.identity import CorrelationIdentity

XAI_SCHEMA_VERSION = "v1"
XAI_ENGINE_VERSION = "v1"

# ---- XAI output categories (brief "XAI OUTPUT CATEGORIES") -------------------
EXPLANATION_CATEGORY_CONFIGURATION = "CONFIGURATION_EXPLANATION"
EXPLANATION_CATEGORY_OBSERVATION = "OBSERVATION_EXPLANATION"
EXPLANATION_CATEGORY_CORRELATION = "CORRELATION_EXPLANATION"
EXPLANATION_CATEGORY_ML = "ML_EXPLANATION"
EXPLANATION_CATEGORY_EVIDENCE = "EVIDENCE_EXPLANATION"
EXPLANATION_CATEGORY_SCORE = "SCORE_EXPLANATION"
EXPLANATION_CATEGORY_LIMITATION = "LIMITATION"

EXPLANATION_CATEGORIES = (
    EXPLANATION_CATEGORY_CONFIGURATION,
    EXPLANATION_CATEGORY_OBSERVATION,
    EXPLANATION_CATEGORY_CORRELATION,
    EXPLANATION_CATEGORY_ML,
    EXPLANATION_CATEGORY_EVIDENCE,
    EXPLANATION_CATEGORY_SCORE,
    EXPLANATION_CATEGORY_LIMITATION,
)


def validate_explanation_category(value: Any) -> str:
    if value not in EXPLANATION_CATEGORIES:
        raise ValueError(
            f"explanation category must be one of {EXPLANATION_CATEGORIES}, "
            f"got {value!r}"
        )
    return value


# ---- provenance (brief "DATA PROVENANCE") -----------------------------------
PROVENANCE_RISK_FINDING = "RISK_FINDING"
PROVENANCE_ML_RESULT = "ML_RESULT"
PROVENANCE_CORRELATION_RESULT = "CORRELATION_RESULT"
PROVENANCE_RISK_ASSESSMENT = "RISK_ASSESSMENT"
PROVENANCE_EVIDENCE = "EVIDENCE"
PROVENANCE_RISK_POLICY = "RISK_POLICY"

PROVENANCE_VALUES = (
    PROVENANCE_RISK_FINDING,
    PROVENANCE_ML_RESULT,
    PROVENANCE_CORRELATION_RESULT,
    PROVENANCE_RISK_ASSESSMENT,
    PROVENANCE_EVIDENCE,
    PROVENANCE_RISK_POLICY,
)


def validate_provenance(value: Any) -> str:
    if value not in PROVENANCE_VALUES:
        raise ValueError(f"provenance must be one of {PROVENANCE_VALUES}, got {value!r}")
    return value


# ---- comparison statuses (preserved, never conflated) ------------------------
STATUS_MATCH = "MATCH"
STATUS_MISMATCH = "MISMATCH"
STATUS_UNKNOWN = "UNKNOWN"
STATUS_NOT_APPLICABLE = "NOT_APPLICABLE"
STATUS_PARTIAL = "PARTIAL"

PRESERVED_STATUSES = (
    STATUS_MATCH,
    STATUS_MISMATCH,
    STATUS_UNKNOWN,
    STATUS_NOT_APPLICABLE,
    STATUS_PARTIAL,
)


def _non_empty_list(value: Any, name: str, item_type, allow_empty: bool = True) -> None:
    if not isinstance(value, (tuple, list)):
        raise ValueError(f"{name} must be a tuple/list")
    if not allow_empty and not value:
        raise ValueError(f"{name} must not be empty")
    for item in value:
        if not isinstance(item, item_type):
            raise ValueError(f"{name} items must be {item_type.__name__} objects")
    for item in value:
        if item in value[value.index(item) + 1 :]:
            raise ValueError(f"{name} must not contain duplicates")


def _sorted_unique(items: Sequence[str]) -> Tuple[str, ...]:
    return tuple(sorted(set(items)))


@dataclass(frozen=True)
class FindingExplanation(JsonModel):
    """Human-readable + machine-readable explanation of ONE Phase-6 finding.

    Every field is copied/derived from the ``RiskFinding``; nothing here is
    invented. ``expected``/``observed`` are the finding's expected/observed
    values preserved verbatim (null when the finding carried none).
    """

    provenance: str = PROVENANCE_RISK_FINDING
    finding_id: str = ""
    rule_id: str = ""
    title: str = ""
    severity: str = ""
    category: str = ""
    related_variable: Optional[str] = None
    description: str = ""
    why_it_was_flagged: str = ""
    expected: Any = None
    observed: Any = None
    condition: str = ""
    reason: str = ""
    source: str = ""
    evidence_type: str = ""
    evidence_refs: Tuple[Dict[str, Any], ...] = field(default_factory=tuple)
    confidence: Optional[float] = None
    model_version: Optional[str] = None
    contributing_factors: Tuple[str, ...] = field(default_factory=tuple)
    explanation_categories: Tuple[str, ...] = field(default_factory=tuple)
    limitations: Tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        validate_provenance(self.provenance)
        for name in ("finding_id", "rule_id", "title", "severity", "category",
                     "why_it_was_flagged", "source", "evidence_type"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{name} must be a non-empty string")
        for name in ("description", "condition", "reason"):
            if not isinstance(getattr(self, name), str):
                raise ValueError(f"{name} must be a string")
        if self.related_variable is not None and (
            not isinstance(self.related_variable, str) or not self.related_variable.strip()
        ):
            raise ValueError("related_variable must be a non-empty string or None")
        for cat in self.explanation_categories:
            validate_explanation_category(cat)
        if not isinstance(self.contributing_factors, (tuple, list)):
            raise ValueError("contributing_factors must be a tuple/list")
        if not isinstance(self.limitations, (tuple, list)):
            raise ValueError("limitations must be a tuple/list")
        if not isinstance(self.evidence_refs, (tuple, list)):
            raise ValueError("evidence_refs must be a tuple/list")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "provenance": self.provenance,
            "finding_id": self.finding_id,
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity,
            "category": self.category,
            "related_variable": self.related_variable,
            "description": self.description,
            "why_it_was_flagged": self.why_it_was_flagged,
            "expected": self.expected,
            "observed": self.observed,
            "condition": self.condition,
            "reason": self.reason,
            "source": self.source,
            "evidence_type": self.evidence_type,
            "evidence_refs": [dict(ev) for ev in self.evidence_refs],
            "confidence": self.confidence,
            "model_version": self.model_version,
            "contributing_factors": list(self.contributing_factors),
            "explanation_categories": list(self.explanation_categories),
            "limitations": list(self.limitations),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "FindingExplanation":
        return cls(
            provenance=data.get("provenance") or PROVENANCE_RISK_FINDING,
            finding_id=data["finding_id"],
            rule_id=data["rule_id"],
            title=data["title"],
            severity=data["severity"],
            category=data["category"],
            related_variable=data.get("related_variable"),
            description=data.get("description") or "",
            why_it_was_flagged=data["why_it_was_flagged"],
            expected=data.get("expected"),
            observed=data.get("observed"),
            condition=data.get("condition") or "",
            reason=data.get("reason") or "",
            source=data["source"],
            evidence_type=data["evidence_type"],
            evidence_refs=tuple(
                dict(ev) for ev in (data.get("evidence_refs") or [])
            ),
            confidence=data.get("confidence"),
            model_version=data.get("model_version"),
            contributing_factors=tuple(data.get("contributing_factors") or ()),
            explanation_categories=tuple(data.get("explanation_categories") or ()),
            limitations=tuple(data.get("limitations") or ()),
        )


@dataclass(frozen=True)
class MLExplanation(JsonModel):
    """Explanation of Phase-5 model-derived evidence.

    Conservative by construction: a verdict is only ever reported as the model
    produced it, never upgraded to an attack conclusion and never converted
    into a new risk contribution.
    """

    provenance: str = PROVENANCE_ML_RESULT
    explanation_kind: str = ""
    model_version: Optional[str] = None
    traffic_class: Optional[str] = None
    classification_confidence: Optional[float] = None
    anomaly: Optional[bool] = None
    anomaly_score: Optional[float] = None
    explanation: str = ""
    explanation_categories: Tuple[str, ...] = field(default_factory=tuple)
    limitations: Tuple[str, ...] = field(default_factory=tuple)
    evidence_refs: Tuple[Dict[str, Any], ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        validate_provenance(self.provenance)
        if not isinstance(self.explanation_kind, str) or not self.explanation_kind.strip():
            raise ValueError("explanation_kind must be a non-empty string")
        if not isinstance(self.explanation, str) or not self.explanation.strip():
            raise ValueError("explanation must be a non-empty string")
        for cat in self.explanation_categories:
            validate_explanation_category(cat)
        if not isinstance(self.limitations, (tuple, list)):
            raise ValueError("limitations must be a tuple/list")
        if not isinstance(self.evidence_refs, (tuple, list)):
            raise ValueError("evidence_refs must be a tuple/list")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "provenance": self.provenance,
            "explanation_kind": self.explanation_kind,
            "model_version": self.model_version,
            "traffic_class": self.traffic_class,
            "classification_confidence": self.classification_confidence,
            "anomaly": self.anomaly,
            "anomaly_score": self.anomaly_score,
            "explanation": self.explanation,
            "explanation_categories": list(self.explanation_categories),
            "limitations": list(self.limitations),
            "evidence_refs": [dict(ev) for ev in self.evidence_refs],
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "MLExplanation":
        return cls(
            provenance=data.get("provenance") or PROVENANCE_ML_RESULT,
            explanation_kind=data["explanation_kind"],
            model_version=data.get("model_version"),
            traffic_class=data.get("traffic_class"),
            classification_confidence=data.get("classification_confidence"),
            anomaly=data.get("anomaly"),
            anomaly_score=data.get("anomaly_score"),
            explanation=data["explanation"],
            explanation_categories=tuple(data.get("explanation_categories") or ()),
            limitations=tuple(data.get("limitations") or ()),
            evidence_refs=tuple(dict(ev) for ev in (data.get("evidence_refs") or [])),
        )


@dataclass(frozen=True)
class GapExplanation(JsonModel):
    """UNKNOWN / NOT_APPLICABLE explanation (distinction preserved).

    A UNKNOWN variable is described as an evidence gap that could NOT establish
    a match or mismatch (never upgraded to MISMATCH). A NOT_APPLICABLE variable
    is described as out of scope for the evaluated rule.
    """

    provenance: str = PROVENANCE_CORRELATION_RESULT
    status: str = ""
    variable: str = ""
    expected_value: Any = None
    reason: str = ""
    explanation: str = ""
    explanation_categories: Tuple[str, ...] = field(default_factory=tuple)
    limitations: Tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        validate_provenance(self.provenance)
        if self.status not in (STATUS_UNKNOWN, STATUS_NOT_APPLICABLE):
            raise ValueError(
                f"status must be UNKNOWN or NOT_APPLICABLE inside a GapExplanation, "
                f"got {self.status!r}"
            )
        if not isinstance(self.variable, str) or not self.variable.strip():
            raise ValueError("variable must be a non-empty string")
        if not isinstance(self.explanation, str) or not self.explanation.strip():
            raise ValueError("explanation must be a non-empty string")
        if not isinstance(self.reason, str):
            raise ValueError("reason must be a string")
        for cat in self.explanation_categories:
            validate_explanation_category(cat)
        if not isinstance(self.limitations, (tuple, list)):
            raise ValueError("limitations must be a tuple/list")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "provenance": self.provenance,
            "status": self.status,
            "variable": self.variable,
            "expected_value": self.expected_value,
            "reason": self.reason,
            "explanation": self.explanation,
            "explanation_categories": list(self.explanation_categories),
            "limitations": list(self.limitations),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "GapExplanation":
        return cls(
            provenance=data.get("provenance") or PROVENANCE_CORRELATION_RESULT,
            status=data["status"],
            variable=data["variable"],
            expected_value=data.get("expected_value"),
            reason=data.get("reason") or "",
            explanation=data["explanation"],
            explanation_categories=tuple(data.get("explanation_categories") or ()),
            limitations=tuple(data.get("limitations") or ()),
        )


@dataclass(frozen=True)
class EvidenceSummary(JsonModel):
    """Deterministic aggregation of every supplied evidence reference.

    Refs are preserved EXACTLY (each ``EvidenceRef.to_dict()``) and sorted by a
    canonical key; duplicates are removed. Nothing is fabricated.
    """

    provenance: str = PROVENANCE_EVIDENCE
    total_refs: int = 0
    refs: Tuple[Dict[str, Any], ...] = field(default_factory=tuple)
    sources: Tuple[str, ...] = field(default_factory=tuple)
    source_counts: Tuple[Tuple[str, int], ...] = field(default_factory=tuple)
    limitation: Optional[str] = None
    fabricated: bool = False

    def __post_init__(self) -> None:
        validate_provenance(self.provenance)
        if not isinstance(self.total_refs, int) or self.total_refs < 0:
            raise ValueError("total_refs must be a non-negative integer")
        if len(self.refs) != self.total_refs:
            raise ValueError("total_refs must equal the number of refs")
        if self.fabricated:
            raise ValueError("EvidenceSummary can never fabricate references")
        if not isinstance(self.refs, (tuple, list)):
            raise ValueError("refs must be a tuple/list")
        if not isinstance(self.sources, (tuple, list)):
            raise ValueError("sources must be a tuple/list")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "provenance": self.provenance,
            "total_refs": self.total_refs,
            "refs": [dict(ev) for ev in self.refs],
            "sources": list(self.sources),
            "source_counts": [list(item) for item in self.source_counts],
            "limitation": self.limitation,
            "fabricated": self.fabricated,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "EvidenceSummary":
        return cls(
            provenance=data.get("provenance") or PROVENANCE_EVIDENCE,
            total_refs=data["total_refs"],
            refs=tuple(dict(ev) for ev in (data.get("refs") or [])),
            sources=tuple(data.get("sources") or ()),
            source_counts=tuple(tuple(item) for item in (data.get("source_counts") or [])),
            limitation=data.get("limitation"),
            fabricated=bool(data.get("fabricated")),
        )


@dataclass(frozen=True)
class ScoreExplanation(JsonModel):
    """Explanation of the Phase-6 score WITHOUT recomputing it.

    score / severity / risk_policy_version are copied from the RiskAssessment.
    The per-finding contributions come from ``metadata.score_detail`` (already
    produced by Phase 6); when absent they are shown as unavailable rather than
    recomputed.
    """

    provenance: str = PROVENANCE_RISK_ASSESSMENT
    score: int = 0
    severity: str = ""
    severity_band: Optional[Tuple[str, int, int]] = None
    risk_policy_version: str = ""
    raw_sum: Optional[int] = None
    contributions: Tuple[Dict[str, Any], ...] = field(default_factory=tuple)
    per_category_totals: Tuple[Tuple[str, int], ...] = field(default_factory=tuple)
    explanation: str = ""
    score_unchanged: bool = True
    severity_unchanged: bool = True

    def __post_init__(self) -> None:
        validate_provenance(self.provenance)
        if not isinstance(self.score, int) or not (0 <= self.score <= 100):
            raise ValueError("score must be an int in [0, 100]")
        if not isinstance(self.severity, str) or not self.severity.strip():
            raise ValueError("severity must be a non-empty string")
        if self.risk_policy_version is None or not self.risk_policy_version.strip():
            raise ValueError("risk_policy_version must be a non-empty string")
        if not isinstance(self.explanation, str) or not self.explanation.strip():
            raise ValueError("explanation must be a non-empty string")
        if not self.score_unchanged or not self.severity_unchanged:
            raise ValueError("score/severity are authoritative; they can never be changed")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "provenance": self.provenance,
            "score": self.score,
            "severity": self.severity,
            "severity_band": list(self.severity_band) if self.severity_band else None,
            "risk_policy_version": self.risk_policy_version,
            "raw_sum": self.raw_sum,
            "contributions": [dict(c) for c in self.contributions],
            "per_category_totals": [list(item) for item in self.per_category_totals],
            "explanation": self.explanation,
            "score_unchanged": self.score_unchanged,
            "severity_unchanged": self.severity_unchanged,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ScoreExplanation":
        band = data.get("severity_band")
        return cls(
            provenance=data.get("provenance") or PROVENANCE_RISK_ASSESSMENT,
            score=data["score"],
            severity=data["severity"],
            severity_band=tuple(band) if band else None,
            risk_policy_version=data["risk_policy_version"],
            raw_sum=data.get("raw_sum"),
            contributions=tuple(dict(c) for c in (data.get("contributions") or [])),
            per_category_totals=tuple(
                tuple(item) for item in (data.get("per_category_totals") or [])
            ),
            explanation=data["explanation"],
            score_unchanged=bool(data.get("score_unchanged")),
            severity_unchanged=bool(data.get("severity_unchanged")),
        )


@dataclass(frozen=True)
class ExplainabilitySummary(JsonModel):
    """Compact deterministic summary of the whole explanation."""

    overall_score: int = 0
    severity: str = ""
    risk_policy_version: str = ""
    finding_explanations: int = 0
    ml_explanations: int = 0
    unknown_explanations: int = 0
    not_applicable_explanations: int = 0
    evidence_refs: int = 0
    overall_explanation: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.overall_score, int) or not (0 <= self.overall_score <= 100):
            raise ValueError("overall_score must be an int in [0, 100]")
        if not isinstance(self.severity, str) or not self.severity.strip():
            raise ValueError("severity must be a non-empty string")
        if self.risk_policy_version is None or not self.risk_policy_version.strip():
            raise ValueError("risk_policy_version must be a non-empty string")
        for name in ("finding_explanations", "ml_explanations",
                     "unknown_explanations", "not_applicable_explanations",
                     "evidence_refs"):
            if not isinstance(getattr(self, name), int) or getattr(self, name) < 0:
                raise ValueError(f"{name} must be a non-negative integer")
        if not isinstance(self.overall_explanation, str):
            raise ValueError("overall_explanation must be a string")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "overall_score": self.overall_score,
            "severity": self.severity,
            "risk_policy_version": self.risk_policy_version,
            "finding_explanations": self.finding_explanations,
            "ml_explanations": self.ml_explanations,
            "unknown_explanations": self.unknown_explanations,
            "not_applicable_explanations": self.not_applicable_explanations,
            "evidence_refs": self.evidence_refs,
            "overall_explanation": self.overall_explanation,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ExplainabilitySummary":
        return cls(
            overall_score=data["overall_score"],
            severity=data["severity"],
            risk_policy_version=data["risk_policy_version"],
            finding_explanations=data["finding_explanations"],
            ml_explanations=data.get("ml_explanations", 0),
            unknown_explanations=data.get("unknown_explanations", 0),
            not_applicable_explanations=data.get("not_applicable_explanations", 0),
            evidence_refs=data.get("evidence_refs", 0),
            overall_explanation=data.get("overall_explanation", ""),
        )


@dataclass(frozen=True)
class ExplainabilityResult(JsonModel):
    """Top-level deterministic output of the Phase-7 XAI engine."""

    schema_version: str = XAI_SCHEMA_VERSION
    identity: Optional[CorrelationIdentity] = None
    summary: Optional[ExplainabilitySummary] = None
    finding_explanations: Tuple[FindingExplanation, ...] = field(default_factory=tuple)
    ml_explanations: Tuple[MLExplanation, ...] = field(default_factory=tuple)
    unknown_explanations: Tuple[GapExplanation, ...] = field(default_factory=tuple)
    not_applicable_explanations: Tuple[GapExplanation, ...] = field(default_factory=tuple)
    evidence_summary: Optional[EvidenceSummary] = None
    score_explanation: Optional[ScoreExplanation] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.schema_version != XAI_SCHEMA_VERSION:
            raise ValueError(f"schema_version must be {XAI_SCHEMA_VERSION!r}")
        if self.identity is not None and not isinstance(self.identity, CorrelationIdentity):
            raise ValueError("identity must be a CorrelationIdentity or None")
        for name, item_type in (
            ("finding_explanations", FindingExplanation),
            ("ml_explanations", MLExplanation),
            ("unknown_explanations", GapExplanation),
            ("not_applicable_explanations", GapExplanation),
        ):
            items = getattr(self, name)
            if not isinstance(items, (tuple, list)):
                raise ValueError(f"{name} must be a tuple/list")
            for item in items:
                if not isinstance(item, item_type):
                    raise ValueError(f"{name} items must be {item_type.__name__}")
        if self.evidence_summary is not None and not isinstance(
            self.evidence_summary, EvidenceSummary
        ):
            raise ValueError("evidence_summary must be an EvidenceSummary or None")
        if self.score_explanation is not None and not isinstance(
            self.score_explanation, ScoreExplanation
        ):
            raise ValueError("score_explanation must be a ScoreExplanation or None")
        if not isinstance(self.metadata, dict):
            raise ValueError("metadata must be a dict")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "identity": self.identity.to_dict() if self.identity else None,
            "summary": self.summary.to_dict() if self.summary else None,
            "finding_explanations": [f.to_dict() for f in self.finding_explanations],
            "ml_explanations": [m.to_dict() for m in self.ml_explanations],
            "unknown_explanations": [g.to_dict() for g in self.unknown_explanations],
            "not_applicable_explanations": [
                g.to_dict() for g in self.not_applicable_explanations
            ],
            "evidence_summary": (
                self.evidence_summary.to_dict() if self.evidence_summary else None
            ),
            "score_explanation": (
                self.score_explanation.to_dict() if self.score_explanation else None
            ),
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ExplainabilityResult":
        identity = data.get("identity")
        summary = data.get("summary")
        evidence = data.get("evidence_summary")
        score = data.get("score_explanation")
        return cls(
            schema_version=data.get("schema_version", XAI_SCHEMA_VERSION),
            identity=CorrelationIdentity.from_dict(identity) if identity else None,
            summary=ExplainabilitySummary.from_dict(summary) if summary else None,
            finding_explanations=tuple(
                FindingExplanation.from_dict(f) for f in (data.get("finding_explanations") or [])
            ),
            ml_explanations=tuple(
                MLExplanation.from_dict(m) for m in (data.get("ml_explanations") or [])
            ),
            unknown_explanations=tuple(
                GapExplanation.from_dict(g) for g in (data.get("unknown_explanations") or [])
            ),
            not_applicable_explanations=tuple(
                GapExplanation.from_dict(g)
                for g in (data.get("not_applicable_explanations") or [])
            ),
            evidence_summary=EvidenceSummary.from_dict(evidence) if evidence else None,
            score_explanation=ScoreExplanation.from_dict(score) if score else None,
            metadata=dict(data.get("metadata") or {}),
        )