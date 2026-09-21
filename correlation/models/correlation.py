"""Unified correlation input and result skeleton.

``CorrelationInput`` joins identity + expected + observed + live features + ML
result + evidence. ``CorrelationResult`` is a SKELETON ONLY: phase 2 does not
implement any comparison, and its status is always ``NOT_EVALUATED``.

No mismatch scoring, thresholds, or risk values are produced in this phase;
``matches`` / ``mismatches`` / ``unknowns`` are therefore empty lists of
future opaque entries.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from ..version import CORRELATION_SCHEMA_VERSION
from ._base import JsonModel
from .evidence import EvidenceRef
from .expected import ExpectedState
from .features import LiveFeatureWindow
from .identity import CorrelationIdentity
from .ml import MLResult
from .observed import ObservedState

CORRELATION_STATUS_NOT_EVALUATED = "NOT_EVALUATED"
CORRELATION_STATUS_MATCH = "MATCH"
CORRELATION_STATUS_MISMATCH = "MISMATCH"
CORRELATION_STATUS_UNKNOWN = "UNKNOWN"
CORRELATION_STATUS_PARTIAL = "PARTIAL"
CORRELATION_STATUS_NOT_APPLICABLE = "NOT_APPLICABLE"

CORRELATION_STATUSES = (
    CORRELATION_STATUS_NOT_EVALUATED,
    CORRELATION_STATUS_MATCH,
    CORRELATION_STATUS_MISMATCH,
    CORRELATION_STATUS_UNKNOWN,
    CORRELATION_STATUS_PARTIAL,
    CORRELATION_STATUS_NOT_APPLICABLE,
)


@dataclass(frozen=True)
class CorrelationInput(JsonModel):
    """One unit of input to a future correlation check.

    ``correlation_schema_version`` MUST equal ``CORRELATION_SCHEMA_VERSION``.
    ``observed`` may be empty (<None>) for expected-only analyses; the primary
    correlation identity lives in ``identity``.
    """

    identity: CorrelationIdentity
    expected: ExpectedState
    correlation_schema_version: str = CORRELATION_SCHEMA_VERSION
    observed: Optional[ObservedState] = None
    live_features: Optional[LiveFeatureWindow] = None
    ml_result: Optional[MLResult] = None
    evidence: List[EvidenceRef] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.correlation_schema_version != CORRELATION_SCHEMA_VERSION:
            raise ValueError(
                f"correlation_schema_version must be "
                f"{CORRELATION_SCHEMA_VERSION!r}, got {self.correlation_schema_version!r}"
            )
        if not isinstance(self.identity, CorrelationIdentity):
            raise ValueError("identity must be a CorrelationIdentity")
        if not isinstance(self.expected, ExpectedState):
            raise ValueError("expected must be an ExpectedState")
        if self.observed is not None and not isinstance(self.observed, ObservedState):
            raise ValueError("observed must be an ObservedState or None")
        if self.live_features is not None and not isinstance(
            self.live_features, LiveFeatureWindow
        ):
            raise ValueError("live_features must be a LiveFeatureWindow or None")
        if self.ml_result is not None and not isinstance(self.ml_result, MLResult):
            raise ValueError("ml_result must be an MLResult or None")
        for ev in self.evidence:
            if not isinstance(ev, EvidenceRef):
                raise ValueError("evidence must contain EvidenceRef objects")

    def to_dict(self) -> Dict[str, Any]:
        data = super().to_dict()
        version = data.pop("correlation_schema_version")
        return {"correlation_schema_version": version, **data}

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CorrelationInput":
        observed = data.get("observed")
        observed_obj = ObservedState.from_dict(observed) if observed else None
        live = data.get("live_features")
        live_obj = LiveFeatureWindow.from_dict(live) if live else None
        ml = data.get("ml_result")
        ml_obj = MLResult.from_dict(ml) if ml else None
        return cls(
            correlation_schema_version=data.get(
                "correlation_schema_version", CORRELATION_SCHEMA_VERSION
            ),
            identity=CorrelationIdentity.from_dict(data["identity"]),
            expected=ExpectedState.from_dict(data["expected"]),
            observed=observed_obj,
            live_features=live_obj,
            ml_result=ml_obj,
            evidence=[EvidenceRef.from_dict(e) for e in data.get("evidence") or []],
        )


@dataclass(frozen=True)
class CorrelationResult(JsonModel):
    """Outcome of an expected-vs-observed comparison.

    Phase 2 created the container with status pinned to ``NOT_EVALUATED``.
    Phase 4 populates it with real, deterministic per-variable outcomes. A
    ``NOT_APPLICABLE`` item means the variable could not semantically be
    compared (e.g. capture filter) and is never upgraded to UNKNOWN/MISMATCH.
    ``not_applicable`` was introduced in phase 4 while keeping the container
    serializable at ``CORRELATION_SCHEMA_VERSION`` (extensions are documented
    in PHASE_4_COMPARISON_ENGINE_REPORT.md).
    """

    identity: CorrelationIdentity
    correlation_schema_version: str = CORRELATION_SCHEMA_VERSION
    status: str = CORRELATION_STATUS_NOT_EVALUATED
    matches: List[Dict[str, Any]] = field(default_factory=list)
    mismatches: List[Dict[str, Any]] = field(default_factory=list)
    unknowns: List[Dict[str, Any]] = field(default_factory=list)
    not_applicable: List[Dict[str, Any]] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.correlation_schema_version != CORRELATION_SCHEMA_VERSION:
            raise ValueError(
                f"correlation_schema_version must be "
                f"{CORRELATION_SCHEMA_VERSION!r}, got {self.correlation_schema_version!r}"
            )
        if not isinstance(self.identity, CorrelationIdentity):
            raise ValueError("identity must be a CorrelationIdentity")
        if self.status not in CORRELATION_STATUSES:
            raise ValueError(
                f"status must be one of {CORRELATION_STATUSES}, got {self.status!r}"
            )
        for name, value in (
            ("matches", self.matches),
            ("mismatches", self.mismatches),
            ("unknowns", self.unknowns),
            ("not_applicable", self.not_applicable),
        ):
            if not isinstance(value, list):
                raise ValueError(f"{name} must be a list")
        if not isinstance(self.metadata, dict):
            raise ValueError("metadata must be a dict")

    def to_dict(self) -> Dict[str, Any]:
        data = super().to_dict()
        version = data.pop("correlation_schema_version")
        return {"correlation_schema_version": version, **data}

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CorrelationResult":
        return cls(
            correlation_schema_version=data.get(
                "correlation_schema_version", CORRELATION_SCHEMA_VERSION
            ),
            identity=CorrelationIdentity.from_dict(data["identity"]),
            status=data.get("status", CORRELATION_STATUS_NOT_EVALUATED),
            matches=list(data.get("matches") or []),
            mismatches=list(data.get("mismatches") or []),
            unknowns=list(data.get("unknowns") or []),
            not_applicable=list(data.get("not_applicable") or []),
            metadata=dict(data.get("metadata") or {}),
        )