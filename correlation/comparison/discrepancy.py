"""Comparison outcome (discrepancy/explanation) structure for Phase 4.

Every comparison item — whether MATCH, MISMATCH, UNKNOWN or NOT_APPLICABLE —
is a ``ComparisonOutcome``. A MISMATCH is never produced without an
explainable reason; an UNKNOWN always carries a specific reason
(section 20/21 of the Phase 4 brief).

Required fields (per the brief):

    variable, expected_value, observed_value, status, reason,
    identity, evidence_refs, comparison_rule
"""

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence, Tuple

from ..models import EvidenceRef
from ..models.correlation import (
    CORRELATION_STATUS_MATCH,
    CORRELATION_STATUS_MISMATCH,
    CORRELATION_STATUS_NOT_APPLICABLE,
    CORRELATION_STATUS_UNKNOWN,
)

COMPARISON_STATUSES = (
    CORRELATION_STATUS_MATCH,
    CORRELATION_STATUS_MISMATCH,
    CORRELATION_STATUS_UNKNOWN,
    CORRELATION_STATUS_NOT_APPLICABLE,
)


@dataclass(frozen=True)
class ComparisonOutcome:
    """One deterministic, explainable comparison item.

    ``identity`` is stored as the serialized ``CorrelationIdentity`` dict so the
    outcome is self-contained. ``evidence_refs`` preserve the original
    ``EvidenceRef`` objects (serialized as their canonical dicts on output).
    """

    variable: str
    comparison_rule: str
    status: str
    reason: str
    expected_value: Any = None
    observed_value: Any = None
    identity: Optional[Dict[str, Any]] = None
    evidence_refs: Tuple[EvidenceRef, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.variable, str) or not self.variable.strip():
            raise ValueError("ComparisonOutcome.variable must be a non-empty string")
        if not isinstance(self.comparison_rule, str) or not self.comparison_rule.strip():
            raise ValueError("comparison_rule must be a non-empty string")
        if not isinstance(self.reason, str) or not self.reason.strip():
            raise ValueError("ComparisonOutcome.reason must be a non-empty string")
        if self.status not in COMPARISON_STATUSES:
            raise ValueError(
                f"ComparisonOutcome.status must be one of {COMPARISON_STATUSES}, "
                f"got {self.status!r}"
            )
        if self.identity is not None and not isinstance(self.identity, dict):
            raise ValueError("ComparisonOutcome.identity must be a dict or None")
        if not isinstance(self.evidence_refs, (tuple, list)):
            raise ValueError("evidence_refs must be a tuple/list of EvidenceRef")
        for ev in self.evidence_refs:
            if not isinstance(ev, EvidenceRef):
                raise ValueError("evidence_refs must contain EvidenceRef objects")

    def to_dict(self) -> Dict[str, Any]:
        ordered = [
            ("variable", self.variable),
            ("status", self.status),
            ("comparison_rule", self.comparison_rule),
            ("reason", self.reason),
            ("expected_value", self.expected_value),
            ("observed_value", self.observed_value),
            ("identity", self.identity),
            ("evidence_refs", [ev.to_dict() for ev in self.evidence_refs]),
        ]
        return {key: value for key, value in ordered if value is not None or key in (
            "expected_value", "observed_value",
        )}

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ComparisonOutcome":
        return cls(
            variable=data["variable"],
            comparison_rule=data["comparison_rule"],
            status=data["status"],
            reason=data["reason"],
            expected_value=data.get("expected_value"),
            observed_value=data.get("observed_value"),
            identity=data.get("identity"),
            evidence_refs=tuple(
                EvidenceRef.from_dict(ev) for ev in data.get("evidence_refs") or []
            ),
        )


def bucket_outcomes(
    outcomes: Sequence[ComparisonOutcome],
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]],
            List[Dict[str, Any]]]:
    """Split outcomes into (matches, mismatches, unknowns, not_applicable)."""
    matches, mismatches, unknowns, not_applicable = [], [], [], []
    for outcome in outcomes:
        payload = outcome.to_dict()
        if outcome.status == CORRELATION_STATUS_MATCH:
            matches.append(payload)
        elif outcome.status == CORRELATION_STATUS_MISMATCH:
            mismatches.append(payload)
        elif outcome.status == CORRELATION_STATUS_UNKNOWN:
            unknowns.append(payload)
        elif outcome.status == CORRELATION_STATUS_NOT_APPLICABLE:
            not_applicable.append(payload)
    return matches, mismatches, unknowns, not_applicable