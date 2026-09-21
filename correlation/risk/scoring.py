"""Risk score calculation (Phase 6).

Documented, centralized aggregation algorithm (sections 8, 21, 22). No magic
numbers live in the engine; all constants are in ``policy.RiskPolicy``:

* each enabled finding contributes ``policy.weights[severity]`` points
  (INFO=0, LOW=6, MEDIUM=12, HIGH=25, CRITICAL=40);
* per-category cap (``policy.category_cap`` = 30) bounds how much a single
  finding theme may contribute, so no one category alone can reach CRITICAL;
* a global cap (``policy.score_cap`` = 100) bounds the total;
* duplicates are removed BEFORE scoring (``findings.deduplicate_findings``);
* the resulting score maps to exactly one severity through the disjoint
  ``policy.severity_bands``.

The output is deterministic: identical inputs (ExpectedState, ObservedState,
CorrelationResult, MLResult, RiskPolicy) produce identical scores, severities
and findings for every input set (section 9).
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Sequence, Tuple

from .models import RiskFinding
from .policy import RiskPolicy


@dataclass(frozen=True)
class ScoreResult:
    """Deterministic outcome of scoring (for report and metadata capture)."""

    score: int
    severity: str
    band: Tuple[str, int, int]
    raw_sum: int
    contributions: Tuple[Dict[str, Any], ...]
    per_category_totals: Tuple[Tuple[str, int], ...]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "score": self.score,
            "severity": self.severity,
            "severity_band": list(self.band),
            "raw_sum": self.raw_sum,
            "contributions": [dict(c) for c in self.contributions],
            "per_category_totals": [list(item) for item in self.per_category_totals],
        }


def score_findings(
    findings: Sequence[RiskFinding],
    policy: RiskPolicy,
) -> ScoreResult:
    """Compute (score, severity, breakdown) from deduplicated findings."""
    category_totals: Dict[str, int] = {}
    contributions: List[Dict[str, Any]] = []
    running = 0
    raw_sum = 0
    for finding in findings:
        weight = policy.weight_of(finding.severity)
        raw_sum += weight
        category_total = category_totals.get(finding.category, 0)
        allowed = max(0, policy.category_cap - category_total)
        added = min(weight, allowed)
        category_totals[finding.category] = category_total + added
        running += added
        contributions.append(
            {
                "finding_id": finding.finding_id,
                "rule_id": finding.rule_id,
                "category": finding.category,
                "severity": finding.severity,
                "weight": weight,
                "added": added,
            }
        )
        if running >= policy.score_cap:
            running = policy.score_cap
            break
    severity, low, high = policy.band_for(running)
    return ScoreResult(
        score=running,
        severity=severity,
        band=(severity, low, high),
        raw_sum=raw_sum,
        contributions=tuple(contributions),
        per_category_totals=tuple(
            sorted(category_totals.items(), key=lambda item: item[0])
        ),
    )


def band_for_score(policy: RiskPolicy, score: int) -> Tuple[str, int, int]:
    """Convenience: exactly one severity per score (section 22)."""
    return policy.band_for(score)