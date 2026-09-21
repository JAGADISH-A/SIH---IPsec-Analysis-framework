"""Finding construction and deterministic deduplication.

Section 19 (finding IDs) and section 20 (duplicate findings) of the Phase 6
brief are implemented here:

* finding IDs are deterministic rule-assigned prefixes (never random UUIDs);
* if the same ``finding_id`` repeats for the same variable (only possible when
  multiple identities/variables collide on one ID), a deterministic numeric
  suffix ``-2``, ``-3`` ... is appended in rule order;
* ``deduplicate_findings`` collapses findings whose DEDUP KEY (policy-driven,
  default ``(category, related_variable, source)``) is identical, keeping the
  first (rule-ordered) occurrence — configuration, comparison and ML rules
  that all point at the same underlying issue produce ONE finding.
"""

from typing import Iterable, List, Sequence, Tuple

from .models import RiskFinding
from .policy import RiskPolicy


def make_finding(**kwargs) -> RiskFinding:
    """Thin constructor wrapper (type/constraint validation in the model)."""
    return RiskFinding(**kwargs)


def deduplicate_findings(
    findings: Sequence[RiskFinding],
    policy: RiskPolicy,
) -> List[RiskFinding]:
    """Deterministic deduplication (section 20).

    Rules are evaluated in a fixed order, so the FIRST occurrence of a dedup
    key is the authoritative one. ``dedup_keys`` come from the policy and are
    validated by ``RiskPolicy.__post_init__``.
    """
    keep: List[RiskFinding] = []
    seen: set = set()
    for finding in findings:
        key = _key_of(finding, policy.dedup_keys)
        if key in seen:
            continue
        seen.add(key)
        keep.append(finding)
    return _ensure_unique_ids(keep)


def _key_of(finding: RiskFinding, keys: Iterable[str]) -> Tuple[object, ...]:
    return tuple(getattr(finding, key) for key in keys)


def _ensure_unique_ids(findings: Sequence[RiskFinding]) -> List[RiskFinding]:
    """Deterministic ID suffixing when an ID genuinely repeats (section 19)."""
    if not findings:
        return []
    counts: dict = {}
    result: List[RiskFinding] = []
    for index, finding in enumerate(findings):
        counts[finding.finding_id] = counts.get(finding.finding_id, 0) + 1
    for finding in findings:
        if counts[finding.finding_id] == 1:
            result.append(finding)
            continue
        ordinal = sum(
            1 for prior in result if prior.finding_id == finding.finding_id
        )
        suffix = "" if ordinal == 0 else f"-{ordinal + 1}"
        data = finding.to_dict()
        data["finding_id"] = f"{finding.finding_id}{suffix}"
        result.append(RiskFinding.from_dict(data))
    return result


def findings_with_ids(findings: Sequence[RiskFinding]) -> List[RiskFinding]:
    """Return findings preserving deterministic rule order (no re-sorting)."""
    return list(findings)