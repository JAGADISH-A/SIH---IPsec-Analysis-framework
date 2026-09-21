"""Versioned RiskPolicy for the Phase 6 risk engine.

The policy is the SINGLE source of truth for every tunable number and toggle:

* severity contribution weights,
* score -> severity bands (disjoint, exhaustive -> each score maps to exactly
  one severity, section 22),
* per-category contribution cap and the global score cap,
* deduplication rules (section 20),
* ML handling (severity ceilings, no anomaly-score-to-risk conversion),
* unknown handling (INSUFFICIENT_EVIDENCE only when explicitly enabled).

Every constant below is documented against the AUTHORITATIVE SIH security
semantics (``controller/dataset_planner.py::posture_of_config``, Phase 1):

    posture score = cipher-family(4|2) + key(2|1) + PFS(2|0) + DH(4/3/1|0)
    STRONG >= 11, GOOD >= 9, MEDIUM >= 6, WEAK >= 4, WORST == 3

The per-rule severities are derived, not invented: a rule fires only when the
authoritative scoring treats the underlying field as a *reduced* contribution,
and the severity reflects the corresponding posture-point deficit (see
PHASE_6_RISK_RULE_TRACEABILITY.md for the derivation table).

No values are hard-coded inside the engine; ``RiskPolicy.default()`` is the
versioned runtime configuration.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, Optional, Sequence, Tuple

from .models import (
    SEVERITIES,
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    SEVERITY_INFO,
    SEVERITY_LOW,
    SEVERITY_MEDIUM,
)

DEFAULT_RISK_POLICY_VERSION = "risk-policy-v1"

# Finding severity -> score contribution. Derived from the authoritative
# posture deficit per rule and documented in the rule traceability report:
#
#   LOW      6      informational / planning-level observations
#   MEDIUM  12      posture deficit of 2 points (CBC family, PFS off)
#   HIGH    25      confirmed authoritative runtime contradiction
#                   (protection model change, expected protection absent)
#   CRITICAL 40     reserved for the aggregate band; no single finding is ever
#                   CRITICAL by itself.
DEFAULT_WEIGHTS = {
    SEVERITY_INFO: 0,
    SEVERITY_LOW: 6,
    SEVERITY_MEDIUM: 12,
    SEVERITY_HIGH: 25,
    SEVERITY_CRITICAL: 40,
}

# Score -> severity bands (disjoint, exhaustive). Every integer score in
# [0, 100] maps to exactly one severity.
DEFAULT_SEVERITY_BANDS: Tuple[Tuple[str, int, int], ...] = (
    (SEVERITY_CRITICAL, 40, 100),
    (SEVERITY_HIGH, 20, 39),
    (SEVERITY_MEDIUM, 10, 19),
    (SEVERITY_LOW, 1, 9),
    (SEVERITY_INFO, 0, 0),
)

DEFAULT_SCORE_CAP = 100
# No single finding category may contribute more than 30 of 100 points.
# Confirmed runtime contradictions live in DIFFERENT categories than
# configuration weaknesses, so compounding across categories can legitimately
# reach CRITICAL, while any single theme is bounded.
DEFAULT_CATEGORY_CAP = 30

DEFAULT_DEDUP_KEYS = ("category", "related_variable", "source")

# ML handling (sections 14-15): ML output is model-derived evidence, never a
# confirmed attack; an anomaly verdict or classification disagreement gets at
# most the LOW informational severity and the anomaly score is never converted
# directly into a risk contribution.
DEFAULT_ML_HANDLING = {
    "anomaly_severity": SEVERITY_LOW,
    "classification_disagreement_severity": SEVERITY_LOW,
    "max_ml_severity": SEVERITY_LOW,
    "anomaly_score_conversion": "none",
}

# Unknown handling (section 16): UNKNOWN / NOT_APPLICABLE / missing values are
# never vulnerabilities. INSUFFICIENT_EVIDENCE findings are produced ONLY when
# a policy explicitly enables them (off by default).
DEFAULT_UNKNOWN_HANDLING = {
    "enable_insufficient_evidence": False,
    "unknown_is_vulnerability": False,
    "not_applicable_is_vulnerability": False,
    "missing_ml_is_risk": False,
}


def validate_severity_bands(
    bands: Sequence[Tuple[str, int, int]]
) -> Tuple[Tuple[str, int, int], ...]:
    result = tuple(sorted(bands, key=lambda band: band[2], reverse=True))
    if not result:
        raise ValueError("severity_bands must not be empty")
    seen_severity: set = set()
    previous_high = result[0][2]
    for severity, low, high in result:
        if severity not in SEVERITIES or severity in seen_severity:
            raise ValueError(f"invalid or duplicate severity in bands: {severity!r}")
        seen_severity.add(severity)
        if not isinstance(low, int) or not isinstance(high, int) or low < 0 or high > 100:
            raise ValueError(f"invalid band range for {severity}: [{low}, {high}]")
        if low > high:
            raise ValueError(f"band range inverted for {severity}: [{low}, {high}]")
        if high > previous_high:
            raise ValueError("bands must occupy disjoint, sorted ranges")
        previous_high = low - 1
    if result[-1][0] != SEVERITY_INFO or result[-1][1] != 0 or result[-1][2] != 0:
        raise ValueError("the lowest band must be INFO == 0")
    return result


@dataclass(frozen=True)
class RiskPolicy:
    """Versioned, immutable risk policy (the engine never hard-codes numbers)."""

    policy_version: str
    weights: Dict[str, int]
    severity_bands: Tuple[Tuple[str, int, int], ...]
    score_cap: int = DEFAULT_SCORE_CAP
    category_cap: int = DEFAULT_CATEGORY_CAP
    dedup_keys: Tuple[str, ...] = DEFAULT_DEDUP_KEYS
    ml_handling: Dict[str, Any] = field(default_factory=lambda: dict(DEFAULT_ML_HANDLING))
    unknown_handling: Dict[str, Any] = field(
        default_factory=lambda: dict(DEFAULT_UNKNOWN_HANDLING)
    )
    rules_enabled: Tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        if not isinstance(self.policy_version, str) or not self.policy_version.strip():
            raise ValueError("policy_version must be a non-empty string")
        for severity in SEVERITIES:
            weight = self.weights.get(severity)
            if weight is None or not isinstance(weight, int) or weight < 0:
                raise ValueError(f"weights must define a non-negative integer for {severity}")
        object.__setattr__(
            self, "severity_bands", validate_severity_bands(self.severity_bands)
        )
        if not isinstance(self.score_cap, int) or self.score_cap <= 0 or self.score_cap > 100:
            raise ValueError("score_cap must be an integer in [1, 100]")
        if not isinstance(self.category_cap, int) or self.category_cap <= 0:
            raise ValueError("category_cap must be a positive integer")
        if not isinstance(self.dedup_keys, (tuple, list)) or not self.dedup_keys:
            raise ValueError("dedup_keys must be a non-empty tuple/list")
        for key in self.dedup_keys:
            if key not in ("category", "related_variable", "source", "rule_id"):
                raise ValueError(f"unsupported dedup key: {key!r}")
        if not isinstance(self.ml_handling, dict) or not isinstance(self.unknown_handling, dict):
            raise ValueError("ml_handling and unknown_handling must be dicts")
        if not isinstance(self.rules_enabled, (tuple, list)):
            raise ValueError("rules_enabled must be a tuple/list")

    def weight_of(self, severity: str) -> int:
        weight = self.weights.get(severity)
        if weight is None:
            raise ValueError(f"no weight configured for severity {severity!r}")
        return weight

    def band_for(self, score: int) -> Tuple[str, int, int]:
        """Map one score to exactly one (severity, low, high) band (section 22)."""
        if not isinstance(score, int) or score < 0 or score > 100:
            raise ValueError(f"score must be an int in [0, 100], got {score!r}")
        for severity, low, high in self.severity_bands:
            if low <= score <= high:
                return (severity, low, high)
        raise ValueError(f"no severity band covers score {score}")

    def rules_enabled_for(self) -> Tuple[str, ...]:
        return self.rules_enabled or ALL_RULES

    @classmethod
    def default(cls) -> "RiskPolicy":
        return cls(
            policy_version=DEFAULT_RISK_POLICY_VERSION,
            weights=dict(DEFAULT_WEIGHTS),
            severity_bands=DEFAULT_SEVERITY_BANDS,
        )

    def with_unknown_handling(self, **overrides: Any) -> "RiskPolicy":
        merged = dict(self.unknown_handling)
        merged.update(overrides)
        return RiskPolicy(
            policy_version=self.policy_version,
            weights=self.weights,
            severity_bands=self.severity_bands,
            score_cap=self.score_cap,
            category_cap=self.category_cap,
            dedup_keys=self.dedup_keys,
            ml_handling=self.ml_handling,
            unknown_handling=merged,
            rules_enabled=self.rules_enabled,
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "policy_version": self.policy_version,
            "weights": dict(self.weights),
            "severity_bands": [list(band) for band in self.severity_bands],
            "score_cap": self.score_cap,
            "category_cap": self.category_cap,
            "dedup_keys": list(self.dedup_keys),
            "ml_handling": dict(self.ml_handling),
            "unknown_handling": dict(self.unknown_handling),
            "rules_enabled": list(self.rules_enabled),
        }


# default rule execution order (kept here to avoid a policy->rules import cycle)
ALL_RULES = (
    "esp.pfs.disabled",
    "esp.encryption.cbc",
    "esp.dh_group.weak",
    "correlation.mismatch",
    "ml.anomaly",
    "ml.classification.disagreement",
    "evidence.insufficient",
)


def default_policy_dict() -> Dict[str, Any]:
    return RiskPolicy.default().to_dict()