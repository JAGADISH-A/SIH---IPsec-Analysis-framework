"""Area 7 -- threat matrix.

A presentation of findings as a threat matrix. The derivation rule is the
brief's own: **derived from findings only**. This module invents no threat,
no severity and no impact of its own -- it maps what the engines already
produced onto the threat vocabulary, and every cell says where it came from.

Two finding streams feed the matrix:

* **risk findings** (``RiskAssessment.findings``) -- severity is copied
  verbatim from the finding and is never recomputed here;
* **metadata exposure findings** (``MetadataExposure.findings``) -- these are
  observation-level statements that deliberately carry no severity and no
  score, so their ``severity`` cell is ``null`` with a ``severity_source``
  that says why. Inventing an INFO here would be exactly the parallel
  implementation the brief forbids.

Recommendations are never written by hand: they are read out of
``correlation.response.rules.RESPONSE_RULE_TRACEABILITY``, the registry the
response planner itself consumes, so the matrix and the planner cannot drift
apart. When no response rule is registered for a finding rule, the cell says
so instead of guessing.
"""

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence, Tuple

from ..risk.models import (
    CATEGORY_CONFIGURATION_MISMATCH,
    CATEGORY_CONFIGURATION_WEAKNESS,
    CATEGORY_INSUFFICIENT_EVIDENCE,
    CATEGORY_ML_CLASSIFICATION_DISAGREEMENT,
    CATEGORY_ML_TRAFFIC_ANOMALY,
    CATEGORY_OBSERVED_MISMATCH,
    CATEGORY_PROTOCOL_ANOMALY,
    RiskFinding,
)
from ..response.rules import RESPONSE_RULE_TRACEABILITY
from .metadata import MetadataExposure
from .states import STATE_ASSESSED

# ---- threat vocabulary -------------------------------------------------------
THREAT_CRYPTOGRAPHIC = "Cryptographic weakness"
THREAT_CONFIGURATION = "Configuration weakness"
THREAT_PROTOCOL = "Protocol weakness"
THREAT_TRAFFIC = "Traffic anomaly"
THREAT_REPLAY = "Replay anomaly"
THREAT_METADATA = "Metadata exposure"
THREAT_EVIDENCE_GAP = "Evidence gap"
THREAT_UNCLASSIFIED = "Unclassified threat"

#: Every threat category the matrix may report, in presentation order. The
#: first six are the brief's example categories; the last two exist because
#: findings do (an evidence gap is a real condition, and an unknown rule must
#: never be silently dropped).
THREAT_CATEGORIES: Tuple[str, ...] = (
    THREAT_CRYPTOGRAPHIC,
    THREAT_CONFIGURATION,
    THREAT_PROTOCOL,
    THREAT_TRAFFIC,
    THREAT_REPLAY,
    THREAT_METADATA,
    THREAT_EVIDENCE_GAP,
    THREAT_UNCLASSIFIED,
)

FINDING_SOURCE_RISK_ENGINE = "risk_engine"
FINDING_SOURCE_METADATA_EXPOSURE = "metadata_exposure"

#: Threat text per category. Deterministic prose, keyed by category rather
#: than by finding, so the same category always reads the same way.
_IMPACT: Dict[str, str] = {
    THREAT_CRYPTOGRAPHIC: (
        "Traffic carried under the affected security association is protected "
        "by weaker cryptographic material than the plan requires, so captured "
        "ciphertext is cheaper to attack and any key compromise reaches "
        "further back in time."
    ),
    THREAT_CONFIGURATION: (
        "The deployed security association does not carry the protection the "
        "plan assumes, so the tunnel runs with a posture the operator did not "
        "intend to approve."
    ),
    THREAT_PROTOCOL: (
        "Behaviour outside the documented expectations of the protocol "
        "weakens a guarantee the tunnel is otherwise assumed to provide, for "
        "example a channel the plan never asked for."
    ),
    THREAT_TRAFFIC: (
        "Observed traffic does not match the expected profile, which is "
        "consistent with misconfiguration, misuse or a condition the model "
        "was not trained to name; it is not, by itself, an attack."
    ),
    THREAT_REPLAY: (
        "A duplicated or replayed sequence number reaches a receiver whose "
        "replay window would normally discard it. If the window does not "
        "discard it, already-delivered traffic is delivered again."
    ),
    THREAT_METADATA: (
        "An on-path observer recovers who talks, when, how much and under "
        "which security association from cleartext headers and recorded "
        "counters, without needing to defeat the cipher."
    ),
    THREAT_EVIDENCE_GAP: (
        "The evidence needed to decide the question is missing, so neither "
        "compliance nor a violation can be claimed. The gap itself is the "
        "risk: the operator cannot see the condition either way."
    ),
    THREAT_UNCLASSIFIED: (
        "The finding did not match any registered threat mapping. It is "
        "reported rather than hidden, and the mapping needs to be extended."
    ),
}

#: ``finding.rule_id`` prefixes that identify the crypto-property rules
#: before category lookup, so a crypto finding raised through any category is
#: still reported as a cryptographic weakness.
_CRYPTO_RULE_PREFIXES: Tuple[str, ...] = (
    "esp.encryption",
    "esp.integrity",
    "esp.dh_group",
    "esp.pfs",
    "ike.encryption",
    "ike.integrity",
    "ike.dh_group",
    "ike.version",
    "ah.integrity",
)

_REPLAY_RULE_PREFIX = "replay."
_ML_RULE_PREFIX = "ml."
_EVIDENCE_RULE_PREFIX = "evidence."

_CATEGORY_THREAT: Dict[str, str] = {
    CATEGORY_CONFIGURATION_WEAKNESS: THREAT_CONFIGURATION,
    CATEGORY_CONFIGURATION_MISMATCH: THREAT_CONFIGURATION,
    CATEGORY_OBSERVED_MISMATCH: THREAT_CONFIGURATION,
    CATEGORY_PROTOCOL_ANOMALY: THREAT_PROTOCOL,
    CATEGORY_ML_TRAFFIC_ANOMALY: THREAT_TRAFFIC,
    CATEGORY_ML_CLASSIFICATION_DISAGREEMENT: THREAT_TRAFFIC,
    CATEGORY_INSUFFICIENT_EVIDENCE: THREAT_EVIDENCE_GAP,
}


@dataclass(frozen=True)
class ThreatEntry:
    """One matrix row: one finding, mapped onto the threat vocabulary."""

    finding: str
    threat: str
    severity: Optional[str]
    evidence: Dict[str, Any]
    impact: str
    recommendation: Dict[str, Any]
    category: str
    rule_id: str
    title: str
    finding_source: str
    severity_source: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding": self.finding,
            "threat": self.threat,
            "severity": self.severity,
            "evidence": dict(self.evidence),
            "impact": self.impact,
            "recommendation": dict(self.recommendation),
            "category": self.category,
            "rule_id": self.rule_id,
            "title": self.title,
            "finding_source": self.finding_source,
            "severity_source": self.severity_source,
        }


@dataclass(frozen=True)
class ThreatMatrix:
    """The complete threat-matrix product for one assessment."""

    state: str
    reason: str
    source: str
    entries: tuple = ()
    categories: tuple = ()
    limitations: tuple = ()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "state": self.state,
            "reason": self.reason,
            "source": self.source,
            "entries": [entry.to_dict() for entry in self.entries],
            "categories": [dict(item) for item in self.categories],
            "entry_count": len(self.entries),
            "limitations": list(self.limitations),
        }


def threat_category_for(rule_id: str, category: str) -> str:
    """Deterministic rule id + finding category -> threat category."""
    if rule_id.startswith(_REPLAY_RULE_PREFIX):
        return THREAT_REPLAY
    if rule_id.startswith(_CRYPTO_RULE_PREFIXES):
        return THREAT_CRYPTOGRAPHIC
    if rule_id.startswith(_ML_RULE_PREFIX):
        return THREAT_TRAFFIC
    if rule_id.startswith(_EVIDENCE_RULE_PREFIX):
        return THREAT_EVIDENCE_GAP
    return _CATEGORY_THREAT.get(category, THREAT_UNCLASSIFIED)


def _recommendation_for(rule_id: str) -> Dict[str, Any]:
    """Read the response registry; never author an action here."""
    entry = RESPONSE_RULE_TRACEABILITY.get(rule_id)
    if entry is None:
        return {
            "text": (
                "No response rule is registered for this finding rule, so the "
                "response planner produces no action for it. The finding is "
                "reported as-is for analyst triage."
            ),
            "source": "none_registered",
            "response_rule_id": None,
            "action": None,
            "priority": None,
            "authorization_requirement": None,
            "approval_requirement": None,
            "policy_dependency": None,
            "limitations": [],
        }
    action = entry.get("action")
    priority = entry.get("priority")
    approval = entry.get("approval_requirement")
    authorization = entry.get("authorization_requirement")
    text = (
        f"Response rule {entry.get('rule_id')} prescribes {action} at "
        f"{priority} priority, {authorization} authorization, approval "
        f"{approval}. Read the registry for the full condition and its "
        f"limitations; this matrix quotes it and does not restate the policy."
    )
    return {
        "text": text,
        "source": "response_policy",
        "response_rule_id": entry.get("rule_id"),
        "action": action,
        "priority": priority,
        "authorization_requirement": authorization,
        "approval_requirement": approval,
        "policy_dependency": entry.get("policy_dependency"),
        "limitations": list(entry.get("limitations") or ()),
    }


def _risk_evidence(finding: RiskFinding) -> Dict[str, Any]:
    return {
        "reason": finding.reason,
        "condition": finding.condition,
        "source": finding.source,
        "evidence_type": finding.evidence_type,
        "expected_value": finding.expected_value,
        "observed_value": finding.observed_value,
        "refs": [ref.to_dict() for ref in finding.evidence_refs],
    }


def _metadata_evidence(item: Dict[str, Any]) -> Dict[str, Any]:
    evidence = item.get("evidence") or []
    first = evidence[0] if evidence else {}
    return {
        "reason": item.get("reason"),
        "condition": f"metadata dimension {item.get('dimension')!r} is "
                     f"{item.get('exposure')}",
        "source": first.get("source"),
        "evidence_type": "observation",
        "expected_value": None,
        "observed_value": first.get("value"),
        "refs": list(evidence),
    }


def build_threat_matrix(
    findings: Sequence[RiskFinding] = (),
    *,
    metadata: Optional[MetadataExposure] = None,
    source: str = "risk engine findings + metadata exposure findings",
) -> ThreatMatrix:
    """Map every finding onto exactly one threat matrix row."""
    entries: List[ThreatEntry] = []
    counts: Dict[str, int] = {name: 0 for name in THREAT_CATEGORIES}

    for finding in findings:
        threat = threat_category_for(finding.rule_id, finding.category)
        counts[threat] = counts.get(threat, 0) + 1
        entries.append(
            ThreatEntry(
                finding=finding.finding_id,
                threat=threat,
                severity=finding.severity,
                evidence=_risk_evidence(finding),
                impact=_IMPACT[threat],
                recommendation=_recommendation_for(finding.rule_id),
                category=finding.category,
                rule_id=finding.rule_id,
                title=finding.title,
                finding_source=FINDING_SOURCE_RISK_ENGINE,
                severity_source=(
                    "copied verbatim from the risk finding; the threat matrix "
                    "never assigns or recomputes a severity"
                ),
            )
        )

    metadata_findings: List[Dict[str, Any]] = list(
        metadata.findings if metadata is not None else ()
    )
    for item in metadata_findings:
        counts[THREAT_METADATA] = counts.get(THREAT_METADATA, 0) + 1
        entries.append(
            ThreatEntry(
                finding=str(item.get("dimension")),
                threat=THREAT_METADATA,
                severity=None,
                evidence=_metadata_evidence(item),
                impact=_IMPACT[THREAT_METADATA],
                recommendation={
                    "text": (
                        "No response rule is registered for metadata "
                        "exposure: it is a property of the capture, not a "
                        "defect in the tunnel. The documented remedy is "
                        "collection-side (capture point, span port, "
                        "encryption of addressing where the deployment "
                        "allows it), which this backend reports but does not "
                        "prescribe."
                    ),
                    "source": "none_registered",
                    "response_rule_id": None,
                    "action": None,
                    "priority": None,
                    "authorization_requirement": None,
                    "approval_requirement": None,
                    "policy_dependency": None,
                    "limitations": [],
                },
                category=str(item.get("dimension")),
                rule_id=f"metadata.{item.get('dimension')}",
                title=str(item.get("finding")),
                finding_source=FINDING_SOURCE_METADATA_EXPOSURE,
                severity_source=(
                    "null by design: an observation-level metadata finding "
                    "carries no severity and no score, because severity and "
                    "score exist only in the risk engine"
                ),
            )
        )

    total = len(list(findings)) + len(metadata_findings)
    if entries and len(entries) != total:
        raise AssertionError(
            f"threat matrix rows ({len(entries)}) must equal findings ({total})"
        )

    categories = [
        {
            "category": name,
            "entry_count": counts.get(name, 0),
            "present": counts.get(name, 0) > 0,
            "impact": _IMPACT[name],
        }
        for name in THREAT_CATEGORIES
    ]

    present = [name for name in THREAT_CATEGORIES if counts.get(name, 0)]
    return ThreatMatrix(
        state=STATE_ASSESSED,
        reason=(
            f"{len(entries)} threat matrix row(s) derived from "
            f"{len(list(findings))} risk finding(s) and "
            f"{len(metadata_findings)} metadata exposure finding(s), covering "
            f"{len(present)} threat "
            f"{'category' if len(present) == 1 else 'categories'}: "
            f"{', '.join(present) if present else 'none'}."
            if entries
            else "No finding was produced for this assessment, so the threat "
                 "matrix is empty rather than populated with generic threats."
        ),
        source=source,
        entries=tuple(entries),
        categories=tuple(categories),
        limitations=(
            "Derived from findings only: no threat appears here that no "
            "finding produced, and an empty matrix means 'no finding', not "
            "'no risk'.",
            "Severity cells are copied, never computed, by this module.",
            "Impact text is a deterministic mapping from the threat "
            "category; it explains the consequence of the finding and does "
            "not add a second score.",
            "Recommendations are quoted from the response rule registry; "
            "when no rule is registered the cell says so instead of "
            "prescribing an action the policy does not authorise.",
        ),
    )
