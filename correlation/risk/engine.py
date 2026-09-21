"""Risk Assessment & Security Scoring Engine (Phase 6).

The engine is a deterministic, read-only orchestrator:

    ExpectedState ─────────────┐
    ObservedState  ────────────┤-> RiskEngine.assess -> RiskAssessment
    CorrelationResult          │     (findings + severity + score)
    MLResult (optional)        │
    evidence_refs (optional)   │

Pipeline: identity safety -> rule evaluation (fixed order) -> deterministic
deduplication -> documented scoring -> deterministic RiskAssessment.

Guarantees enforced here (Phase 6 brief sections 9, 17, 23, 25, 26, 27):

* deterministic: no randomness, no current-time dependence, no network calls;
* identity safety: expected and correlation identities must be compatible
  (``IdentityMismatchError``), mirroring the Phase-4 engine;
* posture is CONSUMED (``expected.security_posture``) with provenance and is
  NEVER recomputed and NEVER the source of an independent score contribution
  (sections 10, 23);
* ML output is consumed as model-derived evidence only (never overrides
  authoritative observation; never a protocol observation);
* every finding records the policy version and a rule id (sections 26-27).
"""

from dataclasses import dataclass
from typing import Any, Dict, Optional, Sequence, Union

from ..adapters.expected_state import MaterializedExpectedState
from ..comparison.engine import IdentityMismatchError, assert_identity_compatible
from ..models import (
    CorrelationIdentity,
    CorrelationResult,
    EvidenceRef,
    ExpectedState,
    MLResult,
    ObservedState,
)
from .findings import deduplicate_findings
from .models import (
    RISK_ENGINE_VERSION,
    RISK_SCHEMA_VERSION,
    RiskAssessment,
    RiskFinding,
)
from .policy import RiskPolicy
from .rules import RiskRuleContext, run_rules
from .scoring import score_findings

POSTURE_PROVENANCE = (
    "posture_of_config (controller/dataset_planner.py): authoritative band "
    "consumed verbatim, never recomputed by the risk engine"
)


def _resolve_expected(
    expected: Union[ExpectedState, MaterializedExpectedState],
    correlation: CorrelationResult,
) -> tuple:
    if isinstance(expected, ExpectedState):
        # An ExpectedState has no identity of its own; the correlation result
        # produced from it is the identity carrier (mirrors Phase-4 engine).
        return expected, correlation.identity
    if isinstance(expected, MaterializedExpectedState):
        return expected.expected, expected.identity
    raise TypeError(
        "expected must be an ExpectedState or a MaterializedExpectedState"
    )


def _resolve_ml_result(
    correlation: CorrelationResult,
    ml_result: Optional[MLResult],
) -> Optional[MLResult]:
    if ml_result is not None:
        if not isinstance(ml_result, MLResult):
            raise TypeError("ml_result must be an MLResult or None")
        return ml_result
    stored = correlation.metadata.get("ml", {}).get("ml_result")
    if not stored:
        return None
    return MLResult.from_dict(stored)


def _coerce_evidence(evidence_refs: Sequence) -> tuple:
    result = []
    for ref in evidence_refs:
        if not isinstance(ref, EvidenceRef):
            raise TypeError("evidence_refs must contain EvidenceRef objects")
        result.append(ref)
    return tuple(result)


@dataclass(frozen=True)
class RiskEngine:
    """Deterministic risk assessment engine (one policy instance)."""

    policy: RiskPolicy = RiskPolicy.default()

    def __post_init__(self) -> None:
        if not isinstance(self.policy, RiskPolicy):
            raise TypeError("policy must be a RiskPolicy")

    def assess(
        self,
        expected: Union[ExpectedState, MaterializedExpectedState],
        observed: Optional[ObservedState] = None,
        *,
        correlation: CorrelationResult,
        ml_result: Optional[MLResult] = None,
        evidence_refs: Sequence = (),
    ) -> RiskAssessment:
        """Assess one correlation and return a deterministic RiskAssessment.

        ``expected`` may be an ``ExpectedState`` (identity carried by
        ``correlation.identity``) or a ``MaterializedExpectedState`` (identity
        carried by the materialized object and verified against the
        correlation). ``correlation`` is required.
        """
        if not isinstance(correlation, CorrelationResult):
            raise TypeError("correlation must be a CorrelationResult")
        if observed is not None and not isinstance(observed, ObservedState):
            raise TypeError("observed must be an ObservedState or None")

        expected_state, expected_identity = _resolve_expected(expected, correlation)
        assert_identity_compatible(expected_identity, correlation.identity)

        ml = _resolve_ml_result(correlation, ml_result)
        evidence = _coerce_evidence(evidence_refs)

        context = RiskRuleContext(
            expected=expected_state,
            correlation=correlation,
            expected_identity=expected_identity,
            policy=self.policy,
            observed=observed,
            ml_result=ml,
            evidence_refs=evidence,
        )
        raw_findings = run_rules(context)
        findings = deduplicate_findings(raw_findings, self.policy)

        score_result = score_findings(findings, self.policy)

        metadata = self._build_metadata(
            expected_state, correlation, ml, findings, score_result
        )
        return RiskAssessment(
            schema_version=RISK_SCHEMA_VERSION,
            risk_engine_version=RISK_ENGINE_VERSION,
            risk_policy_version=self.policy.policy_version,
            identity=expected_identity,
            overall_score=score_result.score,
            severity=score_result.severity,
            findings=tuple(findings),
            evidence_refs=evidence,
            metadata=metadata,
        )

    def _build_metadata(
        self,
        expected_state: ExpectedState,
        correlation: CorrelationResult,
        ml: Optional[MLResult],
        findings: Sequence[RiskFinding],
        score_result,
    ) -> Dict[str, Any]:
        posture = expected_state.security_posture
        return {
            "posture_context": {
                "authoritative_posture": posture,
                "posture_provenance": POSTURE_PROVENANCE,
                "posture_is_context_only": True,
                "posture_not_recomputed": True,
            },
            "score_detail": dict(score_result.to_dict()),
            "ml": {
                "ml_present": ml is not None,
                "model_available": ml is not None,
                "ml_evaluated": bool(correlation.metadata.get("ml_evaluated", ml is not None)),
                "model_version": ml.model_version if ml is not None else None,
                "ml_is_evidence_only": True,
                "ml_never_protocol_observation": True,
            },
            "expected_configuration": {
                "configuration_id": expected_state.configuration_id,
            },
            "evidence_policy": {
                "fabricates_references": False,
                "note": (
                    "evidence references only from the assess call or from "
                    "correlation outcomes; no PCAP/audit references are invented"
                ),
            },
            "unknown_handling": {
                "unknown_is_vulnerability": False,
                "not_applicable_is_vulnerability": False,
                "missing_ml_is_risk": False,
                "enable_insufficient_evidence": bool(
                    self.policy.unknown_handling.get("enable_insufficient_evidence")
                ),
            },
            "risk_policy": dict(self.policy.to_dict()),
            "rules_executed": list(self.policy.rules_enabled_for()),
        }