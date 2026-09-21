"""Deterministic risk rules (Phase 6).

Every rule is registered in ``RULE_REGISTRY`` under a stable rule_id and
described in ``RULE_TRACEABILITY`` (the source of truth mirrored in
PHASE_6_RISK_RULE_TRACEABILITY.md). Rules consume only the Phase 3/4/5 domain
objects and never fabricate evidence.

Security semantics are DERIVED from the authoritative SIH configuration model
(``D:\\sihipsec\\controller\\dataset_planner.py::posture_of_config`` and
``controller\\validate.py``), NOT invented:

    posture score = cipher-family(4|2) + key(2|1) + PFS(2|0) + DH(4/3/1|0)
    STRONG >= 11, GOOD >= 9, MEDIUM >= 6, WEAK >= 4, WORST == 3
    CBC ESP requires an integrity algorithm; GCM must not specify one.

Discipline enforced here (sections 4, 13, 15, 16):

* a MISMATCH becomes a finding ONLY for variables whose security relevance is
  explicitly registered (``MISMATCH_FINDING_SPECS``); all other mismatches are
  ignored (no documented security significance -> no finding);
* UNKNOWN and NOT_APPLICABLE never become vulnerabilities by default;
  INSUFFICIENT_EVIDENCE is produced only when the policy enables it;
* ML output is model-derived evidence (source=ML, model_version preserved),
  capped at the policy-defined informational severity and never converted
  directly from an anomaly score.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union

from ..adapters.expected_state import MaterializedExpectedState
from ..models import (
    CorrelationIdentity,
    CorrelationResult,
    EvidenceRef,
    ExpectedState,
    MLResult,
    ObservedState,
)
from ..models.evidence import EvidenceRef as EvidenceRefModel
from .findings import make_finding
from .models import (
    CATEGORY_CONFIGURATION_MISMATCH,
    CATEGORY_CONFIGURATION_WEAKNESS,
    CATEGORY_INSUFFICIENT_EVIDENCE,
    CATEGORY_ML_CLASSIFICATION_DISAGREEMENT,
    CATEGORY_ML_TRAFFIC_ANOMALY,
    CATEGORY_OBSERVED_MISMATCH,
    CATEGORY_PROTOCOL_ANOMALY,
    EVIDENCE_TYPE_CORRELATION,
    EVIDENCE_TYPE_CONFIGURATION,
    EVIDENCE_TYPE_ML,
    EVIDENCE_TYPE_OBSERVATION,
    SEVERITY_HIGH,
    SEVERITY_INFO,
    SEVERITY_LOW,
    SEVERITY_MEDIUM,
    SOURCE_CORRELATION,
    SOURCE_EXPECTED_CONFIGURATION,
    SOURCE_ML,
    RiskFinding,
)
from .policy import RiskPolicy

CBC_ENCIPHERMENTS = ("aes128cbc", "aes256cbc")
WEAK_DH_RUNG = "modp2048"


@dataclass(frozen=True)
class RiskRuleContext:
    """Everything a rule may read. All inputs are validated by the engine."""

    expected: ExpectedState
    correlation: CorrelationResult
    expected_identity: CorrelationIdentity
    policy: RiskPolicy
    observed: Optional[ObservedState] = None
    ml_result: Optional[MLResult] = None
    evidence_refs: Tuple[EvidenceRef, ...] = ()

    def source_evidence(self) -> Tuple[EvidenceRef, ...]:
        return self.evidence_refs


# ---- expected-configuration rules (sections 11-12) --------------------------
def rule_esp_pfs_disabled(ctx: RiskRuleContext) -> List[RiskFinding]:
    """PFS disabled in the expected ESP configuration.

    Authoritative semantics: ``posture_of_config`` scores PFS as 2 of 12
    points; a PFS-off configuration can never reach the STRONG band. This is a
    configuration weakness, never a runtime compromise observation.
    """
    esp = ctx.expected.esp
    if esp.pfs is not False:
        return []
    return [
        make_finding(
            finding_id="RISK-PFS-DISABLED",
            rule_id="esp.pfs.disabled",
            category=CATEGORY_CONFIGURATION_WEAKNESS,
            severity=SEVERITY_MEDIUM,
            title="PFS disabled in expected ESP configuration",
            description=(
                "Expected ESP configuration has Perfect Forward Secrecy (PFS) "
                "disabled. The authoritative SIH posture scoring "
                "(posture_of_config) contributes 2 points to PFS; a PFS-off "
                "configuration can never reach the STRONG band. This is a "
                "documented forward-secrecy deficiency of the EXPECTED "
                "configuration, not runtime evidence."
            ),
            reason=f"Expected esp.pfs={esp.pfs!r}; PFS is disabled (posture PFS contribution 0/2).",
            condition="esp.pfs == False",
            expected_value=esp.pfs,
            observed_value=None,
            source=SOURCE_EXPECTED_CONFIGURATION,
            evidence_type=EVIDENCE_TYPE_CONFIGURATION,
            related_variable="esp.pfs",
            evidence_refs=ctx.source_evidence(),
        )
    ]


def rule_esp_encryption_cbc(ctx: RiskRuleContext) -> List[RiskFinding]:
    """CBC (non-AEAD) ESP family in the expected configuration.

    Authoritative semantics: ``posture_of_config`` scores the cipher family
    2 (CBC) vs 4 (GCM16); CBC is the weaker family and is REQUIRED (per
    ``controller/validate.py``) to carry a separate integrity algorithm. A CBC
    configuration can never reach STRONG. Severity MEDIUM (posture deficit 2).
    """
    esp = ctx.expected.esp
    if esp.encryption not in CBC_ENCIPHERMENTS:
        return []
    return [
        make_finding(
            finding_id="RISK-WEAK-ESP-CRYPTO",
            rule_id="esp.encryption.cbc",
            category=CATEGORY_CONFIGURATION_WEAKNESS,
            severity=SEVERITY_MEDIUM,
            title="Weak ESP cipher family in expected configuration (CBC)",
            description=(
                "Expected ESP cipher {0} is a CBC (non-AEAD) algorithm. The "
                "authoritative SIH posture scoring contributes 2 points to the "
                "cipher family vs 4 for GCM16, so this configuration can never "
                "reach the STRONG band. CBC is still a supported, valid "
                "configuration in the authoritative model (it must carry a "
                "separate integrity algorithm) - this is a configuration "
                "weakness, not runtime evidence."
            ).format(esp.encryption),
            reason=f"Expected esp.encryption={esp.encryption!r} is in the CBC family "
                   f"{CBC_ENCIPHERMENTS}; posture cipher-family contribution 2/4.",
            condition="esp.encryption in ('aes128cbc', 'aes256cbc')",
            expected_value=esp.encryption,
            observed_value=None,
            source=SOURCE_EXPECTED_CONFIGURATION,
            evidence_type=EVIDENCE_TYPE_CONFIGURATION,
            related_variable="esp.encryption",
            evidence_refs=ctx.source_evidence(),
        )
    ]


def rule_esp_dh_group_weak(ctx: RiskRuleContext) -> List[RiskFinding]:
    """Lowest DH rung (modp2048) while PFS is enabled.

    Authoritative semantics: ``posture_of_config`` scores DH only while PFS is
    enabled (4/3/1 for modp4096/modp3072/modp2048). When PFS is disabled the
    rekey DH exchange does not occur, so the PFS weakness (RISK-PFS-DISABLED)
    already represents the forward-secrecy deficiency and this rule does not
    double-count it.
    """
    esp = ctx.expected.esp
    if esp.pfs is not True or esp.dh_group != WEAK_DH_RUNG:
        return []
    return [
        make_finding(
            finding_id="RISK-WEAK-DH-GROUP",
            rule_id="esp.dh_group.weak",
            category=CATEGORY_CONFIGURATION_WEAKNESS,
            severity=SEVERITY_LOW,
            title="Lowest ESP DH group rung (modp2048) while PFS is enabled",
            description=(
                "Expected ESP DH group is {0} with PFS enabled. The "
                "authoritative SIH posture scoring contributes 1/4 DH points "
                "for modp2048. Informational configuration weakness only; the "
                "group remains a supported, valid rung in the authoritative "
                "model."
            ).format(esp.dh_group),
            reason=f"Expected esp.dh_group={esp.dh_group!r} with esp.pfs=True; "
                   f"posture DH contribution 1/4.",
            condition="esp.pfs == True and esp.dh_group == 'modp2048'",
            expected_value=esp.dh_group,
            observed_value=None,
            source=SOURCE_EXPECTED_CONFIGURATION,
            evidence_type=EVIDENCE_TYPE_CONFIGURATION,
            related_variable="esp.dh_group",
            evidence_refs=ctx.source_evidence(),
        )
    ]


# ---- correlation / observation rules (sections 13, 17) ----------------------
# variable -> (finding_id, rule_id, category, severity-or-None-for-dynamic,
#              security_relevance)
MISMATCH_FINDING_SPECS: Dict[str, Tuple[str, str, str, Optional[str], bool]] = {
    "mode": (
        "RISK-MODE-MISMATCH", "correlation.mismatch.mode",
        CATEGORY_CONFIGURATION_MISMATCH, SEVERITY_HIGH, True,
    ),
    "address_family": (
        "RISK-ADDRESS-FAMILY-MISMATCH", "correlation.mismatch.address_family",
        CATEGORY_OBSERVED_MISMATCH, SEVERITY_MEDIUM, True,
    ),
    "esp.presence": (
        "RISK-ESP-MISMATCH", "correlation.mismatch.esp.presence",
        CATEGORY_OBSERVED_MISMATCH, None, True,
    ),
    "ah.presence": (
        "RISK-AH-UNEXPECTED", "correlation.mismatch.ah.presence",
        CATEGORY_PROTOCOL_ANOMALY, SEVERITY_MEDIUM, True,
    ),
    "ike.activity": (
        "RISK-IKE-ACTIVITY-MISMATCH", "correlation.mismatch.ike.activity",
        CATEGORY_OBSERVED_MISMATCH, SEVERITY_LOW, False,
    ),
    "tunnel.activity": (
        "RISK-TUNNEL-ACTIVITY-MISMATCH", "correlation.mismatch.tunnel.activity",
        CATEGORY_OBSERVED_MISMATCH, SEVERITY_LOW, False,
    ),
    "traffic.activity": (
        "RISK-TRAFFIC-ACTIVITY-MISMATCH", "correlation.mismatch.traffic.activity",
        CATEGORY_OBSERVED_MISMATCH, SEVERITY_LOW, False,
    ),
    "window.containment": (
        "RISK-WINDOW-OUTSIDE", "correlation.mismatch.window.containment",
        CATEGORY_OBSERVED_MISMATCH, SEVERITY_LOW, False,
    ),
}


def _esp_presence_severity(expected_value: Any, observed_value: Any) -> str:
    """ESP presence is protection-critical: expected-present but observed-absent
    (established by a COMPLETE observation) is HIGH; unexpected presence is
    LOW (config drift, not a confirmed compromise)."""
    if expected_value is True and observed_value is False:
        return SEVERITY_HIGH
    return SEVERITY_LOW


def rule_correlation_mismatches(ctx: RiskRuleContext) -> List[RiskFinding]:
    """Classify Phase-4 authoritative mismatch outcomes into findings.

    Only variables with an explicit, documented security relevance are mapped
    (`MISMATCH_FINDING_SPECS`). Anything else is ignored: "a mismatch becomes a
    security finding only when the rule establishes security relevance"
    (section 4/13).
    """
    findings: List[RiskFinding] = []
    for outcome in ctx.correlation.mismatches:
        variable = outcome.get("variable")
        spec = MISMATCH_FINDING_SPECS.get(variable)
        if spec is None:
            continue
        finding_id, rule_id, category, severity, _ = spec
        observed_value = outcome.get("observed_value")
        expected_value = outcome.get("expected_value")
        reason = outcome.get("reason") or f"authoritative observed {variable} contradicts expected"
        if severity is None:
            severity = _esp_presence_severity(expected_value, observed_value)
        evidence_refs = _outcome_evidence_refs(outcome)
        evidence_type = EVIDENCE_TYPE_OBSERVATION if evidence_refs else EVIDENCE_TYPE_CORRELATION
        findings.append(
            make_finding(
                finding_id=finding_id,
                rule_id=rule_id,
                category=category,
                severity=severity,
                title=f"Confirmed observation mismatch on {variable}",
                description=(
                    f"The Phase-4 comparison recorded an authoritative "
                    f"contradiction on {variable!r} (expected {expected_value!r} but "
                    f"observed {observed_value!r}). Finding is CLASSIFIED "
                    f"{category} per the documented risk rule; a mismatch becomes "
                    f"a security finding ONLY when the rule establishes security "
                    f"relevance (Phase 6 brief sections 4/13)."
                ),
                reason=reason,
                condition=f"correlation.mismatch on {variable}",
                expected_value=expected_value,
                observed_value=observed_value,
                source=SOURCE_CORRELATION,
                evidence_type=evidence_type,
                related_variable=variable,
                evidence_refs=evidence_refs,
            )
        )
    return findings


def _outcome_evidence_refs(outcome: Dict[str, Any]) -> Tuple[EvidenceRef, ...]:
    refs: List[EvidenceRef] = []
    for item in outcome.get("evidence_refs") or []:
        if not isinstance(item, dict):
            continue
        try:
            refs.append(EvidenceRefModel.from_dict(item))
        except (ValueError, TypeError, KeyError):
            continue
    return tuple(refs)


# ---- ML rules (sections 14-15) ----------------------------------------------
def rule_ml_anomaly(ctx: RiskRuleContext) -> List[RiskFinding]:
    """Preserve a True ML anomaly verdict as model-derived evidence.

    Severity is pinned by the policy (default LOW); the anomaly score is never
    converted directly into risk (default ``anomaly_score_conversion=none``),
    and CRITICAL is never assigned to an anomaly by itself.
    """
    ml = ctx.ml_result
    if ml is None or ml.anomaly is not True:
        return []
    severity = ctx.policy.ml_handling.get("anomaly_severity", SEVERITY_LOW)
    _guard_ml_severity(ctx.policy, severity)
    return [
        make_finding(
            finding_id="RISK-ML-ANOMALY",
            rule_id="ml.anomaly",
            category=CATEGORY_ML_TRAFFIC_ANOMALY,
            severity=severity,
            title="ML anomaly verdict on observed traffic",
            description=(
                "The ML model reported an anomaly verdict "
                "(anomaly=True). This is MODEL-DERIVED EVIDENCE, not a "
                "confirmed attack and never an authoritative protocol "
                "observation. The anomaly score is informative only and is not "
                "converted into a risk contribution (policy "
                "anomaly_score_conversion=none)."
            ),
            reason=(
                f"ML anomaly flag=True with score={ml.anomaly_score!r} from "
                f"model_version={ml.model_version!r}."
            ),
            condition="ml_result.anomaly == True",
            expected_value=None,
            observed_value=True,
            source=SOURCE_ML,
            evidence_type=EVIDENCE_TYPE_ML,
            related_variable="ML_ANOMALY",
            model_version=ml.model_version,
            evidence_refs=ctx.source_evidence(),
        )
    ]


def rule_ml_classification_disagreement(ctx: RiskRuleContext) -> List[RiskFinding]:
    """ML classification disagreeing with the expected profile.

    Phase-5 comparison semantics: ML_TRAFFIC_CLASSIFICATION MISMATCH. Only an
    explicitly policy-authorized informational (LOW) finding - never a
    vulnerability. The model version and classification confidence are
    preserved.
    """
    ml = ctx.ml_result
    if ml is None or ml.traffic_class is None:
        return []
    if ml.traffic_class == ctx.expected.traffic.profile:
        return []
    severity = ctx.policy.ml_handling.get(
        "classification_disagreement_severity", SEVERITY_LOW
    )
    _guard_ml_severity(ctx.policy, severity)
    return [
        make_finding(
            finding_id="RISK-ML-CLASSIFICATION",
            rule_id="ml.classification.disagreement",
            category=CATEGORY_ML_CLASSIFICATION_DISAGREEMENT,
            severity=severity,
            title="ML traffic classification disagrees with expected profile",
            description=(
                "The ML model classified the observed traffic as "
                "{0!r} while the expected profile is {1!r}. A classification "
                "disagreement is model-derived inference evidence; it is NOT a "
                "confirmed security vulnerability and never overrides observed "
                "protocol evidence. This informational finding exists only "
                "because the risk policy authorizes it at the LOW ceiling."
            ).format(ml.traffic_class, ctx.expected.traffic.profile),
            reason=f"ML classification {ml.traffic_class!r} != expected profile "
                   f"{ctx.expected.traffic.profile!r}.",
            condition="ml_result.traffic_class is not None and  "
                      "!= expected.traffic.profile",
            expected_value=ctx.expected.traffic.profile,
            observed_value=ml.traffic_class,
            source=SOURCE_ML,
            evidence_type=EVIDENCE_TYPE_ML,
            related_variable="ML_TRAFFIC_CLASSIFICATION",
            confidence=ml.classification_confidence,
            model_version=ml.model_version,
            evidence_refs=ctx.source_evidence(),
        )
    ]


def _guard_ml_severity(policy: RiskPolicy, severity: str) -> None:
    ceiling = policy.ml_handling.get("max_ml_severity")
    if ceiling is None:
        return
    from .models import SEVERITY_RANK

    if SEVERITY_RANK[severity] > SEVERITY_RANK[ceiling]:
        raise ValueError(
            f"policy ml_handling caps ML findings at {ceiling!r}; rule requested "
            f"{severity!r}"
        )


# ---- unknown / insufficient evidence rule (section 16) ----------------------
def rule_evidence_insufficient(ctx: RiskRuleContext) -> List[RiskFinding]:
    """INSUFFICIENT_EVIDENCE findings ONLY when the policy explicitly enables
    them (default off). Severity INFO (weight 0): surfacing which evidence is
    missing WITHOUT inflating the risk score.
    """
    if not ctx.policy.unknown_handling.get("enable_insufficient_evidence", False):
        return []
    findings: List[RiskFinding] = []
    for outcome in ctx.correlation.unknowns:
        variable = outcome.get("variable")
        if not variable:
            continue
        findings.append(
            make_finding(
                finding_id=f"RISK-INSUFFICIENT-EVIDENCE-{variable}",
                rule_id="evidence.insufficient",
                category=CATEGORY_INSUFFICIENT_EVIDENCE,
                severity=SEVERITY_INFO,
                title=f"Insufficient evidence to compare {variable}",
                description=(
                    "The Phase-4 comparison left {0!r} as UNKNOWN. This is an "
                    "evidence gap surfaced because the risk policy explicitly "
                    "enables INSUFFICIENT_EVIDENCE findings; it is NOT a "
                    "vulnerability and never inflates the score (severity INFO)."
                ).format(variable),
                reason=outcome.get("reason") or f"{variable} is UNKNOWN.",
                condition="policy.unknown_handling.enable_insufficient_evidence == True and "
                          "variable @ UNKNOWN",
                expected_value=outcome.get("expected_value"),
                observed_value=None,
                source=SOURCE_CORRELATION,
                evidence_type=EVIDENCE_TYPE_CORRELATION,
                related_variable=variable,
                evidence_refs=_outcome_evidence_refs(outcome),
            )
        )
    return findings


# ---- registry ---------------------------------------------------------------
RULE_REGISTRY = {
    "esp.pfs.disabled": rule_esp_pfs_disabled,
    "esp.encryption.cbc": rule_esp_encryption_cbc,
    "esp.dh_group.weak": rule_esp_dh_group_weak,
    "correlation.mismatch": rule_correlation_mismatches,
    "ml.anomaly": rule_ml_anomaly,
    "ml.classification.disagreement": rule_ml_classification_disagreement,
    "evidence.insufficient": rule_evidence_insufficient,
}

# rule metadata (source of truth for PHASE_6_RISK_RULE_TRACEABILITY.md)
RULE_TRACEABILITY: Dict[str, Dict[str, Any]] = {
    "esp.pfs.disabled": {
        "rule_id": "esp.pfs.disabled",
        "finding_id": "RISK-PFS-DISABLED",
        "source_variable": "esp.pfs",
        "authoritative_source": (
            "controller/dataset_planner.py::posture_of_config "
            "(PFS contributes 2 posture points)"
        ),
        "condition": "expected.esp.pfs is False",
        "severity": SEVERITY_MEDIUM,
        "score_contribution": 12,
        "evidence_requirement": "configuration only (EXPECTED_CONFIGURATION source)",
        "unknown_handling": "n/a (expected configuration is always known)",
        "dedup_behavior": (
            "dedup (category, esp.pfs, EXPECTED_CONFIGURATION); not re-fired by "
            "comparison or ML rules (esp.pfs is UNKNOWN in Phase 4, never a "
            "mismatch)"
        ),
    },
    "esp.encryption.cbc": {
        "rule_id": "esp.encryption.cbc",
        "finding_id": "RISK-WEAK-ESP-CRYPTO",
        "source_variable": "esp.encryption",
        "authoritative_source": (
            "controller/dataset_planner.py::posture_of_config "
            "(cipher family 2 vs 4); controller/validate.py CBC-integrity rule"
        ),
        "condition": "expected.esp.encryption in ('aes128cbc', 'aes256cbc')",
        "severity": SEVERITY_MEDIUM,
        "score_contribution": 12,
        "evidence_requirement": "configuration only (EXPECTED_CONFIGURATION source)",
        "unknown_handling": "n/a (expected configuration is always known)",
        "dedup_behavior": (
            "dedup (category, esp.encryption, EXPECTED_CONFIGURATION); aes128 key "
            "length is NOT a weakness (authority never grades it as one)"
        ),
    },
    "esp.dh_group.weak": {
        "rule_id": "esp.dh_group.weak",
        "finding_id": "RISK-WEAK-DH-GROUP",
        "source_variable": "esp.dh_group",
        "authoritative_source": (
            "controller/dataset_planner.py::posture_of_config "
            "(DH 1/4 for modp2048, counted only while PFS is on)"
        ),
        "condition": "expected.esp.pfs is True and expected.esp.dh_group == 'modp2048'",
        "severity": SEVERITY_LOW,
        "score_contribution": 6,
        "evidence_requirement": "configuration only (EXPECTED_CONFIGURATION source)",
        "unknown_handling": (
            "when PFS is off the rule does NOT fire (rekey DH absent; the "
            "forward-secrecy deficiency is represented by RISK-PFS-DISABLED)"
        ),
        "dedup_behavior": "dedup by (category, esp.dh_group, EXPECTED_CONFIGURATION)",
    },
    "correlation.mismatch": {
        "rule_id": "correlation.mismatch",
        "finding_id": "RISK-<VARIABLE-ADAPTED> (see MISMATCH_FINDING_SPECS)",
        "source_variable": "correlation.mismatches[*].variable",
        "authoritative_source": (
            "Phase-4 ComparisonEngine outcomes; variable security relevance "
            "from Phase 1 discovery"
        ),
        "condition": (
            "an authoritative mismatch outcome on a registered security-relevant "
            "variable (mode, address_family, esp.presence, ah.presence, "
            "ike.activity, tunnel.activity, traffic.activity, window.containment)"
        ),
        "severity": "per-variable HIGH/MEDIUM/LOW (esp.presence dynamic)",
        "score_contribution": "25/12/6 per the mapped severity",
        "evidence_requirement": (
            "observation evidence when the outcome carries EvidenceRefs; "
            "otherwise correlation source; NEVER fabricated"
        ),
        "unknown_handling": (
            "UNKNOWN and NOT_APPLICABLE mismatches never create findings; "
            "unregistered mismatch variables are ignored"
        ),
        "dedup_behavior": (
            "dedup by (category, variable, CORRELATION); esp.presence and "
            "mode mismatch cannot double-count each other"
        ),
    },
    "ml.anomaly": {
        "rule_id": "ml.anomaly",
        "finding_id": "RISK-ML-ANOMALY",
        "source_variable": "MLResult.anomaly / anomaly_score",
        "authoritative_source": "Phase-5 MLResult contract (source=ml)",
        "condition": "ml_result is not None and ml_result.anomaly is True",
        "severity": SEVERITY_LOW,
        "score_contribution": 6,
        "evidence_requirement": "model-derived (source=ML, model_version preserved)",
        "unknown_handling": (
            "a missing ML result or an absent anomaly verdict never creates a "
            "finding; anomaly score is not converted into risk"
        ),
        "dedup_behavior": "dedup by (category, ML_ANOMALY, ML)",
    },
    "ml.classification.disagreement": {
        "rule_id": "ml.classification.disagreement",
        "finding_id": "RISK-ML-CLASSIFICATION",
        "source_variable": "MLResult.traffic_class vs expected.traffic.profile",
        "authoritative_source": (
            "Phase-5 ML_TRAFFIC_CLASSIFICATION comparison semantics "
            "(never an authoritative protocol observation)"
        ),
        "condition": "ml_result.traffic_class is not None and "
                     "!= expected.traffic.profile",
        "severity": SEVERITY_LOW,
        "score_contribution": 6,
        "evidence_requirement": "model-derived (source=ML, model_version preserved)",
        "unknown_handling": (
            "no class / missing ML result -> no finding; disagreement never a "
            "vulnerability"
        ),
        "dedup_behavior": "dedup by (category, ML_TRAFFIC_CLASSIFICATION, ML)",
    },
    "evidence.insufficient": {
        "rule_id": "evidence.insufficient",
        "finding_id": "RISK-INSUFFICIENT-EVIDENCE-<variable>",
        "source_variable": "correlation.unknowns[*].variable",
        "authoritative_source": "Phase-4 UNKNOWN outcomes (observability gaps)",
        "condition": (
            "policy.unknown_handling.enable_insufficient_evidence is True "
            "(OFF by default)"
        ),
        "severity": SEVERITY_INFO,
        "score_contribution": 0,
        "evidence_requirement": "none added; surfaces existing outcome reasons",
        "unknown_handling": "explicit opt-in only; INFO severity never inflates score",
        "dedup_behavior": "dedup by (category, variable, CORRELATION)",
    },
}


def _expected_of(expected: Union[ExpectedState, MaterializedExpectedState]) -> ExpectedState:
    if isinstance(expected, MaterializedExpectedState):
        return expected.expected
    return expected


def run_rules(ctx: RiskRuleContext) -> List[RiskFinding]:
    """Evaluate the enabled rules in the fixed policy order."""
    findings: List[RiskFinding] = []
    for rule_name in ctx.policy.rules_enabled_for():
        findings.extend(RULE_REGISTRY[rule_name](ctx))
    return findings