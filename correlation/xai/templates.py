"""XAI templates, deterministic text builders, and traceability registry.

Every ``*_FOR`` function below produces a deterministic text segment derived
from the structured values of an existing Phase-6 ``RiskFinding``, an existing
Phase-5 ``MLResult``, or the overall ``RiskAssessment``. No randomness, no
current-time, no network calls. Templates are the ONLY place where human
phrasing lives; ``explainers.py`` composes them without inventing any.

The ``XAI_TRACEABILITY`` dict at the end of this module is the single
source-of-truth for PHASE_7_XAI_TRACEABILITY.md and is generated from the
code so that the report cannot drift.
"""

from typing import Any, Dict, List, Optional, Sequence, Tuple

from ..models.evidence import EvidenceRef
from ..risk.models import (
    CATEGORY_CONFIGURATION_MISMATCH,
    CATEGORY_CONFIGURATION_WEAKNESS,
    CATEGORY_INSUFFICIENT_EVIDENCE,
    CATEGORY_ML_CLASSIFICATION_DISAGREEMENT,
    CATEGORY_ML_TRAFFIC_ANOMALY,
    CATEGORY_OBSERVED_MISMATCH,
    CATEGORY_PROTOCOL_ANOMALY,
    SEVERITY_LOW,
    SOURCE_EXPECTED_CONFIGURATION,
    SOURCE_ML,
    SEVERITY_MEDIUM,
    SEVERITY_HIGH,
    SEVERITY_INFO,
    SOURCE_CORRELATION,
    SOURCE_OBSERVED_PROTOCOL,
)
from .models import (
    EXPLANATION_CATEGORY_CONFIGURATION,
    EXPLANATION_CATEGORY_CORRELATION,
    EXPLANATION_CATEGORY_EVIDENCE,
    EXPLANATION_CATEGORY_LIMITATION,
    EXPLANATION_CATEGORY_ML,
    EXPLANATION_CATEGORY_OBSERVATION,
    EXPLANATION_CATEGORY_SCORE,
    STATUS_MATCH,
    STATUS_MISMATCH,
    STATUS_NOT_APPLICABLE,
    STATUS_PARTIAL,
    STATUS_UNKNOWN,
)

# ---- deterministic value formatting ------------------------------------------

def format_value(value: Any) -> str:
    """Neutral, deterministic representation of a field value."""
    if value is None:
        return "unavailable"
    if isinstance(value, bool):
        return "True" if value else "False"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, str):
        return value
    return str(value)


def _fmt_confidence(confidence: Any) -> str:
    if confidence is None:
        return "unavailable"
    return "{:.4g}".format(float(confidence))


# ---- brief-compatible why_it_was_flagged builders ----------------------------

CATEGORY_WHY: Dict[str, str] = {
    CATEGORY_CONFIGURATION_WEAKNESS: (
        "The evaluated configuration contains a security weakness identified by "
        "the Phase-6 risk rule."
    ),
    CATEGORY_CONFIGURATION_MISMATCH: (
        "The expected configuration does not match the authoritative observed "
        "value; the Phase-4 comparison engine recorded a confirmed mismatch."
    ),
    CATEGORY_OBSERVED_MISMATCH: (
        "The authoritative observed value does not match the expected "
        "configuration; the Phase-4 comparison engine recorded a confirmed "
        "mismatch."
    ),
    CATEGORY_PROTOCOL_ANOMALY: (
        "Observed protocol behavior departs from the expected envelope; the "
        "Phase-4 comparison engine recorded an anomalous condition."
    ),
    CATEGORY_ML_TRAFFIC_ANOMALY: (
        "The configured ML model marked the observation as anomalous."
    ),
    CATEGORY_ML_CLASSIFICATION_DISAGREEMENT: (
        "The configured ML model's traffic classification differs from the "
        "expected traffic profile."
    ),
    CATEGORY_INSUFFICIENT_EVIDENCE: (
        "The required authoritative observation was unavailable during "
        "comparison; the engine could not establish a match or mismatch."
    ),
}


def _presence_sentence(expected: Any, observed: Any, related_variable: Optional[str]) -> str:
    var_hint = f" for {related_variable}" if related_variable else ""
    if expected is not None and observed is not None:
        return (
            f"The expected value was {format_value(expected)} and the observed "
            f"value was {format_value(observed)}{var_hint}."
        )
    if expected is not None:
        return (
            f"The field{var_hint} had expected value "
            f"{format_value(expected)} at assessment time; no independent "
            f"observed value was available."
        )
    if observed is not None:
        return (
            f"The field{var_hint} was observed as {format_value(observed)}; no "
            f"expected value was recorded."
        )
    return f"No expected or observed values were recorded{var_hint}."


def why_it_was_flagged(
    finding: Any,
    *,
    template_override: Optional[str] = None,
) -> str:
    if template_override:
        return template_override
    base = CATEGORY_WHY.get(
        getattr(finding, "category", ""), "",
    )
    presence = _presence_sentence(
        getattr(finding, "expected_value", None),
        getattr(finding, "observed_value", None),
        getattr(finding, "related_variable", None),
    )
    return f"{base} {presence}".strip()


# ---- rule-specific templates (brief examples + SIH authoritative semantics) ---

def _tpl_pfs_disabled(finding: Any) -> str:
    return (
        "The expected ESP configuration has Perfect Forward Secrecy (PFS) "
        "disabled (esp.pfs=False). The authoritative SIH posture scoring "
        "contributes 0/2 PFS points for a disabled configuration "
        "(posture_of_config); the Phase-6 risk rule esp.pfs.disabled "
        "therefore flags a forward-secrecy configuration weakness "
        f"({finding.finding_id})."
    )


def _tpl_esp_encryption_cbc(finding: Any) -> str:
    enc = format_value(finding.expected_value)
    return (
        f"The expected ESP cipher {enc} is a CBC (non-AEAD) algorithm. "
        "The authoritative SIH posture scoring contributes 2/4 cipher-family "
        "points for CBC versus 4/4 for GCM16 (posture_of_config); a "
        "configuration using CBC can never reach the STRONG band. "
        f"Phase-6 rule {finding.rule_id} therefore flags "
        f"{finding.finding_id}."
    )


def _tpl_esp_dh_group_weak(finding: Any) -> str:
    return (
        f"The expected ESP DH group is {format_value(finding.expected_value)} "
        "with PFS enabled. The authoritative SIH posture scoring contributes "
        "1/4 DH points for the lowest supported rung, modp2048 "
        "(posture_of_config). This is a documented informational configuration "
        "weakness; the group remains a valid supported rung. "
        f"Phase-6 rule {finding.rule_id} fires as {finding.finding_id}."
    )


def _tpl_mismatch_mode(finding: Any) -> str:
    exp = format_value(finding.expected_value)
    obs = format_value(finding.observed_value)
    return (
        "The expected IPsec mode does not match the authoritative observed "
        f"mode (expected {exp}, observed {obs}). This is a confirmed "
        "configuration/protocol mismatch according to the Phase-4 comparison "
        f"result, flagged as {finding.finding_id} by the Phase-6 risk rule."
    )


def _tpl_mismatch_esp_presence(finding: Any) -> str:
    exp = format_value(finding.expected_value)
    obs = format_value(finding.observed_value)
    if finding.severity == SEVERITY_HIGH:
        return (
            "ESP was expected to be present in the observed protocol behavior "
            f"(expected esp.presence={exp}) but was not observed "
            f"(observed esp.presence={obs}). A COMPLETE observation window "
            "established its absence; the Phase-6 risk rule therefore classifies "
            f"this as a HIGH-severity mismatch ({finding.finding_id})."
        )
    return (
        "ESP was not expected in the observed behavior but was detected "
        f"(expected esp.presence={exp}, observed esp.presence={obs}). "
        "This is an informational mismatch flagged by the Phase-6 rule."
    )


def _tpl_mismatch_generic(finding: Any) -> str:
    var = finding.related_variable or "an unknown variable"
    exp = format_value(finding.expected_value)
    obs = format_value(finding.observed_value)
    return (
        "The expected value of "
        f"{var} does not match the authoritative observed value "
        f"(expected {exp}, observed {obs}). The Phase-4 comparison engine "
        "recorded a confirmed mismatch, and the Phase-6 risk rule "
        f"{finding.rule_id} classifies this as {finding.category}."
    )


def _tpl_ah_presence(finding: Any) -> str:
    obs = format_value(finding.observed_value)
    return (
        f"AH was detected (ah.presence={obs}) in the observed protocol "
        "behavior. This is not expected in the current SIH configuration "
        "model and is flagged as a protocol anomaly "
        f"({finding.finding_id}) by the Phase-6 risk rule."
    )


def _tpl_activity_mismatch(finding: Any) -> str:
    var = finding.related_variable or "activity"
    return (
        f"The observed {var} does not match the expected value "
        f"(expected {format_value(finding.expected_value)}, observed "
        f"{format_value(finding.observed_value)}). This is an informational "
        "operational mismatch flagged by the Phase-6 risk rule "
        f"{finding.rule_id}."
    )


def _tpl_ml_anomaly(finding: Any) -> str:
    return (
        "The ML model marked this observation as anomalous "
        "(anomaly=True). This is model-derived evidence and does not by "
        "itself establish that the traffic represents an attack. Phase-6 "
        "risk rule ml.anomaly preserves this verdict as RISK-ML-ANOMALY; "
        f"the model's recorded detail was: {finding.reason}"
    )


def _tpl_ml_classification(finding: Any) -> str:
    conf = _fmt_confidence(finding.confidence)
    return (
        "The ML model classified the observed traffic as "
        f"{format_value(finding.observed_value)} with confidence {conf}, "
        "while the expected profile is "
        f"{format_value(finding.expected_value)}. This classification "
        "disagreement is model-derived inference evidence, not a confirmed "
        "security vulnerability. Phase-6 risk rule "
        f"{finding.rule_id} preserves this as {finding.finding_id}."
    )


def _tpl_evidence_insufficient(finding: Any) -> str:
    var = finding.related_variable or "the field"
    return (
        f"The authoritative observation for {var} was unavailable "
        f"(status UNKNOWN for {var}). The Phase-6 risk rule "
        "evidence.insufficient surfaced this as an information-only finding "
        f"({finding.finding_id}); it is NOT a vulnerability and has zero "
        "score contribution."
    )


_TEMPLATES = {
    "esp.pfs.disabled": _tpl_pfs_disabled,
    "esp.encryption.cbc": _tpl_esp_encryption_cbc,
    "esp.dh_group.weak": _tpl_esp_dh_group_weak,
    "correlation.mismatch.mode": _tpl_mismatch_mode,
    "correlation.mismatch.esp.presence": _tpl_mismatch_esp_presence,
    "correlation.mismatch.ah.presence": _tpl_ah_presence,
    "correlation.mismatch.ike.activity": _tpl_activity_mismatch,
    "correlation.mismatch.tunnel.activity": _tpl_activity_mismatch,
    "correlation.mismatch.traffic.activity": _tpl_activity_mismatch,
    "correlation.mismatch.window.containment": _tpl_activity_mismatch,
    "ml.anomaly": _tpl_ml_anomaly,
    "ml.classification.disagreement": _tpl_ml_classification,
    "evidence.insufficient": _tpl_evidence_insufficient,
}


def rule_template(finding: Any) -> Optional[str]:
    tpl = _TEMPLATES.get(finding.rule_id)
    return tpl(finding) if tpl else None


def generic_why(finding: Any) -> str:
    return why_it_was_flagged(finding, template_override=rule_template(finding))


# ---- contributing factors (deterministic) ------------------------------------

def contributing_factors(finding: Any) -> Tuple[str, ...]:
    factors: List[str] = []
    if getattr(finding, "source", None) == SOURCE_EXPECTED_CONFIGURATION:
        factors.append("expected configuration deficiency")
    if getattr(finding, "source", None) in (SOURCE_CORRELATION, SOURCE_OBSERVED_PROTOCOL):
        factors.append("authoritative comparison outcome")
    if getattr(finding, "source", None) == SOURCE_ML:
        factors.append("model-derived evidence")
    refs = getattr(finding, "evidence_refs", None) or []
    if refs:
        factors.append(f"{len(refs)} evidence reference(s) attached")
    conf = getattr(finding, "confidence", None)
    if conf is not None:
        factors.append(f"model classification confidence {_fmt_confidence(conf)}")
    return tuple(factors)


# ---- limitations (deterministic, non-fabricated) -----------------------------

def limitations(finding: Any) -> Tuple[str, ...]:
    lims: List[str] = []
    source = getattr(finding, "source", "")
    cat = getattr(finding, "category", "")
    obs = getattr(finding, "observed_value", None)
    refs = getattr(finding, "evidence_refs", None) or []

    if source == SOURCE_EXPECTED_CONFIGURATION or (
        cat in (CATEGORY_CONFIGURATION_WEAKNESS,) and obs is None
    ):
        lims.append("The conclusion is based on configuration evidence only.")

    if source == SOURCE_ML:
        lims.append(
            "Model-derived evidence only; it does not establish "
            "malicious activity by itself."
        )
        if cat == CATEGORY_ML_TRAFFIC_ANOMALY:
            lims.append(
                "The anomaly score is informative only and was not converted "
                "into a risk contribution."
            )
        if cat == CATEGORY_ML_CLASSIFICATION_DISAGREEMENT:
            lims.append(
                "A classification disagreement is an informational signal, "
                "not a confirmed security vulnerability."
            )

    if source == SOURCE_CORRELATION and not refs:
        lims.append(
            "No PCAP or audit evidence reference was attached to this "
            "comparison outcome; the conclusion rests on the Phase-4 "
            "comparison result alone."
        )

    if obs is None and source in (SOURCE_CORRELATION, SOURCE_OBSERVED_PROTOCOL):
        lims.append(
            "An authoritative observed value was unavailable for this "
            "field at the time of assessment."
        )

    return tuple(lims)


# ---- explanation categories --------------------------------------------------

def explanation_categories(finding: Any) -> Tuple[str, ...]:
    cats: List[str] = []
    source = getattr(finding, "source", "")
    refs = getattr(finding, "evidence_refs", None) or []

    source_cat_map = {
        SOURCE_EXPECTED_CONFIGURATION: EXPLANATION_CATEGORY_CONFIGURATION,
        SOURCE_OBSERVED_PROTOCOL: EXPLANATION_CATEGORY_OBSERVATION,
        SOURCE_CORRELATION: EXPLANATION_CATEGORY_CORRELATION,
        SOURCE_ML: EXPLANATION_CATEGORY_ML,
        SOURCE_EVIDENCE: EXPLANATION_CATEGORY_EVIDENCE,
    }
    cats.append(source_cat_map.get(source, EXPLANATION_CATEGORY_CORRELATION))
    if refs:
        cats.append(EXPLANATION_CATEGORY_EVIDENCE)
    lims = limitations(finding)
    if lims:
        cats.append(EXPLANATION_CATEGORY_LIMITATION)
    return tuple(dict.fromkeys(cats))


SOURCE_EVIDENCE = "EVIDENCE"


# ---- ML explanation text builders -------------------------------------------

def ml_classification_explanation(
    traffic_class: Optional[str],
    confidence: Optional[float],
    model_version: Optional[str],
) -> str:
    class_word = format_value(traffic_class) if traffic_class else "an unknown class"
    base = (
        f"The ML model classified the observed traffic as {class_word} with "
        f"classification confidence {_fmt_confidence(confidence)}"
    )
    if model_version:
        base += f" (model_version={model_version})."
    else:
        base += "."
    return (
        base + " This is model-derived inference evidence; it does not "
        "represent an authoritative protocol observation."
    )


def ml_anomaly_explanation(
    anomaly: Optional[bool],
    anomaly_score: Optional[float],
    model_version: Optional[str],
) -> str:
    if anomaly is True:
        return (
            "The ML model marked this observation as anomalous "
            f"(anomaly=True, anomaly_score={format_value(anomaly_score)}). "
            "This is model-derived evidence and does not by itself establish "
            "that the traffic represents an attack. Anomaly scores are not "
            "converted into risk contributions under the current risk policy."
        )
    if anomaly is False:
        return (
            "The ML model did not mark this observation as anomalous "
            f"(anomaly=False, anomaly_score={format_value(anomaly_score)})."
        )
    return "The ML model produced no anomaly verdict."


def ml_classification_limitations() -> Tuple[str, ...]:
    return (
        "Reported classification originates from the ML model; it is "
        "model-derived inference and is not an authoritative protocol "
        "observation.",
    )


def ml_anomaly_limitations() -> Tuple[str, ...]:
    return (
        "Model-derived evidence only; it does not establish "
        "malicious activity by itself.",
        "The anomaly score is informative only and was not converted "
        "into a risk contribution.",
    )


# ---- gap explanations (UNKNOWN / NOT_APPLICABLE) ----------------------------

def unknown_explanation_text(variable: str, reason: Optional[str] = None) -> str:
    base = (
        "The required authoritative observation for "
        f"{variable} was unavailable; the Phase-4 comparison could not "
        "establish a match or mismatch (status UNKNOWN)."
    )
    if reason:
        return f"{base} Reason: {reason} This absence of evidence is not treated as a vulnerability."
    return f"{base} This absence of evidence is not treated as a vulnerability."


def unknown_limitations(variable: str) -> Tuple[str, ...]:
    return (
        f"No authoritative observed value was available for {variable}; "
        "the comparison engine could not evaluate it.",
        "UNKNOWN status is never treated as a vulnerability by the "
        "Phase-6 risk engine.",
    )


def not_applicable_explanation_text(variable: str) -> str:
    return (
        f"This variable ({variable}) was not applicable to the evaluated "
        "rule; the Phase-4 comparison engine recorded NOT_APPLICABLE. "
        "NOT_APPLICABLE means the variable cannot semantically be compared "
        "in this context."
    )


def not_applicable_limitations(variable: str) -> Tuple[str, ...]:
    return (
        f"The variable {variable} cannot be meaningfully compared in the "
        "current evaluation context.",
        "NOT_APPLICABLE status never becomes a vulnerability and carries "
        "zero score contribution.",
    )


# ---- score explanation text ---------------------------------------------------

def score_explanation_text(
    score: int,
    severity: str,
    risk_policy_version: str,
    findings_count: int,
    ml_present: bool,
) -> str:
    parts = [
        "The Phase-6 risk assessment produced a score of",
        f"{score} which maps to severity {severity} under",
        f"risk policy {risk_policy_version}.",
    ]
    if findings_count == 0:
        parts.append("No security findings were identified.")
    else:
        parts.append(
            f"The score was derived from {findings_count} deduplicated "
            "finding(s) whose severity weights were consumed from the "
            "Phase-6 RiskAssessment as-is."
        )
    parts.append(
        "The explainability layer does not recompute or modify the "
        "Phase-6 score or severity; they remain authoritative."
    )
    if ml_present:
        parts.append(
            "ML results consumed during risk assessment were treated as "
            "model-derived evidence only and never used as direct protocol "
            "observations."
        )
    return " ".join(parts)


def overall_explanation_text(
    score: int,
    severity: str,
    risk_policy_version: str,
    n_findings: int,
    n_ml: int,
    n_unknown: int,
    n_na: int,
) -> str:
    if n_findings == 0:
        return (
            "The risk assessment produced no security findings; no finding "
            "explanations are required."
        )
    parts = [
        f"The risk assessment produced {n_findings} finding explanation(s)",
        f"under risk policy {risk_policy_version}.",
        f"Overall risk score is {score} ({severity}).",
    ]
    if n_ml:
        parts.append(f"{n_ml} ML explanation(s) describe model-derived evidence.")
    if n_unknown:
        parts.append(
            f"{n_unknown} UNKNOWN variable(s) are explained as evidence "
            "gaps."
        )
    if n_na:
        parts.append(
            f"{n_na} NOT_APPLICABLE variable(s) are explained as out-of-scope "
            "for the evaluated rule."
        )
    parts.append(
        "The XAI layer is an explanatory layer only; it does not create new "
        "vulnerabilities, change scores, or override authoritative results."
    )
    return " ".join(parts)


# ---- evidence summary text ---------------------------------------------------

def evidence_limitation(total_refs: int) -> Optional[str]:
    if total_refs == 0:
        return (
            "No evidence references were supplied to the risk assessment or "
            "were carried by the Phase-4 comparison outcomes. Every finding "
            "relying on correlation or observation evidence therefore rests on "
            "the comparison result alone."
        )
    return None


# ---- evidence summary helpers ------------------------------------------------

def _evidence_ref_key(ref: EvidenceRef) -> Tuple:
    return (
        ref.pcap_path or "",
        ref.capture_sequence or 0,
        ref.audit_event_reference or "",
        ref.source or "",
        ref.timestamp or "",
    )


def build_evidence_refs(
    evidence_refs_from_assessment: Sequence,
    evidence_refs_from_caller: Sequence = (),
    evidence_refs_from_findings: Sequence = (),
) -> Tuple[EvidenceRef, ...]:
    seen: set = set()
    result: List[EvidenceRef] = []
    for ref in evidence_refs_from_findings:
        key = _evidence_ref_key(ref)
        if key not in seen:
            seen.add(key)
            result.append(ref)
    for ref in evidence_refs_from_caller:
        key = _evidence_ref_key(ref)
        if key not in seen:
            seen.add(key)
            result.append(ref)
    for ref in evidence_refs_from_assessment:
        key = _evidence_ref_key(ref)
        if key not in seen:
            seen.add(key)
            result.append(ref)
    return tuple(sorted(result, key=_evidence_ref_key))


def evidence_source_counts(refs: Tuple[EvidenceRef, ...]) -> Tuple[Tuple[str, int], ...]:
    counts: Dict[str, int] = {}
    for ref in refs:
        src = ref.source or "unspecified"
        counts[src] = counts.get(src, 0) + 1
    return tuple(sorted(counts.items()))


# ---- XAI_TRACEABILITY (single source of truth) -------------------------------
# Each row documents: explanation_id, source_field, input_model, output_field,
# rule_ids (which Phase-6 rules produce inputs the explanation logic consumes),
# logic, and inherent limitations.

XAI_TRACEABILITY: Dict[str, Dict[str, Any]] = {
    "XAI-PFS-001": {
        "explanation_id": "XAI-PFS-001",
        "source_field": "related_variable",
        "input_model": "RiskFinding",
        "output_field": "why_it_was_flagged",
        "rule_ids": ["esp.pfs.disabled"],
        "logic": (
            "The expected ESP configuration has PFS disabled; the authoritative "
            "SIH posture scoring contributes 0/2 PFS points for disabled "
            "(posture_of_config); Phase-6 rule esp.pfs.disabled fires as "
            "RISK-PFS-DISABLED."
        ),
        "limitations": [
            "Does not infer cryptographic strength beyond the supplied "
            "configuration evidence.",
            "Does not assert runtime PFS usage; only the expected "
            "configuration is known.",
        ],
    },
    "XAI-CBC-002": {
        "explanation_id": "XAI-CBC-002",
        "source_field": "related_variable",
        "input_model": "RiskFinding",
        "output_field": "why_it_was_flagged",
        "rule_ids": ["esp.encryption.cbc"],
        "logic": (
            "The expected ESP cipher is in the CBC family; posture_of_config "
            "contributes 2/4 cipher-family points (CBC) vs 4/4 (GCM16). "
            "Phase-6 rule esp.encryption.cbc fires as RISK-WEAK-ESP-CRYPTO."
        ),
        "limitations": [
            "Does not assert runtime weakness; the CBC cipher is a valid "
            "supported configuration in the authoritative model.",
            "Does not imply AES-128 key length is a weakness; key length "
            "is never graded.",
        ],
    },
    "XAI-DH-003": {
        "explanation_id": "XAI-DH-003",
        "source_field": "related_variable",
        "input_model": "RiskFinding",
        "output_field": "why_it_was_flagged",
        "rule_ids": ["esp.dh_group.weak"],
        "logic": (
            "ESP DH group is modp2048 with PFS enabled; posture_of_config "
            "contributes 1/4 DH points for the lowest supported rung. "
            "Phase-6 rule esp.dh_group.weak fires as RISK-WEAK-DH-GROUP."
        ),
        "limitations": [
            "Only fires when PFS is enabled; when PFS is disabled the "
            "forward-secrecy deficiency is represented by XAI-PFS-001.",
            "modp2048 remains a valid supported rung in the authoritative model.",
        ],
    },
    "XAI-MODE-004": {
        "explanation_id": "XAI-MODE-004",
        "source_field": "correlation.mismatches[*].variable",
        "input_model": "RiskFinding",
        "output_field": "why_it_was_flagged",
        "rule_ids": ["correlation.mismatch"],
        "logic": (
            "The expected IPsec mode does not match the authoritative observed "
            "mode (confirmed Phase-4 mismatch). Phase-6 rule maps 'mode' to "
            "CONFIGURATION_MISMATCH / HIGH severity."
        ),
        "limitations": [
            "Requires an authoritative mode observation; the finding is only "
            "generated when such observation exists.",
            "Does not assert what impact the mode difference has on "
            "protection; it is a confirmed contradiction of the expected model.",
        ],
    },
    "XAI-OBS-MISMATCH-005": {
        "explanation_id": "XAI-OBS-MISMATCH-005",
        "source_field": "correlation.mismatches[*].variable",
        "input_model": "RiskFinding",
        "output_field": "why_it_was_flagged",
        "rule_ids": ["correlation.mismatch"],
        "logic": (
            "An authoritative observed value does not match the expected "
            "configuration for a registered security-relevant variable. "
            "Phase-6 rule maps the variable to OBSERVED_MISMATCH."
        ),
        "limitations": [
            "Unregistered mismatch variables are ignored and never produce "
            "a finding.",
            "The explanation is derived from the comparison outcome only.",
        ],
    },
    "XAI-PROTOCOL-006": {
        "explanation_id": "XAI-PROTOCOL-006",
        "source_field": "correlation.mismatches[*].variable",
        "input_model": "RiskFinding",
        "output_field": "why_it_was_flagged",
        "rule_ids": ["correlation.mismatch"],
        "logic": (
            "An unexpected protocol element was detected (e.g. AH present "
            "when not expected). Phase-6 rule maps the variable to "
            "PROTOCOL_ANOMALY."
        ),
        "limitations": [
            "Does not classify the anomaly as malicious; it is a "
            "protocol-envelope deviation from the expected configuration.",
        ],
    },
    "XAI-ESP-PRESENCE-007": {
        "explanation_id": "XAI-ESP-PRESENCE-007",
        "source_field": "correlation.mismatches[*].variable",
        "input_model": "RiskFinding",
        "output_field": "why_it_was_flagged",
        "rule_ids": ["correlation.mismatch"],
        "logic": (
            "ESP presence is a protection-critical variable: expected-present "
            "but observed-absent (via a COMPLETE window) is HIGH severity; "
            "unexpected presence is LOW (config drift). Severity is dynamic "
            "based on expected/observed values."
        ),
        "limitations": [
            "A PARTIAL window cannot confirm ESP absence; severity defaults "
            "to LOW when window completeness is not guaranteed.",
        ],
    },
    "XAI-ML-ANOMALY-008": {
        "explanation_id": "XAI-ML-ANOMALY-008",
        "source_field": "MLResult.anomaly",
        "input_model": "RiskFinding / MLResult",
        "output_field": "why_it_was_flagged",
        "rule_ids": ["ml.anomaly"],
        "logic": (
            "MLResult.anomaly is True; the Phase-6 rule preserves the verdict "
            "as model-derived evidence at LOW severity (RISK-ML-ANOMALY)."
        ),
        "limitations": [
            "Model-derived evidence only; does not establish malicious "
            "activity by itself.",
            "Anomaly score is never converted into a risk contribution.",
        ],
    },
    "XAI-ML-CLASS-009": {
        "explanation_id": "XAI-ML-CLASS-009",
        "source_field": "MLResult.traffic_class",
        "input_model": "RiskFinding / MLResult",
        "output_field": "why_it_was_flagged",
        "rule_ids": ["ml.classification.disagreement"],
        "logic": (
            "ML traffic_class does not match the expected traffic profile; "
            "the Phase-6 rule preserves this informational signal at LOW "
            "severity (RISK-ML-CLASSIFICATION)."
        ),
        "limitations": [
            "A classification disagreement is informational only; it is "
            "never a confirmed security vulnerability.",
            "Confidence is the model's own probability; it does not "
            "establish detection accuracy.",
        ],
    },
    "XAI-UNKNOWN-010": {
        "explanation_id": "XAI-UNKNOWN-010",
        "source_field": "correlation.unknowns[*].variable",
        "input_model": "CorrelationResult",
        "output_field": "unknown_explanations",
        "rule_ids": [],
        "logic": (
            "A comparison outcome variable has status UNKNOWN, meaning no "
            "authoritative observation was available to establish a match or "
            "mismatch. The explanation is an evidence gap; it is never a "
            "vulnerability."
        ),
        "limitations": [
            "UNKNOWN does not become MISMATCH; the distinction is preserved.",
        ],
    },
    "XAI-NA-011": {
        "explanation_id": "XAI-NA-011",
        "source_field": "correlation.not_applicable[*].variable",
        "input_model": "CorrelationResult",
        "output_field": "not_applicable_explanations",
        "rule_ids": [],
        "logic": (
            "A comparison outcome variable has status NOT_APPLICABLE, "
            "meaning it cannot semantically be compared in this evaluation "
            "context (e.g. capture_filter, configuration_id)."
        ),
        "limitations": [
            "NOT_APPLICABLE is never treated as a vulnerability and is "
            "never promoted to UNKNOWN or MISMATCH.",
        ],
    },
    "XAI-INSUFFICIENT-012": {
        "explanation_id": "XAI-INSUFFICIENT-012",
        "source_field": "correlation.unknowns[*].variable",
        "input_model": "RiskFinding (evidence.insufficient)",
        "output_field": "why_it_was_flagged",
        "rule_ids": ["evidence.insufficient"],
        "logic": (
            "The risk policy explicitly enables INSUFFICIENT_EVIDENCE findings; "
            "the variable was UNKNOWN and is surfaced as an information-only "
            "finding with zero score contribution (severity INFO)."
        ),
        "limitations": [
            "Produces zero score contribution; exists only to surface evidence "
            "gaps when the policy explicitly opts in.",
            "DEFAULT POLICY HAS THIS RULE DISABLED; it fires only when "
            "unknown_handling.enable_insufficient_evidence is True.",
        ],
    },
    "XAI-SCORE-013": {
        "explanation_id": "XAI-SCORE-013",
        "source_field": "metadata.score_detail",
        "input_model": "RiskAssessment",
        "output_field": "score_explanation",
        "rule_ids": [],
        "logic": (
            "The Phase-6 score, severity, contributions, and band are copied "
            "from the RiskAssessment; the XAI layer does not recompute or "
            "modify them."
        ),
        "limitations": [
            "score_detail may not be present in older RiskAssessments; in that "
            "case contributions are shown as unavailable rather than recomputed.",
        ],
    },
    "XAI-EVIDENCE-014": {
        "explanation_id": "XAI-EVIDENCE-014",
        "source_field": "evidence_refs",
        "input_model": "RiskAssessment / EvidenceRef",
        "output_field": "evidence_summary",
        "rule_ids": [],
        "logic": (
            "All supplied evidence references are collected, deduplicated, "
            "sorted deterministically, and exposed as-is. The number of "
            "supplied refs is recorded and a limitation is added when no "
            "evidence was supplied."
        ),
        "limitations": [
            "No evidence reference is fabricated; refs with all-null fields "
            "are permitted but the summary notes the absence of meaningful "
            "evidence.",
        ],
    },
    "XAI-GENERIC-015": {
        "explanation_id": "XAI-GENERIC-015",
        "source_field": "RiskFinding.category / source",
        "input_model": "RiskFinding",
        "output_field": "why_it_was_flagged",
        "rule_ids": [],
        "logic": (
            "Generic fallback builder: combines a category-specific base "
            "phrase with the expected/observed presence sentence derived from "
            "the RiskFinding's structured values."
        ),
        "limitations": [
            "Less precise than a rule-specific template; used only when no "
            "dedicated template is registered for the rule_id.",
        ],
    },
}

# deterministic explanation IDs present in the registry
EXPLANATION_IDS: Tuple[str, ...] = tuple(sorted(XAI_TRACEABILITY.keys()))

# mapping: Phase-6 rule_id -> list of XAI explanation_ids that consume its output
RULE_TO_XAI_IDS: Dict[str, List[str]] = {}
for _xai_id, _meta in XAI_TRACEABILITY.items():
    for _r in _meta.get("rule_ids", []):
        RULE_TO_XAI_IDS.setdefault(_r, []).append(_xai_id)
# normalise to tuple ordering
RULE_TO_XAI_IDS = {k: tuple(sorted(v)) for k, v in RULE_TO_XAI_IDS.items()}