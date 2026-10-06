"""Areas 8 and 9 -- the technical report and the executive report.

Both documents are *assemblies*: they quote values the engines already
produced and never re-decide anything. Every statement carries the value it
came from, and every document ends with its own limitations, so a reader can
tell an observation from a configuration from an inference without leaving
the page.

* :func:`build_technical_report` -- the analyst document: executive summary,
  identity, expected configuration, observation, SA lifecycle, runtime crypto
  evidence, replay, metadata exposure, correlation, risk (with the evidence
  and the limitations behind its findings), ML transparency, threat matrix,
  response plan, finding-specific remediation and evidence, section by
  section, each with the product it was taken from.
* :func:`build_executive_report` -- answers the brief's five questions and
  only those five: what was assessed, what the security posture is, what the
  major risks are, what evidence supports them and what should be fixed.
  Each answer lists its statements and the evidence behind them.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence

from ..risk.models import SEVERITY_RANK, RiskAssessment
from .crypto_evidence import CryptoEvidence
from .metadata import MetadataExposure
from .replay import ReplayAnalysis
from .sa import SaAnalysis
from .states import (
    STATE_ASSESSED,
    STATE_OBSERVED,
    STATE_UNKNOWN,
)


@dataclass(frozen=True)
class ReportInputs:
    """Everything both reports read, assembled once by the caller."""

    assessment_id: str
    slot: str
    scenario: str
    expected: Any
    observed: Any
    correlation: Any
    assessment: RiskAssessment
    ml: Optional[Any] = None
    sa: Optional[SaAnalysis] = None
    crypto: Optional[CryptoEvidence] = None
    replay: Optional[ReplayAnalysis] = None
    metadata: Optional[MetadataExposure] = None
    threat: Optional[Any] = None
    response_plan: Optional[Any] = None
    sources: tuple = ()


@dataclass(frozen=True)
class ReportSection:
    heading: str
    paragraphs: tuple
    product: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "heading": self.heading,
            "paragraphs": list(self.paragraphs),
            "product": self.product,
        }


@dataclass(frozen=True)
class TechnicalReport:
    state: str
    reason: str
    source: str
    assessment_id: str
    sections: tuple = ()
    limitations: tuple = ()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "state": self.state,
            "reason": self.reason,
            "source": self.source,
            "assessment_id": self.assessment_id,
            "sections": [section.to_dict() for section in self.sections],
            "limitations": list(self.limitations),
        }


@dataclass(frozen=True)
class ExecutiveReport:
    state: str
    reason: str
    source: str
    assessment_id: str
    answers: Dict[str, Any] = field(default_factory=dict)
    limitations: tuple = ()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "state": self.state,
            "reason": self.reason,
            "source": self.source,
            "assessment_id": self.assessment_id,
            "answers": dict(self.answers),
            "limitations": list(self.limitations),
        }


#: The brief's five executive questions, in the order it asks them.
EXECUTIVE_QUESTIONS = (
    "what_was_assessed",
    "security_posture",
    "major_risks",
    "evidence_supporting_risks",
    "what_should_be_fixed",
)


def _comma(items: Sequence[str]) -> str:
    items = list(items)
    if not items:
        return "none"
    if len(items) == 1:
        return items[0]
    return ", ".join(items[:-1]) + " and " + items[-1]


def _count_by_status(correlation) -> Dict[str, int]:
    counts = {"MATCH": 0, "MISMATCH": 0, "UNKNOWN": 0, "NOT_APPLICABLE": 0}
    for bucket in ("matches", "mismatches", "unknowns", "not_applicable"):
        for _ in getattr(correlation, bucket, ()) or ():
            key = "MATCH" if bucket == "matches" else (
                "MISMATCH" if bucket == "mismatches" else (
                    "UNKNOWN" if bucket == "unknowns" else "NOT_APPLICABLE"
                )
            )
            counts[key] += 1
    return counts


def _mismatch_variables(correlation) -> List[str]:
    return sorted(
        str(outcome.get("variable"))
        for outcome in getattr(correlation, "mismatches", ()) or ()
        if isinstance(outcome, dict) and outcome.get("variable")
    )


def _unknown_variables(correlation) -> List[str]:
    return sorted(
        {
            str(outcome.get("variable"))
            for outcome in getattr(correlation, "unknowns", ()) or ()
            if isinstance(outcome, dict) and outcome.get("variable")
        }
    )


def _findings_by_severity(assessment: RiskAssessment) -> List[Any]:
    return sorted(
        assessment.findings,
        key=lambda finding: (-SEVERITY_RANK[finding.severity], finding.finding_id),
    )


def _unknown_crypto_properties(crypto: Optional[CryptoEvidence]) -> List[str]:
    if crypto is None:
        return []
    return [
        prop.name for prop in crypto.properties if prop.state == STATE_UNKNOWN
    ]


def _unknown_metadata_dimensions(metadata: Optional[MetadataExposure]) -> List[str]:
    if metadata is None:
        return []
    return [
        dimension.dimension
        for dimension in metadata.observable_metadata
        if not dimension.observable
    ]


def _risk_line(assessment: RiskAssessment) -> str:
    detail = (assessment.metadata or {}).get("score_detail") or {}
    contributions = detail.get("contributions") or ()
    scored = sum(1 for row in contributions if row.get("added"))
    return (
        f"risk score {assessment.overall_score}/100 at severity "
        f"{assessment.severity}, from {len(assessment.findings)} finding(s) "
        f"({scored} contributed to the score under the per-category cap)."
    )


def _evidence_support(finding: Any) -> str:
    """How one finding is supported, read from the finding's own evidence.

    Quotes ``finding.evidence`` -- the risk engine's structured block -- so the
    report can never name a reference the finding does not carry.
    """
    evidence = finding.evidence or {}
    refs = evidence.get("refs") or []
    identifiers = [
        ref.get("evidence_id") for ref in refs
        if isinstance(ref, dict) and ref.get("evidence_id")
    ]
    if refs:
        support = f"{evidence.get('ref_count')} reference(s)"
        if identifiers:
            support += f" ({', '.join(identifiers)})"
    else:
        support = (
            "no evidence reference; its support is the recorded value itself "
            "(expected_value / observed_value)"
        )
    return (
        f"{finding.finding_id}: {evidence.get('evidence_type')} evidence in "
        f"state {evidence.get('state')}, {support}."
    )


def _executive_summary_paragraphs(assessment: RiskAssessment) -> tuple:
    """The brief's executive-summary values, read and never recomputed."""
    return (
        f"Assessment status: {STATE_ASSESSED}.",
        f"Overall risk score: {assessment.overall_score}/100.",
        f"Severity: {assessment.severity}.",
        f"Finding count: {len(assessment.findings)}.",
        "All four values are quoted from the risk engine's assessment object "
        "and this report's own state; this section performs no scoring.",
    )


def _assessment_evidence_paragraph(assessment: RiskAssessment) -> str:
    findings = _findings_by_severity(assessment)
    if not findings:
        return (
            "Evidence behind the findings: none, because no finding was "
            "raised. An empty list is not evidence that the tunnel is sound."
        )
    return "Evidence behind the findings: " + " ".join(
        _evidence_support(finding) for finding in findings
    )


def _assessment_limitation_paragraphs(assessment: RiskAssessment) -> List[str]:
    """The risk engine's own recorded limitations, quoted and never extended."""
    metadata = assessment.metadata or {}
    paragraphs: List[str] = []
    policy_note = (metadata.get("evidence_policy") or {}).get("note")
    if policy_note:
        paragraphs.append(f"Evidence policy: {policy_note}.")
    handling = metadata.get("unknown_handling") or {}
    if handling:
        paragraphs.append(
            "Unknown handling, as the risk engine records it: "
            + ", ".join(
                f"{key}={value}" for key, value in sorted(handling.items())
            )
            + "."
        )
    configuration_only = [
        finding.finding_id for finding in assessment.findings
        if not finding.runtime_applicable
    ]
    if configuration_only:
        paragraphs.append(
            "Configuration-only findings (runtime_applicable=false): "
            + _comma(configuration_only)
            + ". Each is a configuration weakness, not runtime packet "
                      "evidence, so no runtime claim is made for it."
        )
    if not paragraphs:
        paragraphs.append(
            "The risk engine recorded no additional limitation for this "
            "assessment beyond the report-level ones."
        )
    return paragraphs


def _remediation_paragraphs(threat: Optional[Any]) -> List[str]:
    """Finding-specific remediation, quoted verbatim from the threat matrix.

    The recommendation cell is the only remediation vocabulary this backend
    has: it quotes the response rule registry. This report renders it, it
    never words one of its own.
    """
    if threat is None:
        return [
            "No threat matrix was attached to this report, so no "
            "finding-specific remediation is quoted here."
        ]
    entries = list(getattr(threat, "entries", ()) or ())
    if not entries:
        return [
            "No threat-matrix row exists for this assessment, so no "
            "finding-specific remediation is quoted here."
        ]
    paragraphs = [
        "Quoted verbatim from the threat matrix recommendation cell "
        "(correlation.analysis.threat_matrix); this report writes no "
        "remediation text of its own."
    ]
    for entry in entries:
        recommendation = getattr(entry, "recommendation", None) or {}
        text = recommendation.get("text")
        if text:
            paragraphs.append(f"{getattr(entry, 'finding', None)}: {text}")
    return paragraphs


# ---------------------------------------------------------------------------
# technical report
# ---------------------------------------------------------------------------

def build_technical_report(inputs: ReportInputs) -> TechnicalReport:
    """Assemble the analyst-facing document from the products already built."""
    expected = inputs.expected
    observed = inputs.observed
    correlation = inputs.correlation
    assessment = inputs.assessment
    sections: List[ReportSection] = []

    sections.append(
        ReportSection(
            "1. Executive summary",
            _executive_summary_paragraphs(assessment),
            "risk engine assessment state + report state (quoted, never "
            "recomputed)",
        )
    )

    sections.append(
        ReportSection(
            "2. Scope and identity",
            (
                f"Assessment {inputs.assessment_id} (scenario slot "
                f"{inputs.slot!r}) covers: {inputs.scenario}.",
                "This report quotes values produced by the Phase 4 comparison, "
                "Phase 6 risk engine, Phase 7 explainability engine and the "
                "Phase 9 analysis products. Nothing in it is recomputed.",
            ),
            "store + assessment identity",
        )
    )

    sections.append(
        ReportSection(
            "3. Expected configuration (what the plan asks for)",
            (
                f"The plan configures {expected.mode} mode over "
                f"{expected.address_family} for a {expected.traffic.profile!r} "
                f"traffic profile of {expected.traffic.duration}s on port "
                f"{expected.traffic.port}, posture band "
                f"{expected.security_posture!r}.",
                f"IKE: version {expected.ike.version}, encryption "
                f"{expected.ike.encryption}, integrity "
                f"{expected.ike.integrity}, DH group "
                f"{expected.ike.dh_group}. ESP: encryption "
                f"{expected.esp.encryption}, integrity "
                f"{expected.esp.integrity}, DH group "
                f"{expected.esp.dh_group}, PFS {expected.esp.pfs}.",
                "Every value in this section is CONFIGURED state: it is what "
                "the operator asked for, not what the capture proved.",
            ),
            "expected configuration (materialized plan)",
        )
    )

    if inputs.sa is not None:
        summary = inputs.sa.summary or {}
        paragraphs = [inputs.sa.reason]
        if summary.get("snapshot_timestamp_ns"):
            paragraphs.append(
                f"The observation snapshot is timestamped at "
                f"{summary['snapshot_timestamp_ns']} ns with "
                f"{summary.get('total_packets')} packet(s) across "
                f"{summary.get('association_count')} security association(s)."
            )
        paragraphs.append(
            "Lifetime, rekey interval and IKE SA establishment are "
            "NOT_AVAILABLE: the observation path records neither, so this "
            "report states them as unavailable rather than as satisfied."
        )
        sections.append(
            ReportSection(
                "4. Security association lifecycle",
                tuple(paragraphs),
                "sa analysis (correlation.analysis.sa)",
            )
        )

    if inputs.crypto is not None:
        established = [
            prop.name
            for prop in inputs.crypto.properties
            if prop.state == STATE_OBSERVED
        ]
        unknown = _unknown_crypto_properties(inputs.crypto)
        sections.append(
            ReportSection(
                "5. Runtime cryptographic evidence",
                (
                    inputs.crypto.reason,
                    "Established at runtime: "
                    + (_comma(established) if established else "nothing")
                    + ".",
                    "Not established (state UNKNOWN, configured value quoted "
                    "alongside): " + _comma(unknown) + ".",
                    "No configured value is ever promoted to a runtime value "
                    "in this section.",
                ),
                "crypto evidence (correlation.analysis.crypto_evidence)",
            )
        )

    if inputs.replay is not None:
        sections.append(
            ReportSection(
                "6. Replay protection",
                (
                    f"Replay assessment status: {inputs.replay.status}. "
                    + inputs.replay.reason,
                    f"duplicate_sequences="
                    f"{inputs.replay.duplicate_sequences}, "
                    f"backward_sequences={inputs.replay.backward_sequences}, "
                    f"sequence_gaps={inputs.replay.sequence_gaps}, "
                    f"highest_sequence={inputs.replay.highest_sequence}. "
                    "Gaps are reported separately and are never counted as "
                    "replay evidence.",
                ),
                "replay analysis (correlation.analysis.replay)",
            )
        )

    if inputs.metadata is not None:
        sections.append(
            ReportSection(
                "7. Metadata exposure",
                (
                    inputs.metadata.reason,
                    "Observable dimensions: "
                    + _comma([
                        dimension.dimension
                        for dimension in inputs.metadata.observable_metadata
                        if dimension.observable
                    ])
                    + ".",
                    "Not observable: "
                    + _comma(_unknown_metadata_dimensions(inputs.metadata))
                    + ". 'Not observable' means this sensor recorded no value; "
                    "it never means the traffic is safe.",
                ),
                "metadata exposure (correlation.analysis.metadata)",
            )
        )

    counts = _count_by_status(correlation)
    sections.append(
        ReportSection(
            "8. Comparison results",
            (
                f"Correlation status {correlation.status}: "
                f"{counts['MATCH']} MATCH, {counts['MISMATCH']} MISMATCH, "
                f"{counts['UNKNOWN']} UNKNOWN, "
                f"{counts['NOT_APPLICABLE']} NOT_APPLICABLE.",
                "Confirmed mismatches: "
                + (_comma(_mismatch_variables(correlation))
                   if _mismatch_variables(correlation) else "none")
                + ".",
                "Unresolved variables: "
                + (_comma(_unknown_variables(correlation))
                   if _unknown_variables(correlation) else "none")
                + ". UNKNOWN is reported as UNKNOWN; it is never collapsed "
                  "into a MATCH or into a MISMATCH.",
            ),
            "correlation (Phase 4 comparison)",
        )
    )

    sections.append(
        ReportSection(
            "9. Risk assessment",
            (
                _risk_line(assessment),
                "Findings, in severity order: "
                + (
                    "; ".join(
                        f"{finding.finding_id} [{finding.severity}] "
                        f"{finding.title} (rule {finding.rule_id}, source "
                        f"{finding.source})"
                        for finding in _findings_by_severity(assessment)
                    )
                    if assessment.findings else "none"
                )
                + ".",
                _assessment_evidence_paragraph(assessment),
                *_assessment_limitation_paragraphs(assessment),
                "Score, severity and every finding come from the risk engine; "
                "this report does not recompute any of them.",
            ),
            "risk assessment (Phase 6)",
        )
    )

    ml = inputs.ml
    if ml is None or not ml.get("present"):
        sections.append(
            ReportSection(
                "10. Machine-learning evidence",
                (
                    "No ML result was consumed for this assessment, so no "
                    "model output appears anywhere in this report.",
                ),
                "ml view",
            )
        )
    else:
        verdict = ml.get("predicted_vs_policy") or {}
        sections.append(
            ReportSection(
                "10. Machine-learning evidence",
                (
                    f"Model {ml.get('model')!r} version "
                    f"{ml.get('model_version')!r}, inference status "
                    f"{ml.get('inference_status')!r}: predicted class "
                    f"{ml.get('predicted_class')!r} at confidence "
                    f"{ml.get('classification_confidence')}.",
                    "Predicted class vs policy expectation: "
                    f"{verdict.get('status')!r} "
                    f"(predicted {verdict.get('predicted_class')!r}, policy "
                    f"{verdict.get('policy_expected_class')!r}).",
                    "This is model-derived inference, never an authoritative "
                    "protocol observation, and the anomaly fields are null "
                    "because the model has no anomaly capability.",
                ),
                "ml transparency (Phase 5 view)",
            )
        )

    if inputs.threat is not None:
        sections.append(
            ReportSection(
                "11. Threat matrix",
                (inputs.threat.reason,),
                "threat matrix (correlation.analysis.threat_matrix)",
            )
        )

    plan = inputs.response_plan
    if plan is None:
        sections.append(
            ReportSection(
                "12. Response plan",
                (
                    "No response plan was attached to this report, so no "
                    "action is prescribed here.",
                ),
                "response planner",
            )
        )
    else:
        recommendations = plan.get("recommendations") or []
        sections.append(
            ReportSection(
                "12. Response plan",
                (
                    f"{len(recommendations)} recommendation(s), approval "
                    f"required: {plan.get('requires_approval')}, "
                    f"authorization required: "
                    f"{plan.get('requires_authorization')} "
                    f"(policy {plan.get('policy_version')}).",
                    "Actions: "
                    + (
                        _comma([
                            f"{rec.get('action')} for {rec.get('finding_id')}"
                            for rec in recommendations
                        ])
                        if recommendations else "none"
                    )
                    + ". A plan recommends; it never executes.",
                ),
                "response planner",
            )
        )

    remediation = _remediation_paragraphs(inputs.threat)
    if remediation:
        sections.append(
            ReportSection(
                "13. Recommendations (finding-specific remediation)",
                tuple(remediation),
                "threat matrix recommendation cell "
                "(correlation.analysis.threat_matrix)",
            )
        )

    if inputs.sources:
        sections.append(
            ReportSection(
                "14. Evidence and provenance",
                tuple(
                    f"{source.get('path')} ({source.get('role')})"
                    for source in inputs.sources
                ),
                "store provenance",
            )
        )

    return TechnicalReport(
        state=STATE_ASSESSED,
        reason=(
            f"Technical report assembled from {len(sections)} section(s), "
            "each naming the product its values came from."
        ),
        source="all Phase 4-9 products for this assessment",
        assessment_id=inputs.assessment_id,
        sections=tuple(sections),
        limitations=(
            "Sections are assembled, never re-derived: a value that is "
            "unknown in its source product is unknown here.",
            "Configured values, observed values and inferences are labelled "
            "in the section that reports them and are never merged.",
            "Absence of a statement is not a claim that the condition holds.",
        ),
    )


# ---------------------------------------------------------------------------
# executive report
# ---------------------------------------------------------------------------

def _answer(question: str, statements: Sequence[str], evidence: Sequence[str],
             state: str) -> Dict[str, Any]:
    return {
        "question": question,
        "state": state,
        "statements": list(statements),
        "evidence": list(evidence),
        "answered": bool(statements),
    }


def build_executive_report(inputs: ReportInputs) -> ExecutiveReport:
    """Answer the brief's five executive questions from the same products."""
    expected = inputs.expected
    observed = inputs.observed
    correlation = inputs.correlation
    assessment = inputs.assessment
    answers: Dict[str, Any] = {}
    has_snapshot = bool(
        observed is not None and getattr(observed, "timestamp_ns", 0)
    )

    # 1. what was assessed -- the assessment's identity and scope first, then
    #    the data plane and the plan it covers.
    assessed: List[str] = []
    assessed_evidence: List[str] = []
    assessed.append(
        f"Assessment {inputs.assessment_id} (scenario slot {inputs.slot!r}) "
        f"assesses: {inputs.scenario}."
    )
    assessed_evidence.append("store assessment identity and scenario label")
    if has_snapshot:
        endpoints = dict(getattr(observed, "endpoints", {}) or {})
        assessed.append(
            f"An IPsec data plane configured for {expected.mode} mode over "
            f"{expected.address_family} between "
            f"{endpoints.get('a') or 'an unrecorded endpoint'} and "
            f"{endpoints.get('b') or 'an unrecorded endpoint'}, carrying "
            f"{observed.packets_seen} packet(s) / {observed.bytes_seen} "
            f"byte(s) under {len(observed.spis)} security association(s)."
        )
        assessed_evidence.append(
            f"observed-state snapshot at {observed.timestamp_ns} ns"
        )
        assessed.append(
            f"ESP is {'present' if observed.esp_seen else 'absent'}, AH is "
            f"{'present' if observed.ah_seen else 'absent'}, IKE is "
            f"{'present' if observed.ike_seen else 'absent'} in the "
            "observation window."
        )
        assessed_evidence.append("esp_seen / ah_seen / ike_seen counters")
    else:
        assessed.append(
            "No observed-state snapshot was supplied, so what is running on "
            "the wire could not be observed for this assessment; only the "
            "plan's configuration is on record."
        )
        assessed_evidence.append("no observed-state snapshot attached")
    assessed.append(
        f"The plan configures a {expected.security_posture!r} posture "
        f"({expected.esp.encryption} / {expected.esp.integrity} / "
        f"{expected.esp.dh_group}, PFS {expected.esp.pfs}) for a "
        f"{expected.traffic.profile!r} profile."
    )
    assessed_evidence.append("materialized plan (expected configuration)")
    answers["what_was_assessed"] = _answer(
        EXECUTIVE_QUESTIONS[0],
        assessed,
        assessed_evidence,
        STATE_OBSERVED if has_snapshot else STATE_ASSESSED,
    )

    # 2. security posture -- the risk verdict, the configured posture beside
    #    it, the comparison result, and every gap still open.
    posture: List[str] = []
    posture_evidence: List[str] = []
    posture.append(f"Overall {_risk_line(assessment)}")
    posture_evidence.append("risk engine score and findings (Phase 6)")
    posture.append(
        f"The configured posture is {expected.security_posture!r} "
        f"({expected.esp.encryption} / {expected.esp.integrity} / "
        f"{expected.esp.dh_group}, PFS {expected.esp.pfs}); it is what the "
        "plan asks for, not what the capture proved."
    )
    posture_evidence.append("materialized plan (expected configuration)")
    counts = _count_by_status(correlation)
    posture.append(
        f"Correlation status {correlation.status}: {counts['MATCH']} "
        f"agreement(s), {counts['MISMATCH']} contradiction(s), "
        f"{counts['UNKNOWN']} unknown value(s), "
        f"{counts['NOT_APPLICABLE']} not-applicable value(s)."
    )
    posture_evidence.append("Phase 4 comparison result")
    if inputs.metadata is not None:
        posture.append(
            f"Metadata exposure is rated {inputs.metadata.risk_level}: "
            + inputs.metadata.reason.split("; ", 1)[-1]
        )
        posture_evidence.append("metadata exposure ladder")
    unknown_vars = _unknown_variables(correlation)
    if unknown_vars:
        posture.append(
            "Variables the observation could not decide: "
            + _comma(unknown_vars) + "."
        )
        posture_evidence.append("Phase 4 UNKNOWN outcomes")
    crypto_unknown = _unknown_crypto_properties(inputs.crypto)
    if crypto_unknown:
        posture.append(
            "Runtime cryptographic values this capture cannot establish: "
            + _comma(crypto_unknown)
            + ". The configured values are reported beside them and are "
              "explicitly not runtime evidence."
        )
        posture_evidence.append("crypto evidence product")
    if (inputs.replay is not None
            and inputs.replay.status == "INSUFFICIENT_DATA"):
        posture.append(
            "Replay protection could not be assessed: the sequence evidence "
            "that exists is insufficient to rule duplicates out."
        )
        posture_evidence.append("replay analysis (INSUFFICIENT_DATA)")
    metadata_unknown = _unknown_metadata_dimensions(inputs.metadata)
    if metadata_unknown:
        posture.append(
            "Metadata dimensions with no recorded value: "
            + _comma(metadata_unknown) + "."
        )
        posture_evidence.append("metadata exposure product")
    posture.append(
        "Lifetime, rekey interval and IKE SA establishment are not recorded "
        "by the observation path and are reported NOT_AVAILABLE."
    )
    posture_evidence.append("sa analysis")
    if not unknown_vars and not crypto_unknown:
        posture.append(
            "No additional open question beyond the standing gaps."
        )
    answers["security_posture"] = _answer(
        EXECUTIVE_QUESTIONS[1], posture, posture_evidence, STATE_ASSESSED,
    )

    # 3. major risks -- the highest-severity findings and the exposure rating.
    risky: List[str] = []
    risky_evidence: List[str] = []
    top = _findings_by_severity(assessment)
    if top:
        risky.append(
            f"{len(assessment.findings)} finding(s) are on record; the "
            "highest-severity items are: "
            + "; ".join(
                f"{finding.finding_id} [{finding.severity}] {finding.title}"
                for finding in top[:3]
            )
            + "."
        )
        risky_evidence.append(
            "Phase 6 risk engine findings in severity order"
        )
    else:
        risky.append(
            "No finding was raised, so nothing in this assessment is "
            "flagged as risky. That is a statement about the evidence, not a "
            "certificate that the tunnel is safe."
        )
        risky_evidence.append("Phase 6 risk engine raised no finding")
    if inputs.metadata is not None:
        risky.append(
            f"Metadata exposure is rated {inputs.metadata.risk_level}: "
            + inputs.metadata.reason.split("; ", 1)[-1]
        )
        risky_evidence.append("metadata exposure ladder")
    answers["major_risks"] = _answer(
        EXECUTIVE_QUESTIONS[2], risky, risky_evidence, STATE_ASSESSED,
    )

    # 4. the evidence behind those risks, finding by finding.
    evidence_statements: List[str] = []
    evidence_backing: List[str] = []
    findings = _findings_by_severity(assessment)
    mismatches = _mismatch_variables(correlation)
    if findings:
        evidence_statements.append(
            "Evidence behind the findings, as the risk engine records it: "
            + " ".join(_evidence_support(finding) for finding in findings)
        )
        evidence_backing.append(
            "risk engine evidence blocks (evidence_type, state, ref_count, "
            "evidence_id)"
        )
    else:
        evidence_statements.append(
            "No finding was raised, so no risk evidence exists to report; "
            "an empty list is not evidence that the tunnel is sound."
        )
        evidence_backing.append("risk engine produced no finding evidence")
    if mismatches:
        evidence_statements.append(
            "Contradictions are backed by the Phase 4 comparison result: "
            + _comma(mismatches) + "."
        )
        evidence_backing.append("Phase 4 comparison result rows")
    observed_findings = [
        finding for finding in findings
        if finding.source in (
            "OBSERVED_PROTOCOL", "CORRELATION", "OBSERVATION"
        )
    ]
    if observed_findings:
        evidence_statements.append(
            "Findings backed by a runtime observation: "
            + _comma([
                f"{finding.finding_id} ({finding.severity})"
                for finding in observed_findings
            ])
            + "."
        )
        evidence_backing.append(
            "risk engine findings with an observation source"
        )
    else:
        evidence_statements.append(
            "No finding in this assessment is backed by a runtime "
            "observation; every finding comes from the configuration or from "
            "model output."
        )
    if inputs.replay is not None and inputs.replay.status == "OBSERVED":
        evidence_statements.append(
            f"Replay evidence is OBSERVED: "
            f"{inputs.replay.duplicate_sequences} duplicate sequence "
            "number(s) were carried in the recorded packet journal."
        )
        evidence_backing.append("replay analysis of the packet journal")
    evidence_state = (
        STATE_OBSERVED
        if any(
            (finding.evidence or {}).get("state") == STATE_OBSERVED
            for finding in findings
        )
        else STATE_ASSESSED
    )
    answers["evidence_supporting_risks"] = _answer(
        EXECUTIVE_QUESTIONS[3], evidence_statements, evidence_backing,
        evidence_state,
    )

    # 5. what should be fixed -- the response plan's own recommendations.
    action: List[str] = []
    action_evidence: List[str] = []
    plan = inputs.response_plan
    if plan is None or not plan.get("recommendations"):
        action.append(
            "No response recommendation was produced for this assessment, so "
            "this report prescribes nothing. Review the open evidence gaps "
            "before concluding that no action is needed."
        )
        action_evidence.append("response planner produced no recommendation")
    else:
        recommendations = plan.get("recommendations") or []
        action.append(
            f"{len(recommendations)} response recommendation(s) are on "
            f"record, approval required: {plan.get('requires_approval')}."
        )
        for rec in recommendations:
            action.append(
                f"{rec.get('action')} ({rec.get('priority')}) for "
                f"{rec.get('finding_id')}: {rec.get('reason')}"
            )
        action_evidence.append(
            f"response plan under policy {plan.get('policy_version')}"
        )
        if plan.get("requires_approval") or plan.get("requires_authorization"):
            action.append(
                "No action executes automatically: every recommendation here "
                "is gated by the approval and authorization requirements the "
                "response policy states."
            )
    answers["what_should_be_fixed"] = _answer(
        EXECUTIVE_QUESTIONS[4], action, action_evidence, STATE_ASSESSED,
    )

    return ExecutiveReport(
        state=STATE_ASSESSED,
        reason=(
            f"All {len(EXECUTIVE_QUESTIONS)} executive questions answered "
            "from the Phase 4-9 products; each answer names the evidence it "
            "rests on."
        ),
        source="same products as the technical report",
        assessment_id=inputs.assessment_id,
        answers=answers,
        limitations=(
            "An answer is only as good as the evidence behind it: where the "
            "evidence is absent the answer says so rather than guessing.",
            "Nothing in this report is a conclusion about intent. Findings "
            "are conditions, not accusations.",
            "UNKNOWN and NOT_AVAILABLE are reported as answers in their own "
            "right and are never converted into a negative assurance.",
        ),
    )
