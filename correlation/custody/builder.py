"""Build a chain of custody from artifacts the pipeline already produced.

This module is a **mapper**, not an engine. Given the Phase-3 expected state, the
Phase-4 correlation result, the Phase-6 risk assessment, the Phase-7 XAI result
and a Phase-8 response recommendation, it assembles the audit view of one
finding and nothing else:

* it never compares an expected value to an observed value;
* it never evaluates a rule, a severity or a score;
* it never creates, edits or drops an evidence reference;
* it never proposes a control of its own -- the recommendation is copied from a
  plan the reused :class:`~correlation.response.planner.ResponsePlanner`
  produced;
* it never reads the current time, generates an id, or iterates a set.

Every value it emits is either copied from an input or a SHA-256 over canonical
JSON of an input. Two runs over the same inputs therefore produce byte-identical
output, with the single documented exception of :meth:`EvidenceRef.verify`, which
reports on the filesystem and says so in its own status.

Observation honesty
-------------------
The most important property of this module is what it refuses to do. A passive
IPsec state snapshot does not observe the negotiated mode or ciphers
(:func:`correlation.artifacts.observed_evidence_values` returns nothing on
purpose), so the comparison engine resolves those variables to ``UNKNOWN`` with
a reason. This builder surfaces that as an ``OBSERVED`` fact whose value is
``None`` and whose detail is the comparison engine's own reason, plus an
``observation.authoritative_value_present`` integrity check with status
``unavailable`` and a matching top-level limitation.

It never fills the gap from the expected state, from a sibling variable, or from
a model. A chain that claimed an observed cipher it never saw would be worse
than no chain at all.
"""

import hashlib
import json
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from ..models.evidence import EvidenceRef
from ..models.expected import ExpectedState
from ..models.observed import ObservedState
from ..response.models import ResponseRecommendation
from ..risk.models import (
    CATEGORY_INSUFFICIENT_EVIDENCE,
    SOURCE_EVIDENCE,
    SOURCE_EXPECTED_CONFIGURATION,
    SOURCE_ML,
    RiskAssessment,
    RiskFinding,
)
from ..risk.rules import RULE_REGISTRY, RULE_TRACEABILITY
from .models import (
    AUDIT_LINKED,
    AUDIT_UNAVAILABLE,
    AUTHORITY_DERIVED,
    AUTHORITY_OBSERVATION,
    AUTHORITY_PLAN,
    CHECK_FAIL,
    CHECK_NOT_APPLICABLE,
    CHECK_PASS,
    CHECK_UNAVAILABLE,
    CUSTODY_COMPONENT,
    CUSTODY_COMPONENT_VERSION,
    CUSTODY_SCHEMA_VERSION,
    FACT_DERIVED,
    FACT_EXPECTED,
    FACT_OBSERVED,
    FACT_RECOMMENDED,
    ChainOfCustody,
    CustodyEvidenceLink,
    CustodyFact,
    CustodyIntegrityCheck,
    CustodyProvenanceArtifact,
    CustodyRecommendation,
    CustodyRuleRef,
    CustodyStep,
)

#: Statuses the comparison layer uses that mean "no authoritative observation".
_OUTCOME_WITHOUT_OBSERVATION = ("UNKNOWN", "NOT_APPLICABLE")


def canonical_digest(value: Any) -> str:
    """SHA-256 over canonical JSON, so a client can recompute the digest.

    ``sort_keys`` and tight separators make the encoding independent of dict
    ordering and of whitespace, so two clients that received the same value
    compute the same digest. ``ensure_ascii`` pins the encoding rather than
    letting it follow the interpreter default.
    """
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        default=str,
    )
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _slug(variable: str) -> str:
    """Turn a dotted variable path into a stable fact-id segment."""
    return str(variable).replace(".", "_").replace("/", "_").strip() or "unnamed"


def _outcomes_by_variable(
    correlation: Optional[Mapping[str, Any]],
) -> Dict[str, Mapping[str, Any]]:
    """Index the correlation result's outcome rows by variable.

    ``correlation`` is accepted as a mapping so both a
    :class:`~correlation.models.correlation.CorrelationResult` and its serialized
    form work. Rows are visited in the fixed MATCH -> MISMATCH -> UNKNOWN ->
    NOT_APPLICABLE order and the first row for a variable wins, so the index is
    deterministic regardless of dict ordering.
    """
    if not correlation:
        return {}
    index: Dict[str, Mapping[str, Any]] = {}
    for bucket in ("matches", "mismatches", "unknowns", "not_applicable"):
        for row in (correlation.get(bucket) or ()):
            if not isinstance(row, Mapping):
                continue
            variable = row.get("variable")
            if isinstance(variable, str) and variable and variable not in index:
                index[variable] = row
    return index


def _evidence_ids(refs: Iterable[Any]) -> Tuple[str, ...]:
    """Stable, de-duplicated ``evidence_id`` list from evidence references.

    Sorted so the list is a set in a deterministic order, and built from ids
    only -- a reference contributes its identity, never its path or payload.
    """
    ids = set()
    for ref in refs or ():
        evidence_id = getattr(ref, "evidence_id", None)
        if evidence_id is None and isinstance(ref, Mapping):
            evidence_id = ref.get("evidence_id")
        if isinstance(evidence_id, str) and evidence_id:
            ids.add(evidence_id)
    return tuple(sorted(ids))


def _base_rule_id(rule_id: str) -> Optional[str]:
    """The registry rule a per-variable rule id was specialised from, if any.

    ``correlation.mismatch.address_family`` is not itself a registry key: the
    registered rule is ``correlation.mismatch`` and the per-variable id is minted
    by the mismatch spec table. Reporting only ``registered: false`` would hide
    that the rule genuinely exists, so the resolved base is reported alongside
    it. Returns ``None`` when no dotted prefix of the id is registered either.
    """
    if rule_id in RULE_REGISTRY:
        return rule_id
    parts = str(rule_id).split(".")
    for cut in range(len(parts) - 1, 0, -1):
        candidate = ".".join(parts[:cut])
        if candidate in RULE_REGISTRY:
            return candidate
    return None


def _rule_ref(finding: RiskFinding) -> CustodyRuleRef:
    """The rule record for ``finding``, copied from the rule registry.

    An unregistered rule id is reported as unregistered rather than being given
    a synthesised description. ``registered`` asserts that the id is directly
    executable in :data:`correlation.risk.rules.RULE_REGISTRY`;
    ``base_rule_id`` names the registered rule it was specialised from when the
    exact id is a per-variable variant.
    """
    trace = dict(RULE_TRACEABILITY.get(finding.rule_id) or {})
    base = _base_rule_id(finding.rule_id)
    if not trace and base is not None:
        trace = dict(RULE_TRACEABILITY.get(base) or {})
    return CustodyRuleRef(
        rule_id=finding.rule_id,
        finding_id=finding.finding_id,
        base_rule_id=base,
        source_variable=trace.get("source_variable") or finding.related_variable,
        authoritative_source=trace.get("authoritative_source"),
        condition=trace.get("condition") or finding.condition,
        evidence_requirement=trace.get("evidence_requirement"),
        unknown_handling=trace.get("unknown_handling"),
        dedup_behavior=trace.get("dedup_behavior"),
        severity=trace.get("severity") or finding.severity,
        score_contribution=trace.get("score_contribution"),
        registered=finding.rule_id in RULE_REGISTRY,
        traceability=trace,
    )


def _score_contribution(assessment: RiskAssessment, finding_id: str) -> Optional[Mapping[str, Any]]:
    """This finding's recorded row in the risk engine's score breakdown.

    Read from the assessment the risk engine already produced, so the chain
    reports the engine's own arithmetic instead of repeating it. ``None`` when
    the breakdown has no row for the finding (for example when the score cap
    stopped aggregation before this finding was scored).
    """
    detail = (assessment.metadata or {}).get("score_detail") or {}
    for row in detail.get("contributions") or ():
        if isinstance(row, Mapping) and row.get("finding_id") == finding_id:
            return row
    return None


def _build_facts(
    *,
    finding: RiskFinding,
    assessment: RiskAssessment,
    outcomes: Mapping[str, Mapping[str, Any]],
    expected: Optional[ExpectedState],
    recommendation: Optional[ResponseRecommendation],
) -> List[CustodyFact]:
    """Assemble the ordered fact list, one entry per kind of value.

    Ordering is fixed (observed, expected, derived, recommended) and within each
    group by fact id, so the list is stable across runs.
    """
    facts: List[CustodyFact] = []
    variable = finding.related_variable
    outcome = outcomes.get(variable) if variable else None
    finding_evidence = _evidence_ids(finding.evidence_refs)

    # -- OBSERVED ------------------------------------------------------------
    # Emitted only for the finding's own variable, and only ever with the value
    # the comparison engine recorded. An UNKNOWN variable yields value ``None``
    # plus the engine's reason -- never a substituted value.
    #
    # A model-derived finding gets NO observed fact at all. Its
    # ``observed_value`` is a model verdict, and filing that under
    # ``authoritative_observation`` would assert that the protocol was observed
    # to look a certain way when only a classifier said so. The verdict is
    # emitted below as a DERIVED fact instead.
    if variable and finding.source != SOURCE_ML and outcome is not None:
        status = str(outcome.get("status") or "")
        observed_value = outcome.get("observed_value")
        if status in _OUTCOME_WITHOUT_OBSERVATION or observed_value is None:
            detail = (
                f"no authoritative observation recorded for {variable}: "
                f"{outcome.get('reason') or 'status ' + status}"
            )
        else:
            detail = str(outcome.get("reason") or "")
        facts.append(
            CustodyFact(
                fact_id=f"observed.{_slug(variable)}",
                category=FACT_OBSERVED,
                label=f"authoritative observed {variable}",
                value=observed_value,
                source=f"CorrelationOutcome[{variable}].observed_value",
                detail=detail or None,
                evidence_ids=_evidence_ids(outcome.get("evidence_refs") or ())
                or finding_evidence,
                value_digest=canonical_digest(observed_value),
            )
        )
    elif variable and finding.source != SOURCE_ML:
        facts.append(
            CustodyFact(
                fact_id=f"observed.{_slug(variable)}",
                category=FACT_OBSERVED,
                label=f"authoritative observed {variable}",
                value=None,
                source="CorrelationOutcome (absent)",
                detail=(
                    f"the comparison result carries no outcome row for {variable}; "
                    f"no observed value is claimed"
                ),
                evidence_ids=finding_evidence,
                value_digest=canonical_digest(None),
            )
        )

    # -- EXPECTED ------------------------------------------------------------
    # The plan value comes from the comparison outcome when there is one, since
    # that is where the engine resolved the canonical variable. When there is no
    # outcome row (a model-derived finding compares a traffic classification
    # against the planned profile, which is not a canonical comparison variable)
    # the value the rule recorded on the finding is used instead, so the planned
    # value is still quoted rather than dropped.
    if variable and outcome is not None and "expected_value" in outcome:
        facts.append(
            CustodyFact(
                fact_id=f"expected.{_slug(variable)}",
                category=FACT_EXPECTED,
                label=f"planned {variable}",
                value=outcome.get("expected_value"),
                source=f"CorrelationOutcome[{variable}].expected_value",
                detail=(
                    f"configured intent, resolved by comparison rule "
                    f"{outcome.get('comparison_rule') or 'n/a'}"
                ),
                evidence_ids=finding_evidence,
                value_digest=canonical_digest(outcome.get("expected_value")),
            )
        )
    elif variable and finding.expected_value is not None:
        facts.append(
            CustodyFact(
                fact_id=f"expected.{_slug(variable)}",
                category=FACT_EXPECTED,
                label=f"planned {variable}",
                value=finding.expected_value,
                source="RiskFinding.expected_value",
                detail=(
                    f"configured intent as recorded by rule {finding.rule_id}; "
                    f"this variable is not a canonical comparison variable, so no "
                    f"ComparisonOutcome resolves it"
                ),
                evidence_ids=finding_evidence,
                value_digest=canonical_digest(finding.expected_value),
            )
        )
    if expected is not None:
        for fact_id, label, value, source in (
            (
                "expected.configuration_id",
                "planned configuration id",
                expected.configuration_id,
                "ExpectedState.configuration_id",
            ),
            (
                "expected.security_posture",
                "authoritative planned security posture",
                expected.security_posture,
                "ExpectedState.security_posture",
            ),
        ):
            facts.append(
                CustodyFact(
                    fact_id=fact_id,
                    category=FACT_EXPECTED,
                    label=label,
                    value=value,
                    source=source,
                    detail=(
                        "derived upstream by the dataset planner's posture_of_config; "
                        "consumed here, never recomputed"
                        if fact_id.endswith("security_posture") else None
                    ),
                    value_digest=canonical_digest(value),
                )
            )

    # -- DERIVED -------------------------------------------------------------
    derived: List[Tuple[str, str, Any, str, str, Tuple[str, ...]]] = [
        (
            "derived.severity",
            f"rule-assigned severity ({finding.severity})",
            finding.severity,
            "RiskFinding.severity",
            f"assigned by rule {finding.rule_id}",
            finding_evidence,
        ),
        (
            "derived.reason",
            "why the rule fired",
            finding.reason,
            "RiskFinding.reason",
            f"condition: {finding.condition}",
            finding_evidence,
        ),
        (
            "derived.assessment_risk_score",
            f"assessment risk score ({assessment.overall_score})",
            assessment.overall_score,
            "RiskAssessment.overall_score",
            f"aggregate of all findings under {assessment.risk_policy_version}",
            _evidence_ids(assessment.evidence_refs),
        ),
    ]
    if variable and outcome is not None:
        derived.append(
            (
                "derived.comparison_status",
                f"comparison status for {variable}",
                outcome.get("status"),
                f"CorrelationOutcome[{variable}].status",
                str(outcome.get("reason") or ""),
                finding_evidence,
            )
        )
    if finding.source == SOURCE_ML:
        # The model's verdict, recorded as derived. Deliberately NOT an
        # observed fact: a classifier's output is evidence about traffic, never
        # an authoritative protocol observation.
        derived.append(
            (
                "derived.model_verdict",
                f"model verdict for {variable}" if variable else "model verdict",
                finding.observed_value,
                "RiskFinding.observed_value",
                (
                    f"model_version={finding.model_version or 'n/a'}; "
                    f"classification_confidence={finding.confidence!r}; a model "
                    f"verdict is derived evidence and is never filed as an "
                    f"authoritative observation"
                ),
                finding_evidence,
            )
        )
    contribution = _score_contribution(assessment, finding.finding_id)
    if contribution is not None:
        derived.append(
            (
                "derived.score_contribution",
                "points this finding added to the assessment score",
                contribution.get("added"),
                "RiskAssessment.metadata.score_detail.contributions",
                (
                    f"weight {contribution.get('weight')} for severity "
                    f"{contribution.get('severity')}"
                ),
                finding_evidence,
            )
        )
    for fact_id, label, value, source, detail, evidence in derived:
        facts.append(
            CustodyFact(
                fact_id=fact_id,
                category=FACT_DERIVED,
                label=label,
                value=value,
                source=source,
                detail=detail or None,
                evidence_ids=evidence,
                value_digest=canonical_digest(value),
            )
        )

    # -- RECOMMENDED ---------------------------------------------------------
    if recommendation is not None:
        facts.append(
            CustodyFact(
                fact_id="recommended.action",
                category=FACT_RECOMMENDED,
                label="proposed response action",
                value=recommendation.action,
                source="ResponseRecommendation.action",
                detail=(
                    f"{recommendation.rationale} (policy "
                    f"{recommendation.policy_version}; proposal only, not applied)"
                ),
                evidence_ids=_evidence_ids(recommendation.evidence_refs)
                or finding_evidence,
                value_digest=canonical_digest(recommendation.action),
            )
        )

    return sorted(facts, key=lambda fact: fact.fact_id)


def _build_steps(
    *,
    finding: RiskFinding,
    assessment: RiskAssessment,
    outcomes: Mapping[str, Mapping[str, Any]],
    expected: Optional[ExpectedState],
    observed_present: bool,
    sources: Sequence[Mapping[str, Any]],
    recommendation: Optional[ResponseRecommendation],
) -> Tuple[CustodyStep, ...]:
    """The ordered derivation, as the pipeline stages actually ran it.

    Each step names a stage that has already completed and states what it
    consumed and produced. No step is skipped when its output is absent: the
    step is still listed with an outcome saying the stage produced nothing, so
    the reader can see that the stage ran.
    """
    variable = finding.related_variable
    outcome = outcomes.get(variable) if variable else None
    plan_digests = sorted(
        str(item.get("artifact_sha256"))
        for item in sources
        if item.get("artifact_sha256")
    )
    steps: List[CustodyStep] = [
        CustodyStep(
            index=1,
            stage="expected_state",
            component="correlation.adapters.ExpectedStateAdapter",
            action="materialize the planned configuration for this sequence",
            inputs=tuple(plan_digests) or (),
            outcome=(
                f"configuration_id="
                f"{expected.configuration_id}"
                if expected is not None and expected.configuration_id
                else "no expected state was materialized for this assessment"
            ),
            authoritative=True,
        ),
        CustodyStep(
            index=2,
            stage="observed_state",
            component="ebpf.ipsec_state_builder / correlation.artifacts",
            action="supply the authoritative observation for this capture",
            inputs=(),
            outcome=(
                "an observed state was supplied"
                if observed_present
                else "no observation was supplied; every variable resolves UNKNOWN"
            ),
            authoritative=True,
        ),
        CustodyStep(
            index=3,
            stage="comparison",
            component="correlation.comparison.ComparisonEngine",
            action=(
                f"compare planned and observed {variable}"
                if variable
                else "compare planned and observed variables"
            ),
            inputs=(f"variable={variable}",) if variable else (),
            outcome=(
                f"status={outcome.get('status')} via {outcome.get('comparison_rule')}"
                if outcome is not None
                else (
                    f"no outcome row for {variable}"
                    if variable
                    else "comparison produced no row for this finding"
                )
            ),
            authoritative=True,
        ),
        CustodyStep(
            index=4,
            stage="risk_rules",
            component="correlation.risk.rules.run_rules",
            action=f"evaluate rule {finding.rule_id}",
            inputs=(f"condition={finding.condition}",),
            outcome=f"finding {finding.finding_id} raised with severity {finding.severity}",
            authoritative=True,
        ),
        CustodyStep(
            index=5,
            stage="risk_scoring",
            component="correlation.risk.scoring.score_findings",
            action="aggregate deduplicated findings into the assessment score",
            inputs=(f"policy={assessment.risk_policy_version}",),
            outcome=(
                f"score={assessment.overall_score} severity={assessment.severity}"
            ),
            authoritative=True,
        ),
        CustodyStep(
            index=6,
            stage="xai",
            component="correlation.xai.ExplainabilityEngine",
            action="derive a human-readable explanation of the existing decision",
            inputs=(f"finding_id={finding.finding_id}",),
            outcome=(
                "explanation derived; non-authoritative and unable to change any "
                "observed fact, severity, score, evidence id or provenance record"
            ),
            authoritative=False,
        ),
    ]
    if recommendation is not None:
        steps.append(
            CustodyStep(
                index=7,
                stage="response_planning",
                component="correlation.response.planner.ResponsePlanner",
                action="map the finding to a proposed control action",
                inputs=(
                    f"rule_id={recommendation.rule_id}",
                    f"policy={recommendation.policy_version}",
                ),
                outcome=(
                    f"action={recommendation.action} priority={recommendation.priority}; "
                    f"proposal only, nothing was executed"
                ),
                authoritative=False,
            )
        )
    return tuple(steps)


def _build_evidence(
    *,
    finding: RiskFinding,
    assessment: RiskAssessment,
    outcomes: Mapping[str, Mapping[str, Any]],
    refs: Sequence[EvidenceRef],
    evidence_root: Optional[str],
    verify_evidence: bool = True,
) -> Tuple[Tuple[CustodyEvidenceLink, ...], Dict[str, bool]]:
    """Evidence links plus the per-id verification status map.

    Every ref is verified through its own :meth:`EvidenceRef.verify`, which
    re-hashes the real artifact read-only. The result is reported as it comes
    back: ``invalid`` and ``unavailable`` are surfaced, never repaired and never
    upgraded to ``valid``. Refs are ordered by ``evidence_id`` for determinism.

    ``verify_evidence=False`` skips the filesystem read entirely and reports
    ``not_performed``; it never reports a check as passing that did not run.
    """
    attached: Dict[str, set] = {}
    for ref in finding.evidence_refs:
        attached.setdefault(ref.evidence_id, set()).add("finding")
    for ref in assessment.evidence_refs:
        attached.setdefault(ref.evidence_id, set()).add("assessment")
    variable = finding.related_variable
    outcome = outcomes.get(variable) if variable else None
    for ref in (outcome or {}).get("evidence_refs") or ():
        evidence_id = getattr(ref, "evidence_id", None)
        if evidence_id is None and isinstance(ref, Mapping):
            evidence_id = ref.get("evidence_id")
        if isinstance(evidence_id, str) and evidence_id:
            attached.setdefault(evidence_id, set()).add("comparison_outcome")

    seen: Dict[str, EvidenceRef] = {}
    for ref in refs or ():
        if isinstance(ref, EvidenceRef) and ref.evidence_id not in seen:
            seen[ref.evidence_id] = ref
    for ref in list(finding.evidence_refs) + list(assessment.evidence_refs):
        if ref.evidence_id not in seen:
            seen[ref.evidence_id] = ref

    links: List[CustodyEvidenceLink] = []
    statuses: Dict[str, bool] = {}
    for evidence_id in sorted(seen):
        ref = seen[evidence_id]
        if not verify_evidence:
            # The caller opted out of the re-hash. The recorded digest is still
            # served, but the artifact is reported as *not checked* rather than
            # as valid, and artifact_present stays None because the file was
            # never looked for.
            links.append(
                CustodyEvidenceLink(
                    evidence_id=evidence_id,
                    artifact_type=ref.artifact_type,
                    artifact_sha256=ref.artifact_sha256,
                    byte_size=ref.byte_size,
                    verification_status="not_performed",
                    verification_detail=(
                        "artifact re-hash was not requested (verify=false); the "
                        "recorded digest is served unverified"
                    ),
                    artifact_present=None,
                    actual_sha256=None,
                    attached_by=tuple(sorted(attached.get(evidence_id, ()))),
                )
            )
            statuses[evidence_id] = False
            continue
        try:
            verification = ref.verify(evidence_root)
        except OSError as error:
            # A verification that cannot run is reported as unverified, not as
            # a pass: an unreadable artifact is never reported as verified.
            links.append(
                CustodyEvidenceLink(
                    evidence_id=evidence_id,
                    artifact_type=ref.artifact_type,
                    artifact_sha256=ref.artifact_sha256,
                    byte_size=ref.byte_size,
                    verification_status="unverified",
                    verification_detail=f"verification could not run: {error}",
                    artifact_present=False,
                    actual_sha256=None,
                    attached_by=tuple(sorted(attached.get(evidence_id, ()))),
                )
            )
            statuses[evidence_id] = False
            continue
        passed = verification.status == "valid"
        statuses[evidence_id] = passed
        links.append(
            CustodyEvidenceLink(
                evidence_id=evidence_id,
                artifact_type=ref.artifact_type,
                artifact_sha256=ref.artifact_sha256,
                byte_size=verification.byte_size or ref.byte_size,
                verification_status=verification.status,
                verification_detail=verification.detail,
                artifact_present=verification.artifact_present,
                actual_sha256=verification.actual_sha256,
                attached_by=tuple(sorted(attached.get(evidence_id, ()))),
            )
        )
    return tuple(links), statuses


def _build_sources(
    sources: Sequence[Mapping[str, Any]],
) -> Tuple[CustodyProvenanceArtifact, ...]:
    """Copy the recorded input artifacts, keeping only disclosed fields.

    ``public_path`` is taken as given: the caller's disclosure policy already
    reduced it. Only a documented subset of the artifact record is carried, so
    an unexpected extra key in a source cannot leak into the response.
    """
    items: List[CustodyProvenanceArtifact] = []
    for raw in sources or ():
        if not isinstance(raw, Mapping):
            continue
        detail = {
            key: raw[key]
            for key in ("role", "record_type", "name", "address_family", "capture")
            if key in raw and key != "role"
        }
        items.append(
            CustodyProvenanceArtifact(
                role=str(raw.get("role") or "unspecified"),
                public_path=raw.get("public_path") or raw.get("path"),
                artifact_sha256=raw.get("artifact_sha256"),
                byte_size=raw.get("byte_size"),
                record_count=raw.get("record_count"),
                detail=detail,
            )
        )
    return tuple(sorted(items, key=lambda item: (item.role, item.public_path or "")))


def _build_integrity(
    *,
    finding: RiskFinding,
    assessment: RiskAssessment,
    outcomes: Mapping[str, Mapping[str, Any]],
    links: Sequence[CustodyEvidenceLink],
    statuses: Mapping[str, bool],
    sources: Sequence[Mapping[str, Any]],
    audit_event_ids: Sequence[str],
) -> Tuple[CustodyIntegrityCheck, ...]:
    """The integrity and provenance checks a client can re-run.

    Each check is phrased as a comparison so it is machine-evaluable, and its
    status is reported honestly: a check that could not be evaluated is
    ``unavailable``, never ``pass``.
    """
    checks: List[CustodyIntegrityCheck] = []
    variable = finding.related_variable
    outcome = outcomes.get(variable) if variable else None

    # 1. The finding record itself, digested.
    finding_digest = canonical_digest(finding.to_dict())
    checks.append(
        CustodyIntegrityCheck(
            check_id="finding.record_digest",
            description=(
                "SHA-256 over the canonical JSON of the authoritative RiskFinding; "
                "recompute it from the finding payload to detect an edited finding"
            ),
            status=CHECK_PASS,
            detail="digest computed from the RiskFinding the risk engine produced",
            observed=finding_digest,
            expected=finding_digest,
            client_verifiable=True,
        )
    )

    # 2. Evidence artifact digests, as re-hashed now.
    verifiable = tuple(link for link in links if link.verifiable)
    if not links:
        checks.append(
            CustodyIntegrityCheck(
                check_id="evidence.artifact_digests",
                description=(
                    "re-hash each referenced artifact and compare with the recorded "
                    "artifact_sha256"
                ),
                status=CHECK_NOT_APPLICABLE,
                detail=(
                    f"finding {finding.finding_id} carries no evidence reference; "
                    f"its evidence_type is {finding.evidence_type!r}"
                ),
                client_verifiable=False,
            )
        )
    else:
        invalid = tuple(
            link.evidence_id for link in verifiable
            if statuses.get(link.evidence_id) is False
            and link.verification_status == "invalid"
        )
        unverified = tuple(
            link.evidence_id for link in verifiable
            if link.verification_status not in ("valid", "invalid")
        )
        if invalid:
            status, detail = (
                CHECK_FAIL,
                f"{len(invalid)} referenced artifact(s) no longer match their recorded "
                f"digest: {', '.join(invalid)}; reported, never repaired",
            )
        elif unverified:
            status, detail = (
                CHECK_UNAVAILABLE,
                f"{len(unverified)} referenced artifact(s) could not be re-hashed "
                f"({', '.join(unverified)}); integrity is not asserted for them",
            )
        else:
            status, detail = (
                CHECK_PASS,
                f"all {len(verifiable)} referenced artifact(s) re-hashed to their "
                f"recorded digest",
            )
        checks.append(
            CustodyIntegrityCheck(
                check_id="evidence.artifact_digests",
                description=(
                    "re-hash each referenced artifact and compare with the recorded "
                    "artifact_sha256"
                ),
                status=status,
                detail=detail,
                observed=[
                    {
                        "evidence_id": link.evidence_id,
                        "artifact_sha256": link.artifact_sha256,
                        "actual_sha256": link.actual_sha256,
                    }
                    for link in verifiable
                ],
                expected=None,
                client_verifiable=True,
            )
        )

    # 3. An authoritative observed value for the finding's variable.
    if finding.source == SOURCE_EXPECTED_CONFIGURATION:
        checks.append(
            CustodyIntegrityCheck(
                check_id="observation.authoritative_value_present",
                description=(
                    "an authoritative observed value exists for the finding's variable"
                ),
                status=CHECK_NOT_APPLICABLE,
                detail=(
                    f"rule {finding.rule_id} assesses the PLANNED configuration "
                    f"({variable}); this finding asserts nothing about what was "
                    f"observed, so no observed value is required or claimed"
                ),
                client_verifiable=False,
            )
        )
    elif finding.source == SOURCE_ML:
        checks.append(
            CustodyIntegrityCheck(
                check_id="observation.authoritative_value_present",
                description=(
                    "an authoritative observed value exists for the finding's variable"
                ),
                status=CHECK_NOT_APPLICABLE,
                detail=(
                    f"finding {finding.finding_id} is model-derived (source=ML); a "
                    f"model verdict is not an authoritative protocol observation, so "
                    f"this chain records the verdict as DERIVED and claims no "
                    f"observed value"
                ),
                client_verifiable=False,
            )
        )
    else:
        observed_value = (outcome or {}).get("observed_value")
        if outcome is not None and observed_value is not None:
            checks.append(
                CustodyIntegrityCheck(
                    check_id="observation.authoritative_value_present",
                    description=(
                        "the comparison result carries an authoritative observed "
                        "value for the finding's variable"
                    ),
                    status=CHECK_PASS,
                    detail=str((outcome or {}).get("reason") or ""),
                    observed=observed_value,
                    expected=(outcome or {}).get("expected_value"),
                    client_verifiable=False,
                )
            )
        else:
            checks.append(
                CustodyIntegrityCheck(
                    check_id="observation.authoritative_value_present",
                    description=(
                        "the comparison result carries an authoritative observed "
                        "value for the finding's variable"
                    ),
                    status=CHECK_UNAVAILABLE,
                    detail=(
                        f"no authoritative observed value for {variable}: "
                        f"{(outcome or {}).get('reason') or 'no comparison outcome row'}"
                    ),
                    observed=None,
                    expected=(outcome or {}).get("expected_value"),
                    client_verifiable=False,
                )
            )

    # 4. Expected/observed coherence for an observation-based finding.
    if finding.source in (SOURCE_EXPECTED_CONFIGURATION, SOURCE_ML, SOURCE_EVIDENCE):
        checks.append(
            CustodyIntegrityCheck(
                check_id="observation.expected_observed_coherent",
                description="the recorded observed value is not the planned value",
                status=CHECK_NOT_APPLICABLE,
                detail=(
                    f"finding source is {finding.source}; this check applies to "
                    f"observation-based findings only"
                ),
                client_verifiable=False,
            )
        )
    elif outcome is not None:
        observed_value = outcome.get("observed_value")
        expected_value = outcome.get("expected_value")
        coherent = observed_value is not None and observed_value != expected_value
        checks.append(
            CustodyIntegrityCheck(
                check_id="observation.expected_observed_coherent",
                description=(
                    "the observed value the finding cites is present and differs from "
                    "the planned value, which is what makes it a discrepancy"
                ),
                status=CHECK_PASS if coherent else CHECK_FAIL,
                detail=(
                    f"observed {variable}={observed_value!r} != expected "
                    f"{expected_value!r}"
                    if coherent
                    else (
                        f"observed {variable}={observed_value!r} does not establish a "
                        f"discrepancy against expected {expected_value!r}"
                    )
                ),
                observed=observed_value,
                expected=expected_value,
                client_verifiable=False,
            )
        )

    # 5. Input artifacts are present and digested.
    provenance_sources = _build_sources(sources)
    digestless = tuple(
        str(item.public_path) for item in provenance_sources
        if not item.artifact_sha256
    )
    checks.append(
        CustodyIntegrityCheck(
            check_id="provenance.artifact_digests",
            description=(
                "every recorded input artifact carries a SHA-256 so the assessment "
                "can be rebuilt from the same bytes"
            ),
            status=(
                CHECK_FAIL if digestless
                else (CHECK_PASS if provenance_sources else CHECK_NOT_APPLICABLE)
            ),
            detail=(
                f"{len(digestless)} input artifact(s) carry no digest: "
                f"{', '.join(digestless)}"
                if digestless
                else "every recorded input artifact carries a digest"
            ),
            observed=len(provenance_sources),
            expected=None,
            client_verifiable=True,
        )
    )

    # 6. Audit chain linkage.
    checks.append(
        CustodyIntegrityCheck(
            check_id="audit.chain_linked",
            description=(
                "a content-addressed audit event exists for this assessment, so the "
                "decision is anchored in the tamper-evident journal"
            ),
            status=CHECK_PASS if audit_event_ids else CHECK_UNAVAILABLE,
            detail=(
                f"linked to {len(audit_event_ids)} audit event(s)"
                if audit_event_ids
                else (
                    "no audit event was supplied for this assessment; the chain is "
                    "built from the in-process pipeline objects and is not anchored "
                    "in a persisted journal"
                )
            ),
            observed=list(audit_event_ids),
            expected=None,
            client_verifiable=False,
        )
    )

    # 7. The derived explanation cannot have influenced the decision.
    checks.append(
        CustodyIntegrityCheck(
            check_id="xai.non_authoritative",
            description=(
                "the derived explanation carries no authority over the observed facts, "
                "the severity, the score, the evidence ids or the provenance records"
            ),
            status=CHECK_PASS,
            detail=(
                "every authoritative fact in this chain is copied from the expected "
                "state, the comparison result or the risk assessment; the XAI layer "
                "contributed only a derived explanation"
            ),
            observed=AUTHORITY_DERIVED,
            expected=f"{AUTHORITY_OBSERVATION}|{AUTHORITY_PLAN}",
            client_verifiable=False,
        )
    )

    return tuple(checks)


def _limitations(
    *,
    finding: RiskFinding,
    expected: Optional[ExpectedState],
    observed_present: bool,
    outcomes: Mapping[str, Mapping[str, Any]],
    links: Sequence[CustodyEvidenceLink],
    sources: Sequence[Mapping[str, Any]],
    audit_event_ids: Sequence[str],
    recommendation: Optional[ResponseRecommendation],
) -> Tuple[str, ...]:
    """What this chain does not establish.

    Stated as data so a client can render it and a test can assert it. Each
    entry is a fact about the limits of the evidence, not a hedge.
    """
    items: List[str] = []
    variable = finding.related_variable
    if finding.source == SOURCE_ML:
        items.append(
            f"finding {finding.finding_id} is model-derived (source=ML, model_version="
            f"{finding.model_version or 'n/a'}); a model verdict is evidence about "
            f"traffic, never an authoritative protocol observation"
        )
    if variable and finding.source != SOURCE_ML:
        outcome = outcomes.get(variable)
        if outcome is None or outcome.get("observed_value") is None:
            items.append(
                f"no authoritative observed value exists for {variable}; this chain "
                f"reports the plan and the reason the observation is unavailable, "
                f"and nothing is inferred in its place"
            )
    if not observed_present:
        items.append(
            "no observed state was supplied for this assessment, so every observed "
            "value in this chain is absent by construction"
        )
    if finding.category == CATEGORY_INSUFFICIENT_EVIDENCE:
        items.append(
            "this finding reports missing evidence, so its existence is a statement "
            "about the observation gap rather than about the system's behaviour"
        )
    if not links:
        items.append(
            f"no evidence reference is attached to this finding "
            f"(evidence_type={finding.evidence_type}); no artifact digest can be "
            f"checked for it"
        )
    else:
        for link in links:
            if link.verification_status == "invalid":
                items.append(
                    f"artifact for evidence {link.evidence_id} no longer matches its "
                    f"recorded digest; the reference is reported as invalid and was "
                    f"not repaired"
                )
            elif link.verification_status in ("unavailable", "unverified"):
                items.append(
                    f"integrity of evidence {link.evidence_id} could not be asserted "
                    f"({link.verification_status})"
                )
    if not sources:
        items.append(
            "no input artifact digests were supplied with this chain, so the "
            "assessment cannot be independently rebuilt from recorded bytes"
        )
    else:
        digestless = tuple(
            str(item.public_path)
            for item in _build_sources(sources)
            if not item.artifact_sha256
        )
        if digestless:
            items.append(
                f"{len(digestless)} input artifact(s) carry no digest "
                f"({', '.join(digestless)}), so the assessment cannot be rebuilt "
                f"from those bytes"
            )
    if not audit_event_ids:
        items.append(
            "no audit event is linked, so this chain is not anchored in the "
            "tamper-evident journal"
        )
    if recommendation is not None:
        items.append(
            f"the {recommendation.action} action is a policy proposal "
            f"({recommendation.policy_version}); it was not applied, approved or "
            f"executed, and this API exposes no route that could do so"
        )
    if expected is not None and expected.security_posture is not None:
        items.append(
            "security_posture is planner-supplied context consumed, not recomputed, "
            "here; it is not an observation and not part of the finding"
        )
    return tuple(items)


def build_chain_of_custody(
    *,
    assessment_id: str,
    finding: RiskFinding,
    assessment: RiskAssessment,
    correlation: Optional[Any] = None,
    expected: Optional[ExpectedState] = None,
    observed: Optional[ObservedState] = None,
    recommendation: Optional[ResponseRecommendation] = None,
    sources: Sequence[Mapping[str, Any]] = (),
    audit_event_ids: Sequence[str] = (),
    evidence_root: Optional[str] = None,
    observed_present: bool = True,
    verify_evidence: bool = True,
) -> ChainOfCustody:
    """Assemble the chain for one finding of one assessment.

    ``assessment_id`` is required because finding ids repeat across assessments:
    a finding id alone does not identify a decision, so the chain is keyed by
    the pair.

    ``sources`` must already be reduced to the caller's disclosure policy -- this
    function does no path redaction of its own and has no field that could carry
    an absolute host path. ``evidence_root`` is forwarded to
    :meth:`EvidenceRef.verify`; ``None`` means "verify against the recorded path".

    ``verify_evidence=False`` is the documented opt-out of that filesystem read.
    It serves the recorded digests and reports every one of them as
    ``not_performed``, so a skipped check can never be mistaken for a passed one.

    Every other parameter is a read. Nothing is written, dispatched or mutated,
    and no new detection, comparison or severity is produced here.
    """
    if not isinstance(assessment_id, str) or not assessment_id.strip():
        raise ValueError("assessment_id must be a non-empty string")
    if not isinstance(finding, RiskFinding):
        raise TypeError("finding must be a RiskFinding")
    if not isinstance(assessment, RiskAssessment):
        raise TypeError("assessment must be a RiskAssessment")
    if not any(item.finding_id == finding.finding_id for item in assessment.findings):
        raise ValueError(
            f"finding {finding.finding_id!r} is not part of assessment "
            f"{assessment_id!r}; a chain cannot explain a decision that assessment "
            f"did not make"
        )

    outcomes = _outcomes_by_variable(
        correlation.to_dict() if hasattr(correlation, "to_dict") else correlation
    )
    provenance_sources = _build_sources(sources)
    links, statuses = _build_evidence(
        finding=finding,
        assessment=assessment,
        outcomes=outcomes,
        refs=tuple(
            ref
            for ref in list(finding.evidence_refs) + list(assessment.evidence_refs)
        ),
        evidence_root=evidence_root,
        verify_evidence=verify_evidence,
    )
    audit_ids = tuple(sorted({str(item) for item in audit_event_ids if item}))

    return ChainOfCustody(
        schema_version=CUSTODY_SCHEMA_VERSION,
        component=CUSTODY_COMPONENT,
        component_version=CUSTODY_COMPONENT_VERSION,
        assessment_id=assessment_id,
        finding_id=finding.finding_id,
        finding_digest=canonical_digest(finding.to_dict()),
        title=finding.title,
        summary=(
            f"Rule {finding.rule_id} raised {finding.severity} finding "
            f"{finding.finding_id} from source {finding.source}: {finding.reason}"
        ),
        category=finding.category,
        severity=finding.severity,
        risk_score=assessment.overall_score,
        risk_severity=assessment.severity,
        risk_policy_version=assessment.risk_policy_version,
        risk_engine_version=assessment.risk_engine_version,
        identity=assessment.identity.to_dict(),
        rule=_rule_ref(finding),
        facts=tuple(
            _build_facts(
                finding=finding,
                assessment=assessment,
                outcomes=outcomes,
                expected=expected,
                recommendation=recommendation,
            )
        ),
        steps=_build_steps(
            finding=finding,
            assessment=assessment,
            outcomes=outcomes,
            expected=expected,
            observed_present=observed_present,
            sources=sources,
            recommendation=recommendation,
        ),
        evidence=links,
        sources=provenance_sources,
        integrity=_build_integrity(
            finding=finding,
            assessment=assessment,
            outcomes=outcomes,
            links=links,
            statuses=statuses,
            sources=sources,
            audit_event_ids=audit_ids,
        ),
        recommendation=(
            CustodyRecommendation(
                recommendation_id=recommendation.recommendation_id,
                action=recommendation.action,
                priority=recommendation.priority,
                policy_version=recommendation.policy_version,
                reason=recommendation.reason,
                rationale=recommendation.rationale,
                authorization_required=recommendation.authorization_required,
                approval_required=recommendation.approval_required,
                required_roles=tuple(recommendation.required_roles),
                limitations=tuple(recommendation.limitations),
            )
            if recommendation is not None
            else None
        ),
        audit_event_ids=audit_ids,
        audit_linkage_status=AUDIT_LINKED if audit_ids else AUDIT_UNAVAILABLE,
        limitations=_limitations(
            finding=finding,
            expected=expected,
            observed_present=observed_present,
            outcomes=outcomes,
            links=links,
            sources=sources,
            audit_event_ids=audit_ids,
            recommendation=recommendation,
        ),
        determinism={
            "deterministic": True,
            "reads_wall_clock": False,
            "generates_random_ids": False,
            "order": "facts sorted by fact_id; evidence sorted by evidence_id; "
                     "steps ordered by index",
            "digest_algorithm": "sha256(canonical_json)",
            "canonical_json": "sort_keys=true, separators=(',',':'), ensure_ascii=true",
            "filesystem_dependent_fields": [
                "evidence[].verification_status",
                "evidence[].actual_sha256",
                "evidence[].artifact_present",
                "evidence[].verification_detail",
                "evidence[].byte_size",
                "integrity[evidence.artifact_digests].status",
                "integrity[evidence.artifact_digests].detail",
                "integrity[evidence.artifact_digests].observed",
            ],
        },
        read_only=True,
    )
