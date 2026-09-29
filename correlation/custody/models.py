"""Chain-of-custody domain models (read-only, derived, deterministic).

Why this layer exists
---------------------
A finding produced by :mod:`correlation.risk` answers *what* is wrong. It does
not, on its own, answer the auditor's question: *prove it to me*. An auditor
needs the ordered list of authoritative inputs, the exact rule that fired, the
observed-versus-expected-versus-derived split, the content-addressed evidence
behind it, the ordered derivation steps, and a set of integrity checks that a
client can re-run itself.

This module supplies that container. It supplies nothing else:

* It defines **no** new analysis. Every fact is copied or canonically digested
  from an object that already exists (Phase 3 expected state, Phase 4 comparison
  outcomes, Phase 6 risk assessment, Phase 7 XAI, Phase 8 response plan).
* It defines **no** new evidence. Evidence appears only as stable
  ``evidence_id`` / ``artifact_sha256`` pairs carried by an existing
  :class:`~correlation.models.evidence.EvidenceRef`. No PCAP bytes, no payload,
  no embedded blob, ever.
* It invents **no** filesystem paths. Provenance artifacts arrive already
  redacted by the caller's policy; this layer never sees an absolute path.
* It is **non-authoritative**. A custody chain explains a decision, it cannot
  change a finding id, a severity, a score, an observed value, an evidence
  identity or a provenance record. In particular the derived XAI explanation is
  carried as ``DERIVED`` and is explicitly flagged as unable to influence the
  authoritative facts.

Authority vocabulary
--------------------
Every fact carries both a *category* (where the value came from) and an
*authority* (what may be relied on). Keeping them separate is what stops a
planned value, a model output or a policy recommendation from being read as
something that was actually observed:

======================  ==============================  ==============================
category                authority                       meaning
======================  ==============================  ==============================
``OBSERVED``            ``authoritative_observation``   read from the observation
                                                      contract; the only category
                                                      that can support "it happened"
``EXPECTED``            ``authoritative_plan``          the configured/planned
                                                      intent; authoritative about
                                                      intent, never about reality
``DERIVED``             ``derived_non_authoritative``   computed by a rule, the risk
                                                      model, the score aggregation
                                                      or the XAI layer
``RECOMMENDED``         ``proposed_non_authoritative`` a control proposal from the
                                                      response policy; not a
                                                      decision and never executed
======================  ==============================  ==============================

Determinism
-----------
No wall-clock read, no UUID, no random, no set iteration, no locale-sensitive
formatting and no dependence on dict insertion accidents: every collection is
emitted in an order derived from its inputs, and every ``fact_id`` / ``check_id``
is a stable readable slug or a SHA-256 over canonical JSON. The only value that
can change between two runs of the same pipeline over unchanged inputs is an
``EvidenceRef.verify()`` outcome, which is a statement about the filesystem and
is labelled as such.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, Mapping, Optional, Sequence, Tuple

from ..models._base import JsonModel

CUSTODY_SCHEMA_VERSION = "v1"
CUSTODY_COMPONENT = "correlation.custody"
CUSTODY_COMPONENT_VERSION = "custody-v1"

# ---- fact categories --------------------------------------------------------
FACT_OBSERVED = "OBSERVED"
FACT_EXPECTED = "EXPECTED"
FACT_DERIVED = "DERIVED"
FACT_RECOMMENDED = "RECOMMENDED"
#: Declared, operator-supplied assessment context (asset role, criticality,
#: mission impact). Not an observation and never in
#: :data:`AUTHORITATIVE_CATEGORIES`: configured context may shape a
#: contextualised risk number, but it can never be cited as evidence that
#: something was seen on the wire.
FACT_CONFIGURED = "CONFIGURED"
FACT_CATEGORIES: Tuple[str, ...] = (
    FACT_OBSERVED,
    FACT_EXPECTED,
    FACT_DERIVED,
    FACT_RECOMMENDED,
    FACT_CONFIGURED,
)

# ---- authority levels -------------------------------------------------------
#: The only authority that can support "this was observed to be true".
AUTHORITY_OBSERVATION = "authoritative_observation"
#: Authoritative about configured intent, never about what happened.
AUTHORITY_PLAN = "authoritative_plan"
#: Computed from other facts; cannot be cited as a primary source.
AUTHORITY_DERIVED = "derived_non_authoritative"
#: A control proposal. Not a decision; never applied by this API.
AUTHORITY_PROPOSED = "proposed_non_authoritative"
#: Declared assessment input. Authoritative about *what the operator said*, and
#: about nothing that happened on the network.
AUTHORITY_CONFIGURED = "configured_assessment_context"

CATEGORY_AUTHORITY: Dict[str, str] = {
    FACT_OBSERVED: AUTHORITY_OBSERVATION,
    FACT_EXPECTED: AUTHORITY_PLAN,
    FACT_DERIVED: AUTHORITY_DERIVED,
    FACT_RECOMMENDED: AUTHORITY_PROPOSED,
    FACT_CONFIGURED: AUTHORITY_CONFIGURED,
}

#: Categories that may be cited as a primary source for the finding.
AUTHORITATIVE_CATEGORIES: Tuple[str, ...] = (FACT_OBSERVED, FACT_EXPECTED)

# ---- integrity check statuses -----------------------------------------------
#: The check passed against the state it was given.
CHECK_PASS = "pass"
#: The check ran and found a discrepancy. Reported, never repaired.
CHECK_FAIL = "fail"
#: The check could not be evaluated. Never reported as a pass.
CHECK_UNAVAILABLE = "unavailable"
#: The check is not applicable to this finding.
CHECK_NOT_APPLICABLE = "not_applicable"
CHECK_STATUSES: Tuple[str, ...] = (
    CHECK_PASS,
    CHECK_FAIL,
    CHECK_UNAVAILABLE,
    CHECK_NOT_APPLICABLE,
)

# ---- audit linkage statuses -------------------------------------------------
#: A content-addressed audit event for this assessment was located.
AUDIT_LINKED = "linked"
#: No audit event was supplied for this assessment; stated, not guessed.
AUDIT_UNAVAILABLE = "unavailable"
AUDIT_LINKAGE_STATUSES: Tuple[str, ...] = (AUDIT_LINKED, AUDIT_UNAVAILABLE)


def validate_category(value: Any) -> str:
    if value not in FACT_CATEGORIES:
        raise ValueError(
            f"custody fact category must be one of {FACT_CATEGORIES}, got {value!r}"
        )
    return value


def validate_check_status(value: Any) -> str:
    if value not in CHECK_STATUSES:
        raise ValueError(
            f"custody check status must be one of {CHECK_STATUSES}, got {value!r}"
        )
    return value


@dataclass(frozen=True)
class CustodyFact(JsonModel):
    """One value in the chain, with its category and authority stated.

    ``value`` is a JSON-compatible primitive or a JSON-compatible structure
    copied verbatim from an existing domain object. It is never recomputed and
    never rounded, normalised or paraphrased.
    """

    fact_id: str
    category: str
    label: str
    value: Any
    #: The domain object the value was copied from, e.g. ``RiskFinding.severity``.
    source: str
    #: Why this value is what it is, in the source system's own words.
    detail: Optional[str] = None
    #: ``evidence_id`` values (never paths, never payloads) backing this fact.
    evidence_ids: Tuple[str, ...] = field(default_factory=tuple)
    #: Deterministic SHA-256 over the canonical JSON of ``value``.
    value_digest: Optional[str] = None

    def __post_init__(self) -> None:
        for name in ("fact_id", "category", "label", "source"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{name} must be a non-empty string")
        validate_category(self.category)
        if self.detail is not None and (
            not isinstance(self.detail, str) or not self.detail.strip()
        ):
            raise ValueError("detail must be a non-empty string or None")
        if not isinstance(self.evidence_ids, (tuple, list)):
            raise ValueError("evidence_ids must be a tuple/list")
        for item in self.evidence_ids:
            if not isinstance(item, str) or not item.strip():
                raise ValueError("evidence_ids must contain non-empty strings")
        if self.value_digest is not None and (
            not isinstance(self.value_digest, str) or not self.value_digest.strip()
        ):
            raise ValueError("value_digest must be a non-empty string or None")

    @property
    def authority(self) -> str:
        """Authority implied by the category; never set independently."""
        return CATEGORY_AUTHORITY[self.category]

    @property
    def is_authoritative(self) -> bool:
        return self.category in AUTHORITATIVE_CATEGORIES

    def to_dict(self) -> Dict[str, Any]:
        return {
            "fact_id": self.fact_id,
            "category": self.category,
            "authority": self.authority,
            "authoritative": self.is_authoritative,
            "label": self.label,
            "value": self.value,
            "value_digest": self.value_digest,
            "source": self.source,
            "detail": self.detail,
            "evidence_ids": list(self.evidence_ids),
        }


@dataclass(frozen=True)
class CustodyStep(JsonModel):
    """One ordered step of the derivation, in the order the pipeline ran it.

    A step records what an already-completed stage *did*, naming the component
    that did it. It never instructs a stage to run, and it never asserts an
    outcome the recorded artifacts do not contain.
    """

    #: 1-based position in the derivation; stable across runs.
    index: int
    stage: str
    component: str
    action: str
    #: What the stage consumed, e.g. a variable name or an artifact digest.
    inputs: Tuple[str, ...] = field(default_factory=tuple)
    #: What the stage produced, in the stage's own vocabulary.
    outcome: Optional[str] = None
    #: ``True`` when the stage is part of the authoritative decision path.
    authoritative: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.index, int) or isinstance(self.index, bool):
            raise ValueError("index must be an integer")
        if self.index < 1:
            raise ValueError(f"index must be >= 1, got {self.index}")
        for name in ("stage", "component", "action"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{name} must be a non-empty string")
        if not isinstance(self.inputs, (tuple, list)):
            raise ValueError("inputs must be a tuple/list")
        for item in self.inputs:
            if not isinstance(item, str):
                raise ValueError("inputs must contain strings")
        if self.outcome is not None and (
            not isinstance(self.outcome, str) or not self.outcome.strip()
        ):
            raise ValueError("outcome must be a non-empty string or None")
        if not isinstance(self.authoritative, bool):
            raise ValueError("authoritative must be a bool")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "index": self.index,
            "stage": self.stage,
            "component": self.component,
            "action": self.action,
            "authoritative": self.authoritative,
            "inputs": list(self.inputs),
            "outcome": self.outcome,
        }


@dataclass(frozen=True)
class CustodyEvidenceLink(JsonModel):
    """A reference to one piece of evidence, plus its live integrity result.

    Carries identity and digests only. The referenced artifact is never read
    into the response, and the path is never emitted, so this model is safe to
    serialize to any client.
    """

    evidence_id: str
    artifact_type: Optional[str] = None
    artifact_sha256: Optional[str] = None
    byte_size: Optional[int] = None
    #: ``valid`` / ``unavailable`` / ``invalid`` / ``unverified`` from the ref,
    #: or ``not_performed`` when the caller opted out of the re-hash.
    verification_status: Optional[str] = None
    verification_detail: Optional[str] = None
    #: ``None`` when the artifact was not looked for, so absence is never
    #: reported as a verified absence.
    artifact_present: Optional[bool] = None
    #: SHA-256 recomputed now, when it could be recomputed. ``None`` otherwise.
    actual_sha256: Optional[str] = None
    #: Which stage attached this reference to the finding.
    attached_by: Tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        if not isinstance(self.evidence_id, str) or not self.evidence_id.strip():
            raise ValueError("evidence_id must be a non-empty string")
        if not isinstance(self.attached_by, (tuple, list)):
            raise ValueError("attached_by must be a tuple/list")
        for item in self.attached_by:
            if not isinstance(item, str) or not item.strip():
                raise ValueError("attached_by must contain non-empty strings")
        if not (self.artifact_present is None or isinstance(self.artifact_present, bool)):
            raise ValueError("artifact_present must be a bool or None")

    @property
    def verifiable(self) -> bool:
        """True only when a digest exists to check the artifact against."""
        return bool(self.artifact_sha256)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "artifact_type": self.artifact_type,
            "artifact_sha256": self.artifact_sha256,
            "byte_size": self.byte_size,
            "verifiable": self.verifiable,
            "verification_status": self.verification_status,
            "verification_detail": self.verification_detail,
            "artifact_present": self.artifact_present,
            "actual_sha256": self.actual_sha256,
            "attached_by": list(self.attached_by),
        }


@dataclass(frozen=True)
class CustodyProvenanceArtifact(JsonModel):
    """One recorded input artifact, identified by digest and public path.

    ``public_path`` is whatever the caller's disclosure policy produced. This
    model has no field for an absolute host path and no field for file content,
    so a chain cannot leak a filesystem layout even if a caller passes one in.
    """

    role: str
    #: Least-disclosing path form chosen by the caller's policy, or ``None``.
    public_path: Optional[str] = None
    artifact_sha256: Optional[str] = None
    byte_size: Optional[int] = None
    record_count: Optional[int] = None
    detail: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.role, str) or not self.role.strip():
            raise ValueError("role must be a non-empty string")
        if self.public_path is not None and (
            not isinstance(self.public_path, str) or not self.public_path.strip()
        ):
            raise ValueError("public_path must be a non-empty string or None")
        if not isinstance(self.detail, dict):
            raise ValueError("detail must be a dict")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "role": self.role,
            "public_path": self.public_path,
            "artifact_sha256": self.artifact_sha256,
            "byte_size": self.byte_size,
            "record_count": self.record_count,
            "detail": dict(self.detail),
        }


@dataclass(frozen=True)
class CustodyIntegrityCheck(JsonModel):
    """One machine-evaluable integrity/provenance check and its result.

    A check is stated so a client can run it itself. ``detail`` says what was
    actually compared, and a non-``pass`` status is reported as-is: a failed or
    unavailable check is information, never something to smooth over.
    """

    check_id: str
    description: str
    status: str
    detail: str
    #: The values the check compared, so the result is auditable.
    observed: Optional[Any] = None
    expected: Optional[Any] = None
    #: True when re-running the check requires no private state.
    client_verifiable: bool = True

    def __post_init__(self) -> None:
        for name in ("check_id", "description", "detail"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{name} must be a non-empty string")
        validate_check_status(self.status)
        if not isinstance(self.client_verifiable, bool):
            raise ValueError("client_verifiable must be a bool")

    @property
    def passed(self) -> bool:
        return self.status == CHECK_PASS

    def to_dict(self) -> Dict[str, Any]:
        return {
            "check_id": self.check_id,
            "description": self.description,
            "status": self.status,
            "passed": self.passed,
            "detail": self.detail,
            "observed": self.observed,
            "expected": self.expected,
            "client_verifiable": self.client_verifiable,
        }


@dataclass(frozen=True)
class CustodyRuleRef(JsonModel):
    """Which rule fired, and the traceability metadata recorded for it.

    Carries the rule registry's own record verbatim. ``traceability`` is empty
    only when a rule id has no registry entry, which is stated rather than
    papered over with a synthesised description.
    """

    rule_id: str
    finding_id: str
    #: The registry rule this id was specialised from, when the id itself is a
    #: per-variable variant (e.g. ``correlation.mismatch.address_family`` ->
    #: ``correlation.mismatch``). ``None`` when no dotted prefix resolves.
    base_rule_id: Optional[str] = None
    source_variable: Optional[str] = None
    authoritative_source: Optional[str] = None
    condition: Optional[str] = None
    evidence_requirement: Optional[str] = None
    unknown_handling: Optional[str] = None
    dedup_behavior: Optional[str] = None
    severity: Optional[str] = None
    score_contribution: Optional[int] = None
    #: ``True`` when the rule has a registry entry.
    registered: bool = True
    traceability: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        for name in ("rule_id", "finding_id"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{name} must be a non-empty string")
        if not isinstance(self.registered, bool):
            raise ValueError("registered must be a bool")
        if not isinstance(self.traceability, dict):
            raise ValueError("traceability must be a dict")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "finding_id": self.finding_id,
            "registered": self.registered,
            "base_rule_id": self.base_rule_id,
            "source_variable": self.source_variable,
            "authoritative_source": self.authoritative_source,
            "condition": self.condition,
            "evidence_requirement": self.evidence_requirement,
            "unknown_handling": self.unknown_handling,
            "dedup_behavior": self.dedup_behavior,
            "severity": self.severity,
            "score_contribution": self.score_contribution,
            "traceability": dict(self.traceability),
        }


@dataclass(frozen=True)
class CustodyRecommendation(JsonModel):
    """The response-policy proposal for this finding, if one was planned.

    Copied from a :class:`~correlation.response.models.ResponseRecommendation`.
    Nothing here is a decision: ``applied`` is always ``False`` on this API,
    which exposes no mutation route.
    """

    recommendation_id: Optional[str] = None
    action: Optional[str] = None
    priority: Optional[str] = None
    policy_version: Optional[str] = None
    reason: Optional[str] = None
    rationale: Optional[str] = None
    authorization_required: Optional[bool] = None
    approval_required: Optional[bool] = None
    required_roles: Tuple[str, ...] = field(default_factory=tuple)
    limitations: Tuple[str, ...] = field(default_factory=tuple)
    #: Always False. Stated as data so a client cannot infer otherwise.
    applied: bool = False
    #: How the action was obtained: the reused planner, or nothing.
    derived_by: str = "response.planner"

    def __post_init__(self) -> None:
        if not isinstance(self.applied, bool):
            raise ValueError("applied must be a bool")
        if self.applied:
            raise ValueError(
                "custody recommendations are proposals; applied must be False"
            )
        for name in ("required_roles", "limitations"):
            value = getattr(self, name)
            if not isinstance(value, (tuple, list)):
                raise ValueError(f"{name} must be a tuple/list")
        if not isinstance(self.derived_by, str) or not self.derived_by.strip():
            raise ValueError("derived_by must be a non-empty string")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "recommendation_id": self.recommendation_id,
            "action": self.action,
            "priority": self.priority,
            "policy_version": self.policy_version,
            "reason": self.reason,
            "rationale": self.rationale,
            "authorization_required": self.authorization_required,
            "approval_required": self.approval_required,
            "required_roles": list(self.required_roles),
            "limitations": list(self.limitations),
            "applied": self.applied,
            "derived_by": self.derived_by,
        }


@dataclass(frozen=True)
class ChainOfCustody(JsonModel):
    """The complete, deterministic custody chain for exactly one finding.

    Scope is deliberately narrow: one finding inside one assessment. Finding
    ids repeat across assessments, so a chain is only ever meaningful together
    with its ``assessment_id``; the pair is the identity of this document.

    Everything here is derived from objects that already existed. Building a
    chain is read-only: it creates no finding, changes no score, writes no
    artifact and dispatches no control.
    """

    schema_version: str
    component: str
    component_version: str
    assessment_id: str
    finding_id: str
    #: Canonical JSON of the authoritative ``RiskFinding`` this chain explains,
    #: digested with SHA-256. Lets a client detect an edited finding.
    finding_digest: str
    title: str
    summary: str
    category: str
    severity: str
    #: Assessment-level context, copied from the risk assessment.
    risk_score: int
    risk_severity: str
    risk_policy_version: str
    risk_engine_version: str
    identity: Dict[str, Any] = field(default_factory=dict)
    rule: CustodyRuleRef = None  # type: ignore[assignment]
    facts: Tuple[CustodyFact, ...] = field(default_factory=tuple)
    steps: Tuple[CustodyStep, ...] = field(default_factory=tuple)
    evidence: Tuple[CustodyEvidenceLink, ...] = field(default_factory=tuple)
    sources: Tuple[CustodyProvenanceArtifact, ...] = field(default_factory=tuple)
    integrity: Tuple[CustodyIntegrityCheck, ...] = field(default_factory=tuple)
    recommendation: Optional[CustodyRecommendation] = None
    audit_event_ids: Tuple[str, ...] = field(default_factory=tuple)
    audit_linkage_status: str = AUDIT_UNAVAILABLE
    #: What this chain does not establish. Stated, never omitted.
    limitations: Tuple[str, ...] = field(default_factory=tuple)
    determinism: Dict[str, Any] = field(default_factory=dict)
    #: Externally supplied asset context and the contextualized risk it
    #: produced, or ``None`` when the assessment declared none. A ``dict`` (not
    #: a custody type) so this layer keeps no import edge to the mission package
    #: and stays independently loadable; :meth:`build_chain_of_custody` accepts
    #: the richer object and serializes it here.
    mission_context: Optional[Dict[str, Any]] = None
    #: The validated-baseline comparison this finding was raised by, or ``None``
    #: when the assessment declared no baseline. A ``dict`` (not a custody type)
    #: for the same reason as ``mission_context``: this layer keeps no import
    #: edge to the drift package and stays independently loadable.
    #: :func:`build_chain_of_custody` accepts the richer object and serializes it
    #: here. When present it records the baseline id, both digests, the changed
    #: field and its two values, so the drift claim is auditable from the chain
    #: alone.
    drift: Optional[Dict[str, Any]] = None
    #: Always True. There is no mutation path anywhere in this layer.
    read_only: bool = True

    def __post_init__(self) -> None:
        for name in (
            "schema_version", "component", "component_version", "assessment_id",
            "finding_id", "finding_digest", "title", "summary", "category",
            "severity", "risk_severity", "risk_policy_version",
            "risk_engine_version",
        ):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{name} must be a non-empty string")
        if not isinstance(self.risk_score, int) or isinstance(self.risk_score, bool):
            raise ValueError("risk_score must be an integer")
        if not (0 <= self.risk_score <= 100):
            raise ValueError(f"risk_score must be within 0-100, got {self.risk_score}")
        if not isinstance(self.rule, CustodyRuleRef):
            raise ValueError("rule must be a CustodyRuleRef")
        for name in ("facts", "steps", "evidence", "sources", "integrity",
                     "audit_event_ids", "limitations"):
            value = getattr(self, name)
            if not isinstance(value, (tuple, list)):
                raise ValueError(f"{name} must be a tuple/list")
        if self.recommendation is not None and not isinstance(
            self.recommendation, CustodyRecommendation
        ):
            raise ValueError("recommendation must be a CustodyRecommendation or None")
        if self.audit_linkage_status not in AUDIT_LINKAGE_STATUSES:
            raise ValueError(
                f"audit_linkage_status must be one of {AUDIT_LINKAGE_STATUSES}, "
                f"got {self.audit_linkage_status!r}"
            )
        if not isinstance(self.identity, dict):
            raise ValueError("identity must be a dict")
        if not isinstance(self.determinism, dict):
            raise ValueError("determinism must be a dict")
        if not isinstance(self.read_only, bool):
            raise ValueError("read_only must be a bool")
        if not self.read_only:
            raise ValueError("a chain of custody is read-only; read_only must be True")

    # -- derived views -------------------------------------------------------

    def fact_by_id(self, fact_id: str) -> Optional[CustodyFact]:
        for fact in self.facts:
            if fact.fact_id == fact_id:
                return fact
        return None

    def facts_in_category(self, category: str) -> Tuple[CustodyFact, ...]:
        validate_category(category)
        return tuple(fact for fact in self.facts if fact.category == category)

    def integrity_check(self, check_id: str) -> Optional[CustodyIntegrityCheck]:
        for check in self.integrity:
            if check.check_id == check_id:
                return check
        return None

    @property
    def failed_checks(self) -> Tuple[CustodyIntegrityCheck, ...]:
        return tuple(check for check in self.integrity if not check.passed)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "component": self.component,
            "component_version": self.component_version,
            "read_only": self.read_only,
            "assessment_id": self.assessment_id,
            "finding_id": self.finding_id,
            "finding_digest": self.finding_digest,
            "title": self.title,
            "summary": self.summary,
            "category": self.category,
            "severity": self.severity,
            "risk_score": self.risk_score,
            "risk_severity": self.risk_severity,
            "risk_policy_version": self.risk_policy_version,
            "risk_engine_version": self.risk_engine_version,
            "identity": dict(self.identity),
            "rule": self.rule.to_dict(),
            "facts": [fact.to_dict() for fact in self.facts],
            "steps": [step.to_dict() for step in self.steps],
            "evidence": [item.to_dict() for item in self.evidence],
            "sources": [item.to_dict() for item in self.sources],
            "integrity": [check.to_dict() for check in self.integrity],
            "recommendation": (
                self.recommendation.to_dict() if self.recommendation is not None else None
            ),
            "audit_event_ids": list(self.audit_event_ids),
            "audit_linkage_status": self.audit_linkage_status,
            "limitations": list(self.limitations),
            "determinism": dict(self.determinism),
            "mission_context": (
                dict(self.mission_context) if self.mission_context is not None else None
            ),
            "drift": dict(self.drift) if self.drift is not None else None,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "ChainOfCustody":
        rule = data.get("rule") or {}
        return cls(
            schema_version=data["schema_version"],
            component=data["component"],
            component_version=data["component_version"],
            read_only=data.get("read_only", True),
            assessment_id=data["assessment_id"],
            finding_id=data["finding_id"],
            finding_digest=data["finding_digest"],
            title=data["title"],
            summary=data["summary"],
            category=data["category"],
            severity=data["severity"],
            risk_score=data["risk_score"],
            risk_severity=data["risk_severity"],
            risk_policy_version=data["risk_policy_version"],
            risk_engine_version=data["risk_engine_version"],
            identity=dict(data.get("identity") or {}),
            rule=CustodyRuleRef(
                rule_id=rule["rule_id"],
                finding_id=rule["finding_id"],
                base_rule_id=rule.get("base_rule_id"),
                source_variable=rule.get("source_variable"),
                authoritative_source=rule.get("authoritative_source"),
                condition=rule.get("condition"),
                evidence_requirement=rule.get("evidence_requirement"),
                unknown_handling=rule.get("unknown_handling"),
                dedup_behavior=rule.get("dedup_behavior"),
                severity=rule.get("severity"),
                score_contribution=rule.get("score_contribution"),
                registered=rule.get("registered", True),
                traceability=dict(rule.get("traceability") or {}),
            ),
            facts=tuple(
                CustodyFact(
                    fact_id=item["fact_id"],
                    category=item["category"],
                    label=item["label"],
                    value=item.get("value"),
                    source=item["source"],
                    detail=item.get("detail"),
                    evidence_ids=tuple(item.get("evidence_ids") or ()),
                    value_digest=item.get("value_digest"),
                )
                for item in data.get("facts") or ()
            ),
            steps=tuple(
                CustodyStep(
                    index=item["index"],
                    stage=item["stage"],
                    component=item["component"],
                    action=item["action"],
                    inputs=tuple(item.get("inputs") or ()),
                    outcome=item.get("outcome"),
                    authoritative=bool(item.get("authoritative", False)),
                )
                for item in data.get("steps") or ()
            ),
            evidence=tuple(
                CustodyEvidenceLink(
                    evidence_id=item["evidence_id"],
                    artifact_type=item.get("artifact_type"),
                    artifact_sha256=item.get("artifact_sha256"),
                    byte_size=item.get("byte_size"),
                    verification_status=item.get("verification_status"),
                    verification_detail=item.get("verification_detail"),
                    artifact_present=bool(item.get("artifact_present", False)),
                    actual_sha256=item.get("actual_sha256"),
                    attached_by=tuple(item.get("attached_by") or ()),
                )
                for item in data.get("evidence") or ()
            ),
            sources=tuple(
                CustodyProvenanceArtifact(
                    role=item["role"],
                    public_path=item.get("public_path"),
                    artifact_sha256=item.get("artifact_sha256"),
                    byte_size=item.get("byte_size"),
                    record_count=item.get("record_count"),
                    detail=dict(item.get("detail") or {}),
                )
                for item in data.get("sources") or ()
            ),
            integrity=tuple(
                CustodyIntegrityCheck(
                    check_id=item["check_id"],
                    description=item["description"],
                    status=item["status"],
                    detail=item["detail"],
                    observed=item.get("observed"),
                    expected=item.get("expected"),
                    client_verifiable=bool(item.get("client_verifiable", True)),
                )
                for item in data.get("integrity") or ()
            ),
            recommendation=(
                CustodyRecommendation(
                    **{
                        key: (tuple(value) if isinstance(value, list) else value)
                        for key, value in (data.get("recommendation") or {}).items()
                        if key in CustodyRecommendation.__dataclass_fields__
                    }
                )
                if data.get("recommendation")
                else None
            ),
            audit_event_ids=tuple(data.get("audit_event_ids") or ()),
            audit_linkage_status=data.get("audit_linkage_status", AUDIT_UNAVAILABLE),
            limitations=tuple(data.get("limitations") or ()),
            determinism=dict(data.get("determinism") or {}),
            mission_context=(
                dict(data["mission_context"])
                if data.get("mission_context") is not None
                else None
            ),
            drift=dict(data["drift"]) if data.get("drift") is not None else None,
        )


def facts_by_category(facts: Sequence[CustodyFact]) -> Dict[str, Tuple[CustodyFact, ...]]:
    """Group facts by category, every category present even when empty.

    Grouping is over the fixed ``FACT_CATEGORIES`` order so a client always sees
    the same four keys.
    """
    grouped: Dict[str, Tuple[CustodyFact, ...]] = {}
    for category in FACT_CATEGORIES:
        grouped[category] = tuple(
            fact for fact in facts if fact.category == category
        )
    return grouped
