"""Longitudinal comparison: a validated baseline versus a later observation.

This module performs the one comparison the milestone asks for -- baseline vs
current observed state -- and then hands the result to the **existing** risk
machinery. It does not score anything itself: severities come from
``correlation.risk.rules.MISMATCH_FINDING_SPECS`` and from
``_esp_presence_severity``, and the score comes from
``correlation.risk.scoring.score_findings`` under the existing
``RiskPolicy``. There is no drift scoring scale, because the existing one is
correct and a second one would be a competing abstraction.

Why this is not just the comparison engine again
------------------------------------------------

``ComparisonEngine`` answers "does the observation match the *plan*?". A
baseline answers a different question: "does the observation match the state
somebody validated earlier?". The plan is a forward-looking intention produced
by a planner; a baseline is a historical fact that was observed and then
approved. The rule evaluation is the same kind of exact comparison, but the
left-hand side is a validated observation, and that difference is the whole
point of the milestone. The variables, the derivations, the severities, the
categories, the scoring and the evidence model are all reused unchanged.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, Mapping, Optional, Sequence, Tuple

from ..models.evidence import EvidenceRef
from ..models.identity import CorrelationIdentity
from ..models.observed import ObservedState
from ..risk.findings import make_finding
from ..risk.models import (
    CATEGORY_CONFIGURATION_MISMATCH,
    EVIDENCE_TYPE_OBSERVATION,
    RISK_ENGINE_VERSION,
    RISK_SCHEMA_VERSION,
    SEVERITY_INFO,
    SOURCE_OBSERVED_PROTOCOL,
    RiskAssessment,
    RiskFinding,
)
from ..risk.policy import RiskPolicy
from ..risk.rules import MISMATCH_FINDING_SPECS, _esp_presence_severity
from ..risk.scoring import score_findings
from .baseline import ValidatedBaseline
from .canonical import (
    COMPARABLE_FIELDS,
    comparable_field,
    observation_is_informative,
    security_relevance_of,
    canonical_security_state,
    canonical_state_digest,
)
from .models import (
    DRIFT_CATEGORY_CONFIGURATION,
    DRIFT_CATEGORIES,
    DRIFT_MODEL_VERSION,
    DRIFT_SOURCE_KIND_DECLARED,
    DRIFT_SOURCE_KIND_RECORDED,
    DRIFT_SOURCE_KINDS,
    DRIFT_STATUS_DRIFT,
    DRIFT_STATUS_INDETERMINATE,
    DRIFT_STATUS_NO_DRIFT,
    DRIFT_STATUS_NOT_CONFIGURED,
)

#: The rule id recorded on every drift finding and in the chain of custody: this
#: is the logic that determined the drift.
DRIFT_RULE_ID = "drift.configuration"

#: Severity is only ever read from the existing mismatch spec table.
_SEVERITY_REUSED_FROM = "correlation.risk.rules.MISMATCH_FINDING_SPECS"


@dataclass(frozen=True)
class FieldChange:
    """One comparable field whose value differs from the validated baseline.

    ``baseline_value`` and ``current_value`` are kept as separate, separately
    named fields so a consumer can never mistake one for the other.
    """

    variable: str
    label: str
    baseline_value: Any
    current_value: Any
    comparison_rule: str
    security_relevance: bool
    drift_category: str
    finding_id: Optional[str]
    severity: Optional[str]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "variable": self.variable,
            "label": self.label,
            "baseline_value": self.baseline_value,
            "current_value": self.current_value,
            "comparison_rule": self.comparison_rule,
            "security_relevance": self.security_relevance,
            "drift_category": self.drift_category,
            "finding_id": self.finding_id,
            "severity": self.severity,
        }


@dataclass(frozen=True)
class DriftCurrentSource:
    """What kind of thing the current observed state actually is.

    A drift claim has two sides, and the two sides do not always have the same
    epistemic status. The baseline is by definition something that was observed
    and then approved. The current state may be a real capture, or it may be a
    declaration -- a controlled fixture derived from a capture, for instance.
    Without a structured place to say which, a demonstration is
    indistinguishable from a field observation, and a reader has no way to tell
    them apart.

    So the kind is a field, not a convention, and ``is_capture`` is derived from
    it rather than set independently.
    """

    kind: str
    #: The declared artifact's real digest, when the current state came from one.
    artifact_sha256: Optional[str] = None
    #: The repository-relative path of that artifact, when there is one.
    public_path: Optional[str] = None
    #: The producer's own classification of the artifact, in the producer's words
    #: (for example ``"disclosed_derived_observation"``). Distinct from ``kind``,
    #: which is this layer's canonical vocabulary.
    declared_kind: Optional[str] = None
    #: A verbatim statement by the producer that the artifact is not a capture.
    #: Carried through unmodified: this layer reports declarations, it does not
    #: rewrite them into its own phrasing.
    declaration: Optional[str] = None
    #: The artifact the current state was derived from, as a structured
    #: reference: its path, its digest, and any description the producer gave.
    derived_from: Optional[Mapping[str, Any]] = None
    is_live_capture: Optional[bool] = None

    def __post_init__(self) -> None:
        if self.kind not in DRIFT_SOURCE_KINDS:
            raise ValueError(
                f"current source kind must be one of {DRIFT_SOURCE_KINDS!r}; "
                f"got {self.kind!r}"
            )
        if self.derived_from is not None and self.kind == DRIFT_SOURCE_KIND_RECORDED:
            raise ValueError(
                "a recorded capture is not derived from anything; if the current "
                "state was derived, declare it as "
                f"{DRIFT_SOURCE_KIND_DECLARED!r}"
            )
        for name in ("declared_kind", "declaration", "public_path", "artifact_sha256"):
            value = getattr(self, name)
            if value is not None and not isinstance(value, str):
                raise TypeError(
                    f"{name} must be a string or None, not "
                    f"{type(value).__name__}"
                )
        if self.derived_from is not None and not isinstance(
                self.derived_from, Mapping):
            raise TypeError(
                "derived_from must be a mapping or None, not "
                f"{type(self.derived_from).__name__}"
            )
        if self.is_live_capture not in (None, True, False):
            raise TypeError(
                f"is_live_capture must be True, False or None, not "
                f"{self.is_live_capture!r}"
            )
        if self.is_live_capture and not self.is_capture:
            raise ValueError(
                "a declared observation cannot also be a live capture; the two "
                "fields contradict each other"
            )

    @property
    def is_capture(self) -> bool:
        """Whether a live capture produced this state.

        Only :data:`DRIFT_SOURCE_KIND_RECORDED` says so. A declared source is
        never a capture, whatever the artifact it was read from happens to be.
        """
        return self.kind == DRIFT_SOURCE_KIND_RECORDED

    def to_dict(self) -> Dict[str, Any]:
        return {
            "kind": self.kind,
            "is_capture": self.is_capture,
            "is_live_capture": (
                self.is_live_capture if self.is_live_capture is not None
                else self.is_capture
            ),
            "artifact_sha256": self.artifact_sha256,
            "public_path": self.public_path,
            "declared_kind": self.declared_kind,
            "declaration": self.declaration,
            "derived_from": (
                dict(self.derived_from) if self.derived_from is not None else None
            ),
        }


@dataclass(frozen=True)
class DriftAssessment:
    """The outcome of comparing one observation against one validated baseline.

    ``status`` is the headline; ``baseline_id``/``state_digest`` and
    ``current_state_digest`` are the two sides, and ``changed_fields`` is the
    derived difference. ``risk`` is an ordinary ``RiskAssessment`` produced by
    the existing scoring path, or ``None`` when there is nothing to score.
    """

    status: str
    baseline_id: Optional[str] = None
    baseline_state_digest: Optional[str] = None
    baseline_digest: Optional[str] = None
    baseline_validated_at: Optional[str] = None
    baseline_validated_by: Optional[str] = None
    baseline_asset_id: Optional[str] = None
    current_state_digest: Optional[str] = None
    current_source_ref: Optional[str] = None
    current_run_id: Optional[str] = None
    current_sequence: Optional[int] = None
    #: What kind of artifact the current state is. Defaults to a recorded
    #: capture, which is the ordinary case; a caller with a declared current
    #: state must say so rather than let the default speak for it.
    current_source: DriftCurrentSource = field(
        default_factory=lambda: DriftCurrentSource(DRIFT_SOURCE_KIND_RECORDED))
    changed_fields: Tuple[FieldChange, ...] = ()
    unchanged_variables: Tuple[str, ...] = ()
    unknown_variables: Tuple[str, ...] = ()
    drift_categories: Tuple[str, ...] = ()
    risk: Optional[RiskAssessment] = None
    reason: Optional[str] = None
    model_version: str = DRIFT_MODEL_VERSION

    @property
    def drift_detected(self) -> bool:
        return self.status == DRIFT_STATUS_DRIFT

    def changed_variable(self, variable: str) -> Optional[FieldChange]:
        for change in self.changed_fields:
            if change.variable == variable:
                return change
        return None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status,
            "drift_detected": self.drift_detected,
            "baseline": {
                "baseline_id": self.baseline_id,
                "state_digest": self.baseline_state_digest,
                "baseline_digest": self.baseline_digest,
                "validated_at": self.baseline_validated_at,
                "validated_by": self.baseline_validated_by,
                "asset_id": self.baseline_asset_id,
                "validation_status": "validated" if self.baseline_id else None,
            },
            "current": {
                "state_digest": self.current_state_digest,
                "source_ref": self.current_source_ref,
                "source": self.current_source.to_dict(),
                "run_id": self.current_run_id,
                "sequence": self.current_sequence,
            },
            "changed_fields": [change.to_dict() for change in self.changed_fields],
            "unchanged_variables": list(self.unchanged_variables),
            "unknown_variables": list(self.unknown_variables),
            "drift_categories": list(self.drift_categories),
            "risk": self.risk.to_dict() if self.risk is not None else None,
            "reason": self.reason,
            "model_version": self.model_version,
            "rule_id": DRIFT_RULE_ID,
        }


def _severity_for(variable: str, baseline_value: Any, current_value: Any) -> str:
    """Severity of a drift on ``variable``, read from the existing rule table.

    Nothing is invented here. ``esp.presence`` is the one variable with a
    directional severity in the existing table, and the existing
    ``_esp_presence_severity`` decides it: a protection that was in force and
    is no longer observed is HIGH, the reverse (an unexpected protection
    appearing) is LOW, because that is config drift rather than a confirmed
    loss of protection.
    """
    spec = MISMATCH_FINDING_SPECS.get(variable)
    if spec is None:
        return SEVERITY_INFO
    static = spec[3]
    if static is not None:
        return static
    return _esp_presence_severity(baseline_value, current_value)


def _finding_id_for(variable: str) -> str:
    """A stable, greppable finding id for a drift on ``variable``."""
    return "RISK-DRIFT-" + variable.replace(".", "-").upper()


def _build_finding(
    change: FieldChange,
    *,
    baseline_id: str,
    baseline_state_digest: str,
    baseline_validated_at: Optional[str],
    baseline_validated_by: Optional[str],
    current_state_digest: str,
    current_source_ref: Optional[str],
    evidence_refs: Sequence[EvidenceRef],
) -> RiskFinding:
    """One drift finding, in the existing ``RiskFinding`` vocabulary.

    ``expected_value`` carries the *baseline* value and ``observed_value``
    carries the *current* observation, which is how the existing model already
    separates a claim from a measurement.
    """
    return make_finding(
        finding_id=change.finding_id,
        rule_id=DRIFT_RULE_ID,
        category=CATEGORY_CONFIGURATION_MISMATCH,
        severity=change.severity,
        title=f"IPsec security state drifted from validated baseline: {change.variable}",
        description=(
            f"The independently observed IPsec security state differs from "
            f"validated baseline {baseline_id!r} on {change.variable!r}. "
            f"Baseline: {change.baseline_value!r}. Current observation: "
            f"{change.current_value!r}. The technical risk of the current "
            f"observation is unchanged by this comparison; only the "
            f"contextualized view and this finding are added."
        ),
        reason=(
            f"validated baseline {baseline_id!r} (state digest "
            f"{baseline_state_digest[:16]}...) recorded "
            f"{change.variable}={change.baseline_value!r}; the current "
            f"observation (state digest {current_state_digest[:16]}...) recorded "
            f"{change.variable}={change.current_value!r}. Rule "
            f"{change.comparison_rule!r}; severity taken unchanged from "
            f"{_SEVERITY_REUSED_FROM}."
        ),
        condition=(
            f"baseline {baseline_id!r} validated at {baseline_validated_at!r} "
            f"by {baseline_validated_by!r} AND a later independent observation "
            f"of {change.variable!r} differs"
        ),
        source=SOURCE_OBSERVED_PROTOCOL,
        evidence_type=EVIDENCE_TYPE_OBSERVATION,
        related_variable=change.variable,
        expected_value=change.baseline_value,
        observed_value=change.current_value,
        evidence_refs=tuple(evidence_refs),
    )


def _identity_for(
    run_id: str,
    sequence: int,
    experiment_id: str,
) -> CorrelationIdentity:
    return CorrelationIdentity(
        dataset_run_id=run_id,
        sequence=sequence,
        experiment_id=experiment_id,
        attempt_number=1,
    )


def validate_baseline(
    observed: ObservedState,
    *,
    baseline_id: str,
    validated_by: str,
    validated_at: str,
    asset_id: Optional[str] = None,
    source_run_id: Optional[str] = None,
    source_observation_ref: Optional[str] = None,
    captured_at: Optional[str] = None,
    notes: Optional[str] = None,
    evidence_refs: Sequence[Dict[str, Any]] = (),
) -> ValidatedBaseline:
    """Establish a validated baseline from one observation.

    Baseline creation is an explicit, attributable act. The caller must name the
    baseline, who validated it and when; there is no way to obtain a
    ``ValidatedBaseline`` from an observation implicitly, and
    :func:`assess_drift` refuses ``None`` rather than falling back to the most
    recent observation it can find.

    ``validated_at`` is required and caller-supplied (not read from a clock here)
    so that a baseline record is fully determined by its inputs and therefore
    reproducible and verifiable.

    The observation must at least be able to establish one comparable field; a
    baseline with nothing to compare is rejected rather than stored empty.
    """
    if not isinstance(observed, ObservedState):
        raise TypeError(
            "a baseline must be validated from an ObservedState, got "
            f"{type(observed).__name__}"
        )
    if not observation_is_informative(observed):
        # An observation that saw no traffic reports every presence flag as
        # False. Validating one as a baseline would record "AH is not in force"
        # and "ESP is not in force" as an approved historical state, which is
        # the absence of evidence promoted to a fact -- the same inversion the
        # comparison side refuses, closed here at the point a baseline is born.
        raise ValueError(
            "this observation saw no traffic, so it cannot be validated as a "
            "baseline: its IPsec presence flags are False by non-observation, "
            "not by security state, and sealing them would turn the absence of "
            "evidence into an approved baseline"
        )
    state = canonical_security_state(observed)
    if not state:
        raise ValueError(
            "this observation establishes no comparable security-state field "
            f"(any of {', '.join(field.variable for field in COMPARABLE_FIELDS)} "
            "would have to be derivable from it), so it cannot be validated as "
            "a baseline; nothing would be comparable later"
        )
    return ValidatedBaseline(
        baseline_id=baseline_id,
        state_digest=canonical_state_digest(state),
        canonical_state=state,
        asset_id=asset_id,
        source_run_id=source_run_id,
        source_observation_ref=source_observation_ref,
        captured_at=captured_at,
        validated_at=validated_at,
        validated_by=validated_by,
        notes=notes,
        evidence_refs=tuple(dict(ref) for ref in evidence_refs),
    )


def assess_drift(
    baseline: Optional[ValidatedBaseline],
    observed: Any,
    *,
    current_source_ref: Optional[str] = None,
    current_source: Optional[DriftCurrentSource] = None,
    run_id: str = "drift-comparison",
    sequence: int = 1,
    experiment_id: str = "drift-comparison",
    evidence_refs: Sequence[EvidenceRef] = (),
    policy: Optional[RiskPolicy] = None,
) -> DriftAssessment:
    """Compare one observation against a validated baseline.

    ``baseline=None`` yields ``not_configured`` -- never a comparison against an
    invented or most-recent state.

    ``current_source`` declares what kind of artifact ``observed`` came from. It
    defaults to a recorded capture, which is the ordinary case; a caller holding
    a controlled fixture must pass ``DriftCurrentSource`` explicitly so the
    published comparison cannot be read as an observation of a live device.
    """
    source = current_source or DriftCurrentSource(DRIFT_SOURCE_KIND_RECORDED)
    if baseline is None:
        return DriftAssessment(
            status=DRIFT_STATUS_NOT_CONFIGURED,
            reason=(
                "no validated baseline was supplied for this comparison, so no "
                "baseline-vs-current comparison was made and no drift is claimed"
            ),
        )
    ok, reason = baseline.verify()
    if not ok:
        from .baseline import BaselineIntegrityError

        raise BaselineIntegrityError(
            f"baseline {baseline.baseline_id!r} failed its integrity check: {reason}"
        )

    current_state = canonical_security_state(observed)
    current_digest = canonical_state_digest(current_state)
    baseline_state = baseline.canonical_state

    # A comparable field that either side cannot establish is unknown, never a
    # change: absence of a value is not a value.
    shared = [field.variable for field in COMPARABLE_FIELDS]
    unestablishable = tuple(
        variable
        for variable in shared
        if variable not in current_state or variable not in baseline_state
    )
    comparable = [variable for variable in shared if variable not in unestablishable]

    changed: list = []
    unchanged: list = []
    for variable in comparable:
        before = baseline_state[variable]
        after = current_state[variable]
        if before == after and type(before) is type(after):
            unchanged.append(variable)
            continue
        field = comparable_field(variable)
        changed.append(
            FieldChange(
                variable=variable,
                label=field.label,
                baseline_value=before,
                current_value=after,
                comparison_rule=field.comparison_rule,
                security_relevance=security_relevance_of(variable),
                drift_category=DRIFT_CATEGORY_CONFIGURATION,
                finding_id=_finding_id_for(variable)
                if security_relevance_of(variable) else None,
                severity=_severity_for(variable, before, after)
                if security_relevance_of(variable) else None,
            )
        )

    if not observation_is_informative(observed):
        # No traffic at all: every presence flag reads False, and reading that
        # as "ESP is gone" would promote absence of evidence to a security
        # finding. The comparison is therefore withheld entirely -- nothing is
        # reported as changed and nothing as agreed.
        return DriftAssessment(
            status=DRIFT_STATUS_INDETERMINATE,
            baseline_id=baseline.baseline_id,
            baseline_state_digest=baseline.state_digest,
            baseline_digest=baseline.baseline_digest,
            baseline_validated_at=baseline.validated_at,
            baseline_validated_by=baseline.validated_by,
            baseline_asset_id=baseline.asset_id,
            current_state_digest=current_digest,
            current_source_ref=current_source_ref,
            current_source=source,
            current_run_id=run_id,
            current_sequence=sequence,
            unknown_variables=unestablishable,
            reason=(
                "the current observation saw no traffic, so every IPsec presence "
                "flag reads False by observation, not by security change; no "
                "field was compared, and this comparison is indeterminate and "
                "claims neither drift nor agreement"
            ),
        )

    if not changed:
        status = DRIFT_STATUS_NO_DRIFT
        reason = (
            f"the current observation matches validated baseline "
            f"{baseline.baseline_id!r} on every comparable security-state field"
        )
        if unestablishable:
            reason += (
                f"; {len(unestablishable)} comparable field(s) could not be "
                f"established from one of the two sides and are reported as "
                f"unknown, not as agreement"
            )
    else:
        status = DRIFT_STATUS_DRIFT
        reason = (
            f"{len(changed)} comparable security-state field(s) differ from "
            f"validated baseline {baseline.baseline_id!r}: "
            + ", ".join(
                f"{change.variable} {change.baseline_value!r} -> "
                f"{change.current_value!r}"
                for change in changed
            )
        )
        if unestablishable:
            reason += (
                f"; {len(unestablishable)} further comparable field(s) were "
                f"unknown and are excluded from this determination"
            )

    risk: Optional[RiskAssessment] = None
    if changed:
        findings = [
            _build_finding(
                change,
                baseline_id=baseline.baseline_id,
                baseline_state_digest=baseline.state_digest,
                baseline_validated_at=baseline.validated_at,
                baseline_validated_by=baseline.validated_by,
                current_state_digest=current_digest,
                current_source_ref=current_source_ref,
                evidence_refs=evidence_refs,
            )
            for change in changed
            if change.finding_id is not None
        ]
        if findings:
            active_policy = policy or RiskPolicy.default()
            # The existing scoring function, under the existing policy. A drift
            # assessment is scored exactly like any other risk assessment.
            score_result = score_findings(findings, active_policy)
            risk = RiskAssessment(
                schema_version=RISK_SCHEMA_VERSION,
                risk_engine_version=RISK_ENGINE_VERSION,
                risk_policy_version=active_policy.policy_version,
                identity=_identity_for(run_id, sequence, experiment_id),
                overall_score=score_result.score,
                severity=score_result.severity,
                findings=tuple(findings),
                evidence_refs=tuple(evidence_refs),
                metadata={
                    "drift_model_version": DRIFT_MODEL_VERSION,
                    "drift_rule_id": DRIFT_RULE_ID,
                    "drift_categories": [DRIFT_CATEGORY_CONFIGURATION],
                    "supported_drift_categories": list(DRIFT_CATEGORIES),
                    "baseline_id": baseline.baseline_id,
                    "baseline_state_digest": baseline.state_digest,
                    "current_state_digest": current_digest,
                    "severity_source": _SEVERITY_REUSED_FROM,
                    "scoring": "correlation.risk.scoring.score_findings",
                },
            )

    return DriftAssessment(
        status=status,
        baseline_id=baseline.baseline_id,
        baseline_state_digest=baseline.state_digest,
        baseline_digest=baseline.baseline_digest,
        baseline_validated_at=baseline.validated_at,
        baseline_validated_by=baseline.validated_by,
        baseline_asset_id=baseline.asset_id,
        current_state_digest=current_digest,
        current_source_ref=current_source_ref,
        current_source=source,
        current_run_id=run_id,
        current_sequence=sequence,
        changed_fields=tuple(changed),
        unchanged_variables=tuple(unchanged),
        unknown_variables=unestablishable,
        drift_categories=(DRIFT_CATEGORY_CONFIGURATION,) if changed else (),
        risk=risk,
        reason=reason,
    )
