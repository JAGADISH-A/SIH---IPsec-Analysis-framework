"""Data contract for the scoped IPsec reasoning assistant.

Everything the assistant is allowed to say is derived from a
:class:`GroundingContext`, and every value in that context carries an explicit
:func:`origin` label. The four origins are the trust boundary of the whole
feature and are never merged:

===========================  =============================================
``observed_fact``            Something the capture produced: SPIs, packet
                             counts, protocol numbers, configured policy
                             materialized from the plan.
``deterministic_assessment`` Something the risk engine decided: severity,
                             overall score, findings, per-finding weight and
                             contribution, comparison status, evidence refs.
``ml_inference``             Something a model predicted: traffic class and
                             classification confidence. Carries its own
                             provenance and is never presented as an
                             observation or as a security decision.
``ai_explanation``           The generated prose. The only origin that is
                             prose, and the only one that is not
                             authoritative.
===========================  =============================================

A missing value is modelled as ``None`` plus a ``reason`` string, never as a
zero, an empty string, or an empty list. The difference matters: ``0`` is a
recorded risk score and ``[]`` is a recorded absence of findings, while
``None`` means *the backend did not record this*, and the assistant must say so
rather than fill the gap.

Authority boundary
------------------
None of these models can express a security decision. There is no severity
field an answer may set, no score field an answer may set, and no finding
creation path. :class:`AiAnswer` carries the authoritative severity and score
as *read-only echoes of the backend* so the UI can render the trust boundary
from server data, but nothing writes back into them.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Optional, Tuple

from ..models._base import JsonModel

#: The four provenance tiers. Values are the wire format; the frontend
#: renders them verbatim, so they must stay stable.
ORIGIN_OBSERVED = "observed_fact"
ORIGIN_DETERMINISTIC = "deterministic_assessment"
ORIGIN_ML = "ml_inference"
ORIGIN_AI = "ai_explanation"

ORIGINS: Tuple[str, ...] = (ORIGIN_OBSERVED, ORIGIN_DETERMINISTIC, ORIGIN_ML, ORIGIN_AI)

#: Hard bound on question length. A question is prose, not a payload; anything
#: longer is a paste accident, and the answer cannot depend on it.
MAX_QUESTION_CHARS = 500

#: Hard bound on retained follow-up turns. The conversation exists to refine an
#: explanation of *one* selected context, so depth past this adds cost without
#: adding grounding.
MAX_HISTORY_TURNS = 8


@dataclass(frozen=True)
class GroundedValue(JsonModel):
    """One recorded value plus the origin that produced it.

    ``source`` names the authoritative component verbatim (for example
    ``"correlation.risk.engine"``) so an analyst can see which subsystem is
    being reported rather than trusting the assistant's summary of it.
    """

    name: str
    value: Any
    origin: str
    source: str
    note: Optional[str] = None

    def __post_init__(self) -> None:
        if self.origin not in ORIGINS:
            raise ValueError(f"origin must be one of {ORIGINS}, got {self.origin!r}")
        if not self.name.strip():
            raise ValueError("name must be a non-empty string")
        if not self.source.strip():
            raise ValueError("source must be a non-empty string")


@dataclass(frozen=True)
class GroundedFinding(JsonModel):
    """One backend-produced finding, copied with no reshaping.

    ``score_contribution`` is the ``added`` value the risk engine actually
    booked for this finding, taken from ``score_detail.contributions``. It is
    not recomputed here and not derivable from ``severity`` alone, because the
    per-category cap means a finding can be partially absorbed.
    """

    finding_id: str
    rule_id: str
    category: str
    severity: str
    title: str
    description: str
    reason: str
    condition: str
    source: str
    related_variable: Optional[str] = None
    expected_value: Any = None
    observed_value: Any = None
    score_contribution: Optional[int] = None
    rule_weight: Optional[int] = None
    confidence: Optional[float] = None
    model_version: Optional[str] = None


@dataclass(frozen=True)
class GroundedComparison(JsonModel):
    """One expected-vs-observed comparison row, as the comparison engine left it."""

    variable: str
    status: str
    expected_value: Any = None
    observed_value: Any = None
    reason: Optional[str] = None


@dataclass(frozen=True)
class GroundedMl(JsonModel):
    """ML classification output, kept strictly separate from everything else.

    ``present=False`` means ML did not run or its result was not consumed. That
    is a different statement from ``confidence=None``, which means ML ran and
    the model supplied no probability (the nearest-centroid path never does).
    The distinction is preserved because "no model output" and "the model
    declined to state a confidence" lead to different explanations.
    """

    present: bool
    traffic_class: Optional[str] = None
    classification_confidence: Optional[float] = None
    model_version: Optional[str] = None
    anomaly: Optional[bool] = None
    anomaly_score: Optional[float] = None
    reason: Optional[str] = None


@dataclass(frozen=True)
class GroundedDrift(JsonModel):
    """Longitudinal drift state, or an explicit "not configured"."""

    configured: bool
    status: Optional[str] = None
    reason: Optional[str] = None
    changed_variables: Tuple[str, ...] = ()
    baseline_id: Optional[str] = None


@dataclass(frozen=True)
class GroundedCustody(JsonModel):
    """The recorded provenance chain, stage names only.

    The assistant may describe what each stage means, but it may not add a
    stage the backend did not record. ``stages`` is therefore exactly the
    sequence the chain builder emitted.
    """

    available: bool
    stages: Tuple[str, ...] = ()
    facts: Tuple[str, ...] = ()
    evidence_ids: Tuple[str, ...] = ()
    audit_linkage: Optional[str] = None
    integrity_statuses: Tuple[str, ...] = ()
    reason: Optional[str] = None


@dataclass(frozen=True)
class GroundingContext(JsonModel):
    """The authoritative slice of state one question is allowed to be answered from.

    ``available=False`` is the honest answer when the assessment could not be
    resolved. It is not an error: the assistant's job in that case is to say
    the assessment is not in the recorded context, not to guess.
    """

    assessment_id: Optional[str] = None
    available: bool = False
    reason: Optional[str] = None

    scenario: Optional[str] = None
    slot: Optional[str] = None
    dataset_run_id: Optional[str] = None
    sequence: Optional[int] = None

    severity: Optional[str] = None
    risk_score: Optional[int] = None
    risk_policy_version: Optional[str] = None
    risk_engine_version: Optional[str] = None

    finding: Optional[GroundedFinding] = None
    finding_ids: Tuple[str, ...] = ()
    finding_summaries: Tuple[str, ...] = ()

    expected: Dict[str, Any] = field(default_factory=dict)
    observed: Dict[str, Any] = field(default_factory=dict)
    comparisons: Tuple[GroundedComparison, ...] = ()
    variables: Tuple[str, ...] = ()

    evidence_ids: Tuple[str, ...] = ()
    evidence_sources: Tuple[str, ...] = ()
    evidence_count: Optional[int] = None
    integrity_status: Optional[str] = None

    custody: Optional[GroundedCustody] = None
    drift: Optional[GroundedDrift] = None
    ml: Optional[GroundedMl] = None
    asset: Optional[Dict[str, Any]] = None
    #: The control plane's recorded verdict for the related experiment job.
    #: ``None`` when no job was referenced or the controller recorded no cause.
    #: Never inferred from the finding: "why did this fail" must be answered from
    #: what the controller decided, or declared unrecorded.
    root_cause: Optional[Dict[str, Any]] = None

    def identifiers(self) -> frozenset:
        """Every string this context licenses the assistant to name.

        This is the whitelist the output guard checks model prose against. It
        is intentionally wide: it contains recorded values, not just ids, so a
        model that invents an unrecorded algorithm or an unrecorded severity is
        caught the same way one that invents an evidence id is.
        """
        allowed = set()
        for value in (
            self.assessment_id,
            self.dataset_run_id,
            self.scenario,
            self.slot,
            self.severity,
            self.risk_policy_version,
            self.risk_engine_version,
            self.integrity_status,
            self.finding_id,
        ):
            if value:
                allowed.add(str(value))
        for finding in self.findings:
            for value in (finding.finding_id, finding.rule_id, finding.severity,
                          finding.category, finding.related_variable):
                if value:
                    allowed.add(str(value))
        for name in ("modp1024", "modp2048", "modp3072", "modp4096", "modp8192",
                     "modp1536", "modp20", "x25519", "curve25519", "ffdhe2048",
                     "ffdhe3072", "ffdhe4096", "ffdhe6144", "ffdhe8192"):
            allowed.add(name)
        for row in self.comparisons:
            allowed.add(row.variable)
            allowed.add(row.status)
            for value in (row.expected_value, row.observed_value):
                if isinstance(value, str) and value.strip():
                    allowed.add(value)
                elif value is not None:
                    allowed.add(str(value))
        for value in _flatten_strings(self.expected):
            allowed.add(value)
        for value in _flatten_strings(self.observed):
            allowed.add(value)
        for value in self.evidence_ids:
            allowed.add(str(value))
        for value in self.evidence_sources:
            allowed.add(str(value))
        if self.drift is not None:
            allowed.update(self.drift.changed_variables)
            if self.drift.status:
                allowed.add(self.drift.status)
            if self.drift.baseline_id:
                allowed.add(self.drift.baseline_id)
        if self.ml is not None:
            for value in (self.ml.traffic_class, self.ml.model_version):
                if value:
                    allowed.add(str(value))
            if self.ml.classification_confidence is not None:
                allowed.add(_fmt_number(self.ml.classification_confidence))
        if self.asset:
            allowed.update(_flatten_strings(self.asset))
        if self.root_cause:
            allowed.update(_flatten_strings(self.root_cause))
        if self.risk_score is not None:
            allowed.add(str(self.risk_score))
        if self.finding is not None and self.finding.score_contribution is not None:
            allowed.add(str(self.finding.score_contribution))
        return frozenset(allowed)

    @property
    def finding_id(self) -> Optional[str]:
        return self.finding.finding_id if self.finding else None

    @property
    def findings(self) -> Tuple[GroundedFinding, ...]:
        if self.finding is not None:
            return (self.finding,)
        return ()

    def has(self, name: str) -> bool:
        """Whether a named piece of recorded context exists (not whether it is non-empty)."""
        if name in ("finding",):
            return self.finding is not None
        if name in ("ml",):
            return self.ml is not None and self.ml.present
        if name in ("custody",):
            return self.custody is not None and self.custody.available
        if name in ("drift",):
            return self.drift is not None and self.drift.configured
        if name in ("asset",):
            return self.asset is not None
        if name in ("root_cause",):
            return bool(self.root_cause and self.root_cause.get("root_cause"))
        if name in ("evidence",):
            return bool(self.evidence_ids)
        if name in ("severity", "risk_score"):
            return getattr(self, name) is not None
        if name in ("expected", "observed"):
            return bool(getattr(self, name))
        if name in ("comparisons",):
            return bool(self.comparisons)
        return False


def _flatten_strings(value: Any):
    """Every string reachable in a nested plain-data structure."""
    if isinstance(value, str):
        if value.strip():
            yield value
    elif isinstance(value, dict):
        for item in value.values():
            yield from _flatten_strings(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            yield from _flatten_strings(item)


def _fmt_number(value: float) -> str:
    """Format a float the way the assistant states it, so guard and prose agree."""
    if float(value).is_integer():
        return str(int(value))
    return f"{value:.4f}".rstrip("0").rstrip(".")


# ---------------------------------------------------------------------------
# scope
# ---------------------------------------------------------------------------

SCOPE_IN = "in_scope"
SCOPE_OUT = "out_of_scope"

INTENT_TERMINOLOGY = "terminology"
INTENT_RISK = "risk_explanation"
INTENT_EXPECTED_VS_OBSERVED = "expected_vs_observed"
INTENT_EVIDENCE = "evidence"
INTENT_DECISION_REQUEST = "decision_request"
INTENT_GENERAL = "general_ipsec"
#: "Why did this experiment fail?" -- answered from the control plane's recorded
#: verdict. When no verdict was recorded, the honest answer is that none was.
INTENT_ROOT_CAUSE = "root_cause"
#: "How critical is this asset?" -- answered from declared operator input, never
#: inferred from traffic, addresses or ML output.
INTENT_ASSET_CRITICALITY = "asset_criticality"

INTENTS: Tuple[str, ...] = (
    INTENT_TERMINOLOGY,
    INTENT_RISK,
    INTENT_EXPECTED_VS_OBSERVED,
    INTENT_EVIDENCE,
    INTENT_DECISION_REQUEST,
    INTENT_GENERAL,
    INTENT_ROOT_CAUSE,
    INTENT_ASSET_CRITICALITY,
)


@dataclass(frozen=True)
class ScopeDecision(JsonModel):
    """Whether a question is answerable by this assistant, and why.

    ``matched_terms`` records the vocabulary that put the question in scope so
    the decision is auditable. A refusal is a decision like any other: it must
    be explicable, not a black box.
    """

    in_scope: bool
    intent: str
    reason: str
    matched_terms: Tuple[str, ...] = ()
    term_key: Optional[str] = None

    def __post_init__(self) -> None:
        if self.in_scope and self.intent not in INTENTS:
            raise ValueError(f"in-scope intent must be one of {INTENTS}")


# ---------------------------------------------------------------------------
# guard
# ---------------------------------------------------------------------------

GUARD_CLEAN = "clean"
GUARD_REFUSED = "refused"
GUARD_SUBSTITUTED = "substituted"


@dataclass(frozen=True)
class GuardReport(JsonModel):
    """What the output guard found, and what it did about it.

    ``violations`` are machine-readable codes, never prose. A violation is
    never silently repaired: the answer is replaced or the question refused, and
    the reason is reported so the UI can show that the guard fired.
    """

    status: str
    violations: Tuple[str, ...] = ()
    detail: Optional[str] = None

    @property
    def clean(self) -> bool:
        return self.status == GUARD_CLEAN


# ---------------------------------------------------------------------------
# answer
# ---------------------------------------------------------------------------

ANSWER_ORIGIN_LLM = "llm"
ANSWER_ORIGIN_TEMPLATE = "deterministic_template"
ANSWER_ORIGIN_REFUSAL = "fixed_refusal"
ANSWER_ORIGIN_GLOSSARY = "glossary"
ANSWER_ORIGIN_UNAVAILABLE = "unavailable"

ANSWER_ORIGINS: Tuple[str, ...] = (
    ANSWER_ORIGIN_LLM,
    ANSWER_ORIGIN_TEMPLATE,
    ANSWER_ORIGIN_REFUSAL,
    ANSWER_ORIGIN_GLOSSARY,
    ANSWER_ORIGIN_UNAVAILABLE,
)

#: The fixed text used when a question leaves the IPsec assessment domain. It is
#: a constant, not a generation, so a refusal can never be talked out of scope.
OUT_OF_SCOPE_ANSWER = (
    "I am scoped to explaining the IPsec security assessment and the evidence "
    "recorded for it. I can help with the IPsec configuration, finding, risk "
    "rationale, or evidence shown here."
)

#: The fixed text used when the deterministic result exists but the question
#: asks for a decision. The assistant explains and declines, in that order.
DECISION_REFUSAL_ANSWER = (
    "I explain what the backend recorded; I do not make the change and I do not "
    "make the call. The recorded finding, the expected value, the observed value "
    "and the evidence are set out above. Whether to act on them is a judgement "
    "for you and the gateway owner."
)

#: Used whenever the recorded context cannot answer the question.
UNAVAILABLE_ANSWER = (
    "That information is not recorded in the current assessment. I only explain "
    "values the backend supplied, and I will not fill a gap with a guess."
)

SERVICE_UNAVAILABLE_ANSWER = (
    "The AI explanation service is unavailable. The authoritative assessment and "
    "evidence remain available."
)

INSUFFICIENT_EVIDENCE_ANSWER = (
    "I can explain the recorded information, but the current assessment does not "
    "contain enough evidence to determine that."
)


@dataclass(frozen=True)
class AiCitation(JsonModel):
    """One identifier the answer was allowed to rely on.

    Citations are assembled by the context builder, never by the model. The
    model can only choose which of the already-assembled ones to mention, so a
    citation in the response is a reference the backend minted.
    """

    kind: str
    identifier: str
    origin: str


@dataclass(frozen=True)
class AiAnswer(JsonModel):
    """The complete response for one question.

    The shape is deliberately split: ``authoritative`` and ``ml`` are server
    data the UI renders *beside* the prose with their own labels, while
    ``text`` is the only field that is generated. That split is what keeps the
    deterministic result visually separable from the AI explanation.
    """

    answer: str
    question: str
    origin: str
    scope: ScopeDecision
    guard: GuardReport
    assessment_id: Optional[str] = None
    finding_id: Optional[str] = None
    model_version: Optional[str] = None
    citations: Tuple[AiCitation, ...] = ()
    authoritative: Dict[str, Any] = field(default_factory=dict)
    ml: Optional[Dict[str, Any]] = None
    read_only: bool = True
    decision_made: bool = False
    is_explanation: bool = True
    #: Which reasoning provider produced ``answer`` -- ``"gemini"`` for a
    #: model-generated explanation, ``"none"`` when the deterministic template
    #: or a fixed refusal answered instead. The client renders this rather than
    #: inferring the source from the prose.
    provider: Optional[str] = None
    #: Why the configured model did not answer, when one was configured and
    #: failed (missing key, timeout, network, rate limit, provider error). It
    #: is populated on the grounded fallback so an analyst can tell "the model
    #: said this" from "the model was unavailable, so the recorded values are
    #: being explained without it". It never replaces the explanation.
    provider_unavailable_reason: Optional[str] = None

    def __post_init__(self) -> None:
        if self.origin not in ANSWER_ORIGINS:
            raise ValueError(f"origin must be one of {ANSWER_ORIGINS}, got {self.origin!r}")
        if self.decision_made:
            raise ValueError(
                "an AI answer can never carry decision_made=True; the assistant "
                "does not make security decisions"
            )
        if self.model_version is not None and self.origin != ANSWER_ORIGIN_LLM:
            raise ValueError(
                "model_version is only meaningful for an LLM-generated answer; a "
                "templated or fixed answer must not imply a model produced it"
            )
