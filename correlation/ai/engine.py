"""The explanation engine.

The flow is fixed and every branch is auditable:

    question
      -> scope.classify            deterministic; out of scope never reaches a model
      -> glossary.lookup           deterministic, for "what does X mean"
      -> build_grounding_context   read-only read of authoritative state
      -> grounded template         always available, never a model
      -> provider.complete         only when a model is configured
      -> guard.enforce             a violation replaces the generated text
      -> AiAnswer

Two properties hold on every path:

*Nothing is decided.* The engine cannot set a severity, cannot set a score,
cannot create a finding and cannot change an assessment. It reads them. The
:class:`~correlation.ai.models.AiAnswer` model rejects ``decision_made=True`` at
construction, so a decision cannot be serialised even if some future caller
tried.

*An answer is always grounded or it says it is not.* There is no path that
produces prose without a context to ground it in, and the "not recorded" and
"not enough evidence" responses are constants for exactly that reason.

The deterministic template is not a fallback of last resort. It is the answer
when no model is configured, and it is the substituted answer when the guard
fires. That is deliberate: the acceptance criterion "Why is this MEDIUM?" must
hold on a deployment with no model at all, and a guard that fell back to a
generic apology would be a worse product than one that falls back to the
recorded values.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Sequence, Tuple

from . import glossary
from .context import ContextSource, build_grounding_context
from .guard import enforce
from .llm import LlmProvider, NullProvider, ProviderError, history_from_turns
from .models import (
    ANSWER_ORIGIN_GLOSSARY,
    ANSWER_ORIGIN_LLM,
    ANSWER_ORIGIN_REFUSAL,
    ANSWER_ORIGIN_TEMPLATE,
    ANSWER_ORIGIN_UNAVAILABLE,
    DECISION_REFUSAL_ANSWER,
    INTENT_DECISION_REQUEST,
    INTENT_EVIDENCE,
    INTENT_EXPECTED_VS_OBSERVED,
    INTENT_GENERAL,
    INTENT_RISK,
    INTENT_TERMINOLOGY,
    INSUFFICIENT_EVIDENCE_ANSWER,
    MAX_HISTORY_TURNS,
    MAX_QUESTION_CHARS,
    ORIGIN_AI,
    ORIGIN_DETERMINISTIC,
    ORIGIN_ML,
    ORIGIN_OBSERVED,
    OUT_OF_SCOPE_ANSWER,
    UNAVAILABLE_ANSWER,
    AiAnswer,
    AiCitation,
    GroundedComparison,
    GroundedFinding,
    GroundingContext,
    GuardReport,
    ScopeDecision,
)
from .prompt import build_messages, render_context
from .scope import classify

#: Emitted ahead of a generated or templated explanation so a screenshot can
#: never be mistaken for an engine output.
EXPLANATION_BANNER = "AI EXPLANATION"


class AiExplanationEngine:
    """Explains recorded IPsec assessment state. Decides nothing.

    Constructed once per process with a read-only context source and an optional
    model provider. It holds no per-request state, so it is safe to share across
    threads and safe to construct at import time in tests.
    """

    def __init__(self, source: ContextSource, provider: Optional[LlmProvider] = None) -> None:
        self._source = source
        self._provider = provider or NullProvider()

    @property
    def source(self) -> ContextSource:
        return self._source

    @property
    def provider(self) -> LlmProvider:
        return self._provider

    def explain(
        self,
        question: str,
        *,
        assessment_id: Optional[str] = None,
        finding_id: Optional[str] = None,
        history: Sequence[Dict[str, str]] = (),
    ) -> AiAnswer:
        """Answer one question about one selected context."""
        raw = str(question or "")
        turns = history_from_turns(history)[-MAX_HISTORY_TURNS:]
        context = build_grounding_context(
            self._source,
            assessment_id=assessment_id,
            finding_id=finding_id,
        )
        scope = classify(
            raw,
            has_context=context.available,
            has_finding=context.finding is not None,
        )
        if not scope.in_scope:
            return _refusal(raw, assessment_id, finding_id, scope)

        term = glossary.lookup(raw)
        if term is not None and scope.intent == INTENT_TERMINOLOGY:
            return _glossary_answer(raw, term, context, scope, assessment_id, finding_id)

        if not context.available:
            return _unavailable(raw, context, scope, assessment_id, finding_id)

        grounded = self._template(raw, context, scope, assessment_id, finding_id)
        if not self._provider.info.configured:
            return grounded

        return self._with_model(raw, context, scope, grounded, turns, assessment_id, finding_id)

    # -- the model path ----------------------------------------------------

    def _with_model(
        self,
        question: str,
        context: GroundingContext,
        scope: ScopeDecision,
        grounded: AiAnswer,
        history: Sequence[Dict[str, str]],
        assessment_id: Optional[str],
        finding_id: Optional[str],
    ) -> AiAnswer:
        """Ask the model, then gate what it produced.

        A provider failure is not an error state for the analyst: the grounded
        template is returned instead and the origin says which one it is, so the
        UI can label it. Failing loudly would mean the analyst loses the
        explanation they asked for because a network call did not return.
        """
        try:
            generated = self._provider.complete(build_messages(question, context, scope, history=history))
        except ProviderError:
            return grounded
        if not isinstance(generated, str) or not generated.strip():
            return grounded

        text, report = enforce(
            generated.strip(),
            context,
            scope,
            fallback=grounded.answer,
        )
        if not report.clean:
            return _withheld(grounded, report)
        return AiAnswer(
            answer=f"{EXPLANATION_BANNER}\n\n{text}",
            question=question,
            origin=ANSWER_ORIGIN_LLM,
            scope=scope,
            guard=report,
            assessment_id=assessment_id,
            finding_id=finding_id or context.finding_id,
            model_version=self._provider.info.model_version,
            citations=grounded.citations,
            authoritative=grounded.authoritative,
            ml=grounded.ml,
        )

    # -- the grounded path -------------------------------------------------

    def _template(
        self,
        question: str,
        context: GroundingContext,
        scope: ScopeDecision,
        assessment_id: Optional[str],
        finding_id: Optional[str],
        *,
        guard: Optional[GuardReport] = None,
    ) -> AiAnswer:
        body = _compose(context, scope)
        if scope.intent == INTENT_DECISION_REQUEST:
            body = f"{body}\n\n{DECISION_REFUSAL_ANSWER}"
        return AiAnswer(
            answer=f"{EXPLANATION_BANNER}\n\n{body}",
            question=question,
            origin=ANSWER_ORIGIN_TEMPLATE,
            scope=scope,
            guard=guard or GuardReport(status="clean"),
            assessment_id=assessment_id,
            finding_id=finding_id or context.finding_id,
            model_version=None,
            citations=_citations(context),
            authoritative=_authoritative(context),
            ml=_ml_block(context),
        )


def _withheld(grounded: AiAnswer, report: GuardReport) -> AiAnswer:
    """The grounded answer, stamped with the fact that generated text was withheld.

    Returning the grounded answer silently would be a lie of omission: the
    analyst would have no way to know the model was asked and its answer
    refused. The notice is prepended rather than appended so it is the first
    thing read, and the violations are named so the reason is inspectable.
    """
    names = ", ".join(report.violations)
    notice = (
        f"{EXPLANATION_BANNER}\n\n"
        f"[generated explanation withheld: {names}]\n"
        f"The model's answer was not shown because it {report.detail or names}. "
        "What follows is the deterministic explanation built from the recorded values."
    )
    body = grounded.answer
    if body.startswith(f"{EXPLANATION_BANNER}\n\n"):
        body = body[len(EXPLANATION_BANNER) + 2 :]
    return AiAnswer(
        answer=f"{notice}\n\n{body}",
        question=grounded.question,
        origin=grounded.origin,
        scope=grounded.scope,
        guard=report,
        assessment_id=grounded.assessment_id,
        finding_id=grounded.finding_id,
        model_version=None,
        citations=grounded.citations,
        authoritative=grounded.authoritative,
        ml=grounded.ml,
    )


# ---------------------------------------------------------------------------
# composition
# ---------------------------------------------------------------------------

def _compose(context: GroundingContext, scope: ScopeDecision) -> str:
    """Build the WHAT / WHY / EVIDENCE / IMPACT answer from recorded values.

    Every sentence here is a projection of a value the backend produced or an
    explicit statement that one is absent. There is no interpolation of an
    unrecorded value anywhere, and no arithmetic: the score and the contribution
    are printed, never derived.
    """
    if scope.intent == INTENT_EVIDENCE:
        body = _evidence_body(context)
    elif scope.intent == INTENT_EXPECTED_VS_OBSERVED:
        body = _expected_vs_observed_body(context)
    else:
        body = _risk_body(context, scope)
    return f"{body}\n\n{_provenance(context)}"


def _provenance(context: GroundingContext) -> str:
    """Name the origin of every kind of value in this answer.

    The separation between what was observed, what the rules concluded, what a
    model predicted and what the assistant said is the point of this feature,
    so the answer says which is which in its own words rather than leaving the
    label to the UI. A reader who copies the text into a ticket carries the
    attribution with it.
    """
    lines = [
        "WHERE THIS COMES FROM",
        f"Observed facts ({ORIGIN_OBSERVED}): the packet, configuration and drift "
        "values the tools recorded.",
        f"Deterministic assessment ({ORIGIN_DETERMINISTIC}): the severity, the risk "
        "score and this finding, as the risk engine produced them.",
    ]
    if context.ml is not None and context.ml.present:
        lines.append(
            f"ML inference ({ORIGIN_ML}): a traffic-shape prediction. It is not a "
            "security judgement and did not produce the severity."
        )
    else:
        lines.append(
            f"ML inference ({ORIGIN_ML}): none was recorded for this assessment, so "
            "no machine classification contributed to this answer."
        )
    lines.append(
        f"This section ({ORIGIN_AI}) is explanation only. It restates the values "
        "above and reaches no verdict of its own."
    )
    return "\n".join(lines)


def _risk_body(context: GroundingContext, scope: ScopeDecision) -> str:
    finding = context.finding
    parts: List[str] = []

    if finding is not None:
        parts.append("WHAT")
        parts.append(
            f"The backend recorded {finding.finding_id} at {finding.severity}, from rule "
            f"{finding.rule_id} in category {finding.category}. {_assessment_sentence(context)}"
        )
        parts.append("")
        parts.append("WHY")
        parts.append(_why_paragraph(finding, context))
        parts.append("")
        parts.append("EVIDENCE")
        parts.append(_evidence_paragraph(context, finding))
        parts.append("")
        parts.append("IMPACT")
        parts.append(_impact_paragraph(context, finding))
    else:
        parts.append("WHAT")
        parts.append(_assessment_sentence(context))
        parts.append("")
        parts.append("WHY")
        parts.append(_no_finding_paragraph(context))
        parts.append("")
        parts.append("EVIDENCE")
        parts.append(_evidence_paragraph(context, None))
        parts.append("")
        parts.append("IMPACT")
        if context.risk_score is not None:
            parts.append(
                f"The recorded overall risk score is {context.risk_score}, produced by risk "
                f"policy {context.risk_policy_version or 'of unrecorded version'}. No individual "
                "contribution is stated because no single finding is selected."
            )
        else:
            parts.append(
                "The backend recorded no overall risk score for this assessment, so there is "
                "no contribution to state."
            )

    if scope.intent == INTENT_GENERAL and finding is not None:
        parts.append("")
        parts.append("OBSERVED")
        parts.append(_observed_paragraph(context))

    parts.append("")
    parts.append(
        "This is a restatement of what the backend recorded. The severity, the score and the "
        "contribution above are the risk engine's; nothing here re-derives them."
    )
    return "\n".join(parts)


def _expected_vs_observed_body(context: GroundingContext) -> str:
    parts: List[str] = ["WHAT"]
    variable = context.finding.related_variable if context.finding else None
    if variable:
        row = _comparison_for(context, variable)
        if row is not None:
            parts.append(
                f"For {row.variable} the comparison engine recorded {row.status}: expected "
                f"{_value(row.expected_value)}, observed {_value(row.observed_value)}."
            )
        else:
            parts.append(
                f"No comparison row was recorded for {variable}, so the backend did not compare "
                "that variable in this assessment."
            )
    else:
        parts.append(
            f"The comparison engine recorded {_count_label(len(context.comparisons), 'comparison row')} "
            f"for this assessment, with a recorded status of "
            f"{_overall_comparison(context)}."
        )

    parts.append("")
    parts.append("EXPECTED VERSUS OBSERVED")
    if context.comparisons:
        for row in context.comparisons:
            parts.append(
                f"{row.variable}: expected {_value(row.expected_value)}, observed "
                f"{_value(row.observed_value)}, recorded status {row.status}"
            )
    else:
        parts.append(
            "The backend recorded no comparison rows for this assessment, so there is nothing "
            "to compare here."
        )

    parts.append("")
    parts.append("CONFIGURATION AS RECORDED")
    if context.expected:
        for key in sorted(context.expected):
            parts.append(f"{key}: {_value(context.expected[key])}")
    else:
        parts.append("No expected configuration was recorded for this assessment.")
    if not context.observed:
        parts.append(
            "No observed state was recorded for this assessment, so no observed value can be "
            "set against the configuration above."
        )

    parts.append("")
    parts.append(
        "Configuration combinations are not analysed here. Whether a given combination of "
        "recorded values is permitted is a policy question, and the policy rule needed to "
        "answer it is not part of this context."
    )
    return "\n".join(parts)


def _evidence_body(context: GroundingContext) -> str:
    parts: List[str] = ["WHAT"]
    if context.evidence_ids:
        parts.append(
            f"The backend recorded {_count_label(len(context.evidence_ids), 'evidence identifier')} "
            "referenced by this assessment."
        )
    elif context.evidence_count:
        parts.append(
            f"The backend recorded {context.evidence_count} evidence references for this "
            "assessment but supplied no identifiers, so they cannot be named."
        )
    else:
        parts.append("The backend recorded no evidence references for this assessment.")

    parts.append("")
    parts.append("EVIDENCE")
    if context.evidence_ids:
        for value in context.evidence_ids:
            parts.append(f"evidence_id {value} is recorded against this assessment.")
    else:
        parts.append(
            "No evidence identifiers are available in this context, so none are cited. This "
            "is a statement about what was supplied, not a claim that the finding has no "
            "support."
        )
    if context.evidence_sources:
        parts.append("recorded evidence sources: " + ", ".join(context.evidence_sources))
    if context.integrity_status:
        parts.append(f"recorded evidence integrity status: {context.integrity_status}")

    parts.append("")
    parts.append("CHAIN OF CUSTODY")
    chain = context.custody
    if chain is not None and chain.available:
        parts.append("recorded stages, in order: " + " -> ".join(chain.stages))
        for stage in chain.stages:
            parts.append(f"{stage}: {_stage_meaning(stage)}")
        if chain.facts:
            parts.append("recorded facts:")
            for fact in chain.facts:
                parts.append(f"  {fact}")
        if chain.audit_linkage:
            parts.append(f"audit linkage: {chain.audit_linkage}")
        parts.append(
            "Every stage above was produced by the analysis pipeline. A stage that is not "
            "listed was not recorded and is not described here."
        )
    elif chain is not None:
        parts.append(chain.reason or "No custody stages were recorded for this finding.")
    else:
        parts.append(
            "The backend returned no chain of custody for this finding, so none is described."
        )

    parts.append("")
    parts.append(
        "These identifiers tell you what the backend recorded. An identifier is not an "
        "inspection: the assistant has not opened the artifact and does not claim to have."
    )
    return "\n".join(parts)


def _why_paragraph(finding: GroundedFinding, context: GroundingContext) -> str:
    row = _comparison_for(context, finding.related_variable) if finding.related_variable else None
    parts: List[str] = []
    parts.append(
        f"The recorded condition was: {finding.condition} The recorded reason was: "
        f"{finding.reason}"
    )
    parts.append(
        f"Expected value: {_value(finding.expected_value)}. Observed value: "
        f"{_value(finding.observed_value)}."
    )
    if row is not None:
        parts.append(
            f"The comparison engine recorded {row.variable} as {row.status}"
            + (f": {row.reason}" if row.reason else ".")
        )
    elif not context.comparisons:
        parts.append(
            "The backend recorded no comparison rows for this assessment, so there is no "
            "recorded comparison to point at."
        )
    if finding.description:
        parts.append(f"Recorded description: {finding.description}")
    if not context.observed:
        parts.append(
            "No observed state was recorded for this assessment. That matters here: an "
            "observed value that the comparison engine recorded is not the same as a value "
            "observed on the wire, and a passive capture does not record ESP or IKE "
            "algorithms at all."
        )
    return " ".join(parts)


def _evidence_paragraph(context: GroundingContext, finding: Optional[GroundedFinding]) -> str:
    if context.evidence_ids:
        listed = ", ".join(context.evidence_ids)
        return (
            f"The recorded evidence references for this finding are: {listed}. The assistant "
            "has not inspected any of them and describes only what the backend recorded."
        )
    if context.evidence_count:
        return (
            f"The backend recorded {context.evidence_count} evidence references for this "
            "assessment but supplied no identifiers, so none is named here."
        )
    return (
        "The backend recorded no evidence references for this assessment. Nothing is cited "
        "because nothing was supplied."
    )


def _impact_paragraph(context: GroundingContext, finding: GroundedFinding) -> str:
    parts: List[str] = []
    if finding.score_contribution is not None:
        parts.append(
            f"{finding.finding_id} contributed {finding.score_contribution} point"
            f"{'' if finding.score_contribution == 1 else 's'} to the recorded overall score."
        )
    elif finding.rule_weight is not None:
        parts.append(
            f"The recorded rule weight for {finding.finding_id} is {finding.rule_weight}, but "
            "the backend recorded no booked contribution for it, so no contribution is stated."
        )
    else:
        parts.append(
            f"The backend recorded no score contribution for {finding.finding_id}, so none is "
            "stated."
        )
    if context.risk_score is not None and context.severity is not None:
        parts.append(
            f"The recorded overall risk score is {context.risk_score}, which risk policy "
            f"{context.risk_policy_version or 'of unrecorded version'} places in the "
            f"{context.severity} band."
        )
    return " ".join(parts)


def _no_finding_paragraph(context: GroundingContext) -> str:
    if context.finding_summaries:
        listed = "; ".join(context.finding_summaries)
        return (
            f"No single finding is selected, so the severity cannot be attributed to one. "
            f"The backend recorded {len(context.finding_summaries)} finding"
            f"{'' if len(context.finding_summaries) == 1 else 's'} for this assessment: {listed}. "
            "Select one to see its expected and observed values."
        )
    if context.risk_score == 0:
        return (
            "The backend recorded no findings for this assessment, and a recorded overall score "
            "of 0 places it in the INFO band. That is an absence of recorded findings, which is "
            "different from an inspection that proved the configuration is sound."
        )
    return "The backend recorded no findings for this assessment."


def _assessment_sentence(context: GroundingContext) -> str:
    if context.severity is None and context.risk_score is None:
        return (
            "The backend recorded no severity and no overall risk score for this assessment."
        )
    return (
        f"The assessment overall is {context.severity} with a recorded risk score of "
        f"{context.risk_score}, under risk policy {context.risk_policy_version or 'of unrecorded version'}."
    )


def _observed_paragraph(context: GroundingContext) -> str:
    if not context.observed:
        return "No observed state was recorded for this assessment."
    keys = (
        "ike_seen",
        "esp_seen",
        "ah_seen",
        "packets_seen",
        "spi_count",
        "active",
        "tunnel_seen",
    )
    parts = [
        f"{key} is recorded as {_value(context.observed[key])}"
        for key in keys
        if key in context.observed
    ]
    if not parts:
        return "The recorded observed state carries no comparable counter."
    return (
        "The capture recorded: "
        + "; ".join(parts)
        + ". These are observed counters. They are not configuration and they do not "
        "establish which algorithms were negotiated."
    )


def _comparison_for(context: GroundingContext, variable: str) -> Optional[GroundedComparison]:
    for row in context.comparisons:
        if row.variable == variable:
            return row
    return None


def _overall_comparison(context: GroundingContext) -> str:
    statuses = {row.status for row in context.comparisons}
    if not statuses:
        return "no recorded status"
    return ", ".join(sorted(statuses))


def _value(value: Any) -> str:
    """A recorded value, or the explicit statement that none was recorded."""
    if value is None:
        return "not recorded in this assessment"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, str):
        return value if value.strip() else "not recorded in this assessment"
    if isinstance(value, float) and value.is_integer():
        return str(int(value))
    return str(value)


def _count_label(count: int, noun: str) -> str:
    return f"{count} {noun}" if count == 1 else f"{count} {noun}s"


_STAGE_MEANINGS = {
    "expected_state": "the configured policy, materialized from the run plan",
    "observed_state": "what the capture recorded on the wire",
    "comparison": "the expected-versus-observed comparison of those two",
    "risk_rules": "the deterministic rules that were evaluated",
    "risk_scoring": "the policy that turned the findings into a score and a severity",
    "xai": "the deterministic explanation record for this finding",
    "response_planning": "the recommendations drafted from the finding, none of which were applied",
}


def _stage_meaning(stage: str) -> str:
    return _STAGE_MEANINGS.get(stage, "a recorded pipeline stage of this assessment")


# ---------------------------------------------------------------------------
# response envelopes
# ---------------------------------------------------------------------------

def _authoritative(context: GroundingContext) -> Dict[str, Any]:
    """The server-side block the UI renders beside the explanation.

    The frontend labels this "DETERMINISTIC ASSESSMENT" and takes the values
    from here, not from the model's prose. That is what keeps the visual trust
    boundary honest: the number an analyst reads is the backend's number.
    """
    block: Dict[str, Any] = {
        "read_only": True,
        "origin": ORIGIN_DETERMINISTIC,
        "source": "correlation.risk.engine",
        "assessment_id": context.assessment_id,
        "finding_id": context.finding_id,
        "severity": context.severity,
        "risk_score": context.risk_score,
        "risk_policy_version": context.risk_policy_version,
        "risk_engine_version": context.risk_engine_version,
    }
    if context.finding is not None:
        block["finding"] = {
            "finding_id": context.finding.finding_id,
            "rule_id": context.finding.rule_id,
            "category": context.finding.category,
            "severity": context.finding.severity,
            "title": context.finding.title,
            "expected_value": context.finding.expected_value,
            "observed_value": context.finding.observed_value,
            "score_contribution": context.finding.score_contribution,
            "rule_weight": context.finding.rule_weight,
        }
    return block


def _ml_block(context: GroundingContext) -> Dict[str, Any]:
    """The ML block, kept structurally apart from the explanation.

    ``assistant_confidence`` is present and always ``None``. The field exists to
    make the absence explicit rather than merely omitted, because a model
    confidence is exactly the field an analyst would otherwise assume exists.
    """
    ml = context.ml
    return {
        "origin": ORIGIN_ML,
        "source": "correlation.ml",
        "present": bool(ml is not None and ml.present),
        "traffic_class": ml.traffic_class if ml else None,
        "classification_confidence": ml.classification_confidence if ml else None,
        "model_version": ml.model_version if ml else None,
        "anomaly": ml.anomaly if ml else None,
        "anomaly_score": ml.anomaly_score if ml else None,
        "reason": (ml.reason if ml else None)
        or "no ML result was recorded for this assessment",
        "assistant_confidence": None,
        "note": (
            "ML classification is a model prediction about traffic shape. It is not a "
            "security judgement, it does not affect severity, and the assistant has no "
            "confidence of its own."
        ),
    }


def _citations(context: GroundingContext) -> Tuple[AiCitation, ...]:
    """Identifiers the backend minted, which the answer is allowed to lean on.

    Assembled here rather than extracted from the generated text, so a citation
    in the response is always a real identifier even if the model invented a
    sentence around it.
    """
    out: List[AiCitation] = []
    if context.assessment_id:
        out.append(AiCitation("assessment", str(context.assessment_id), "observed_fact"))
    if context.finding is not None:
        out.append(
            AiCitation("finding", context.finding.finding_id, "deterministic_assessment")
        )
        out.append(AiCitation("rule", context.finding.rule_id, "deterministic_assessment"))
    for row in context.comparisons:
        out.append(AiCitation("comparison", row.variable, "deterministic_assessment"))
    for value in context.evidence_ids:
        out.append(AiCitation("evidence", str(value), "deterministic_assessment"))
    if context.drift is not None and context.drift.baseline_id:
        out.append(AiCitation("baseline", context.drift.baseline_id, "deterministic_assessment"))
    return tuple(dict.fromkeys(out))


def _refusal(
    question: str,
    assessment_id: Optional[str],
    finding_id: Optional[str],
    scope: ScopeDecision,
) -> AiAnswer:
    return AiAnswer(
        answer=OUT_OF_SCOPE_ANSWER,
        question=question,
        origin=ANSWER_ORIGIN_REFUSAL,
        scope=scope,
        guard=GuardReport(status="clean"),
        assessment_id=assessment_id,
        finding_id=finding_id,
        model_version=None,
        citations=(),
        authoritative={},
        ml=None,
    )


def _unavailable(
    question: str,
    context: GroundingContext,
    scope: ScopeDecision,
    assessment_id: Optional[str],
    finding_id: Optional[str],
) -> AiAnswer:
    body = UNAVAILABLE_ANSWER
    if context.reason:
        body = f"{body}\n\nThe recorded reason: {context.reason}."
    if scope.intent == INTENT_RISK and context.has("evidence") is False and assessment_id:
        body = f"{body}\n\n{INSUFFICIENT_EVIDENCE_ANSWER}"
    # Even a refusal states its own provenance. "I found nothing" is an
    # assertion about the record, and the reader is entitled to know that it is
    # the record being silent rather than the assistant being unhelpful.
    body = (
        f"{body}\n\nWHERE THIS COMES FROM\n"
        f"Nothing was recorded for this selection, so no {ORIGIN_OBSERVED} value, no "
        f"{ORIGIN_DETERMINISTIC} result and no {ORIGIN_ML} prediction contributed to "
        f"this answer. This section ({ORIGIN_AI}) reports the absence and invents no "
        "value to fill it."
    )
    return AiAnswer(
        answer=body,
        question=question,
        origin=ANSWER_ORIGIN_UNAVAILABLE,
        scope=scope,
        guard=GuardReport(status="clean"),
        assessment_id=assessment_id,
        finding_id=finding_id,
        model_version=None,
        citations=(),
        authoritative={},
        ml=None,
    )


def _glossary_answer(
    question: str,
    entry: glossary.GlossaryEntry,
    context: GroundingContext,
    scope: ScopeDecision,
    assessment_id: Optional[str],
    finding_id: Optional[str],
) -> AiAnswer:
    """A protocol definition, plus what this assessment records for the term.

    The definition is authored in this repository, so it needs no model and no
    guard: it cannot hallucinate because it is not generated. The second half is
    the grounding: the recorded value, or the explicit absence.
    """
    parts = [EXPLANATION_BANNER, "", glossary.render(entry), ""]
    recorded = _recorded_for_term(entry, context)
    if recorded is not None:
        parts.append(f"In the selected assessment: {recorded}")
    parts.append("")
    parts.append(
        "This definition describes the protocol. It is not a judgement about this "
        "assessment, and it does not change the recorded severity or score."
    )
    return AiAnswer(
        answer="\n".join(parts),
        question=question,
        origin=ANSWER_ORIGIN_GLOSSARY,
        scope=scope,
        guard=GuardReport(status="clean"),
        assessment_id=assessment_id,
        finding_id=finding_id,
        model_version=None,
        citations=_citations(context) if context.available else (),
        authoritative=_authoritative(context) if context.available else {},
        ml=_ml_block(context) if context.available else None,
    )


def _recorded_for_term(entry: glossary.GlossaryEntry, context: GroundingContext) -> Optional[str]:
    """The recorded value of the fields a term maps to, or the honest absence.

    Returns ``None`` when the term maps to no field at all, which is different
    from returning "not recorded": a term like AH has no counterpart in the
    fields this assessment carries, and claiming it is unrecorded would be
    inventing a gap.
    """
    fields = glossary.RECORDED_FIELDS.get(entry.key)
    if not fields:
        return None
    if not context.available:
        return (
            f"no assessment is selected, so the backend recorded no value for "
            f"{_humanise(fields[0])} in this context."
        )
    present: List[str] = []
    missing: List[str] = []
    for field in fields:
        if field in context.expected:
            present.append(f"{_humanise(field)} is recorded as {_value(context.expected[field])}")
        else:
            missing.append(_humanise(field))
    lines: List[str] = []
    if present:
        lines.append("; ".join(present) + ".")
    if missing:
        lines.append(
            "The backend did not record a value for " + _humanise_list(missing) + " in this assessment."
        )
    if not present and not missing:
        lines.append(
            f"The backend did not record a value for {_humanise(fields[0])} in this assessment."
        )
    return " ".join(lines)


def _humanise(field: str) -> str:
    return field.replace("_", " ")


def _humanise_list(fields: Sequence[str]) -> str:
    listed = [f"'{_humanise(field)}'" for field in fields]
    if len(listed) == 1:
        return listed[0]
    return ", ".join(listed[:-1]) + " and " + listed[-1]


def render_context_for_audit(context: GroundingContext) -> str:
    """The exact CONTEXT block a model would have received.

    Exposed on the service so an operator can see exactly what was sent, which
    is the only way to audit a grounding claim after the fact.
    """
    return render_context(context)
