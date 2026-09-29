"""The scoped IPsec prompt.

The prompt is one long, explicit contract, and it is written to be *read* by a
reviewer as much as by a model. Everything it forbids is also forbidden by
:mod:`correlation.ai.guard`, so a model that ignores an instruction produces a
substituted answer rather than a wrong one. The prompt exists to make that
substitution rare, not to be the only defence.

The context block is rendered from a :class:`~correlation.ai.models.GroundingContext`
and nothing else. Each value is prefixed with its origin so the model cannot
promote a prediction into an observation or a recorded value into a judgement.
A value the backend did not record is written as ``NOT RECORDED`` with the field
name, which is the one rendering the model is most likely to echo faithfully.

The prompt never contains: a key, a credential, a raw authentication value, a
journal body, or a packet payload. The context builder does not produce any of
those, and the renderer refuses to pass a value it does not recognise.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional, Sequence, Tuple

from .models import (
    INTENT_DECISION_REQUEST,
    INTENT_EVIDENCE,
    INTENT_EXPECTED_VS_OBSERVED,
    INTENT_RISK,
    INTENT_TERMINOLOGY,
    GroundedFinding,
    GroundingContext,
    ScopeDecision,
)

#: The wire marker for a value the backend did not record. Deliberately shouty
#: and unmissable: the model must copy it, not paraphrase it into a value.
NOT_RECORDED = "NOT RECORDED"

SYSTEM_PROMPT = """\
You are the IPsec explanation layer inside Sentinel, an IPsec security \
assessment system. You explain. You do not decide.

The deterministic backend has already produced the finding, the severity, the \
risk score and the evidence. Those are settled. Your only job is to restate \
them in clear technical English for an analyst who is looking at this screen.

WHAT YOU MUST NEVER DO
- Never assign, change, suggest or imply a severity, a risk score, a weight or a \
contribution. Only ever repeat values given to you in the CONTEXT block.
- Never create a finding, or say something "should" be a finding.
- Never say what the analyst should change, enable, disable or reconfigure. If \
asked, explain the recorded finding and the recorded configuration, then say \
plainly that the decision is not yours to make.
- Never claim to have inspected an artifact you were not given. You see \
identifiers, not artifacts.
- Never cite an identifier that is not in the CONTEXT block. That includes \
finding ids, rule ids, evidence ids, SPIs and run ids.
- Never fill a missing value. If a field is NOT RECORDED, say that the backend \
did not provide it, in those words, and stop there.
- Never give yourself a confidence score. You do not have one.
- Never write code, configuration files, or instructions for attacking \
anything.

HOW TO ANSWER
Use this shape, in this order, and keep it short:

WHAT   one sentence naming the recorded result.
WHY    the recorded expected and observed values, and the recorded comparison.
EVIDENCE   the evidence identifiers the context gives you, or a plain statement \
that none were recorded.
IMPACT the recorded contribution to the risk score.

Use these words for these things, and do not blur them:
- "the backend recorded" / "the comparison recorded" for anything in the \
CONTEXT block. Never "I detected", "I found", "I analysed", "the analysis shows".
- "the ML model classified" for the traffic profile. It is a prediction, not an \
observation, and not a security judgement.
- "not recorded in this assessment" for a field marked NOT RECORDED.

DOMAIN
IPsec: IKE, ESP, AH, PFS, DH groups, IKE and ESP proposals, encryption, \
integrity, authentication, tunnel and transport mode, IPv4 and IPv6, address \
family, traffic selectors, SPI, sequence numbers, Security Associations, \
rekeying, and this system's findings, risk explanations, comparisons, evidence, \
drift and chain of custody.

If a question is outside that domain, reply with exactly: \
"I'm scoped to explaining the IPsec security assessment and its recorded \
evidence. I can help with the IPsec configuration, finding, risk rationale, or \
evidence shown here."

If the context is not enough to answer, say so and name what is missing. A \
short honest "the backend did not record that" is a correct answer. Never \
generate a confident answer because the question expects one.
"""

#: Appended when the question asks for a decision. Kept separate from the base
#: prompt so its presence is auditable in the request record.
DECISION_APPENDIX = """\

THE QUESTION ASKS FOR A DECISION
Answer it by explaining the recorded finding and the recorded configuration \
values, and then state, in your own words, that you explain what was recorded \
and do not make the call. Do not recommend an action, do not describe one as \
the obvious one, and do not soften the recorded severity.
"""


def render_context(context: GroundingContext) -> str:
    """The CONTEXT block: recorded values only, each labelled with its origin."""
    lines: List[str] = []
    add = lines.append

    if not context.available:
        add("ASSESSMENT CONTEXT IS NOT AVAILABLE.")
        add(f"reason: {context.reason or 'the backend did not return a resolvable assessment'}")
        add("There are no recorded values to explain. Say the assessment is not in the "
            "recorded context and stop. Do not describe a finding, a severity, a score "
            "or a configuration, because none was supplied.")
        return "\n".join(lines)

    add(f"assessment_id: {context.assessment_id}")
    add(f"scenario: {context.scenario or NOT_RECORDED}")
    add(f"slot: {context.slot or NOT_RECORDED}")
    add(f"dataset_run_id: {context.dataset_run_id or NOT_RECORDED}")

    add("")
    add("[deterministic_assessment] produced by correlation.risk.engine")
    add(f"overall_severity: {context.severity or NOT_RECORDED}")
    add(f"overall_risk_score: {context.risk_score if context.risk_score is not None else NOT_RECORDED}")
    add(f"risk_policy_version: {context.risk_policy_version or NOT_RECORDED}")
    add(f"risk_engine_version: {context.risk_engine_version or NOT_RECORDED}")

    if context.finding is not None:
        add("")
        add("[deterministic_assessment] the selected finding")
        for line in _finding_lines(context.finding):
            add(line)
    else:
        add("")
        add("[deterministic_assessment] no single finding is selected.")
        if context.finding_summaries:
            add("findings in this assessment:")
            for summary in context.finding_summaries:
                add(f"  - {summary}")
        else:
            add("findings in this assessment: none recorded")

    add("")
    add(f"[observed_fact] expected configuration, from {context.assessment_id}")
    if context.expected:
        for key in sorted(context.expected):
            add(f"{key}: {_render_value(context.expected[key])}")
    else:
        add("no expected configuration was recorded for this assessment")

    add(f"[observed_fact] observed state, from the capture")
    if context.observed:
        for key in sorted(context.observed):
            add(f"{key}: {_render_value(context.observed[key])}")
    else:
        add("no observed state was recorded for this assessment")
    add(
        "note: a packet capture records protocol activity, not configuration. "
        "The observed ESP and IKE algorithms are not observable and are therefore "
        "absent above. Never supply them."
    )

    if context.comparisons:
        add("")
        add("[deterministic_assessment] comparison rows, from correlation.comparison.engine")
        for row in context.comparisons:
            add(
                f"variable: {row.variable} | status: {row.status} | "
                f"expected: {_render_value(row.expected_value)} | "
                f"observed: {_render_value(row.observed_value)}"
            )
    else:
        add("")
        add("comparison rows: none recorded")

    add("")
    add("[deterministic_assessment] evidence")
    if context.evidence_ids:
        for value in context.evidence_ids:
            add(f"evidence_id: {value}")
    elif context.evidence_count is not None:
        add(f"evidence references recorded: {context.evidence_count} (identifiers not supplied)")
    else:
        add("no evidence references were recorded for this assessment")
    if context.integrity_status:
        add(f"evidence integrity status: {context.integrity_status}")

    if context.custody is not None:
        add("")
        add(f"[deterministic_assessment] chain of custody, from {context.assessment_id}")
        if context.custody.available:
            add("recorded stages, in order: " + " -> ".join(context.custody.stages))
        else:
            add("no custody stages were recorded")
        if context.custody.audit_linkage:
            add(f"audit linkage: {context.custody.audit_linkage}")
        if context.custody.evidence_ids:
            add("custody evidence ids: " + ", ".join(context.custody.evidence_ids))
        add("Never add a stage that is not listed above.")

    if context.drift is not None:
        add("")
        add("[deterministic_assessment] drift")
        if context.drift.configured:
            add(f"status: {context.drift.status or NOT_RECORDED}")
            add(f"baseline_id: {context.drift.baseline_id or NOT_RECORDED}")
            add(
                "changed variables: "
                + (", ".join(context.drift.changed_variables) if context.drift.changed_variables
                   else "none")
            )
        else:
            add("not configured: "
                + (context.drift.reason or "no validated baseline is configured"))

    ml = context.ml
    add("")
    add("[ml_inference] traffic classification, from correlation.ml")
    if ml is None or not ml.present:
        add("not present: " + (ml.reason if ml and ml.reason
                               else "no ML result was recorded for this assessment"))
    else:
        add(f"traffic_class: {ml.traffic_class or NOT_RECORDED}")
        add(
            "classification_confidence: "
            + (f"{ml.classification_confidence}" if ml.classification_confidence is not None
               else NOT_RECORDED + " (the model supplied no probability)")
        )
        add(f"model_version: {ml.model_version or NOT_RECORDED}")
        if ml.anomaly is not None:
            add(f"anomaly: {ml.anomaly}")
    add(
        "note: this is a model prediction about traffic shape. It is not a "
        "security judgement and it does not affect severity. Report it as recorded "
        "and give it no confidence of your own."
    )

    if context.asset:
        add("")
        add("[configured] declared asset context")
        for key in sorted(context.asset):
            add(f"{key}: {_render_value(context.asset[key])}")
    else:
        add("")
        add("asset context: not configured for this assessment. Do not describe this "
            "asset's importance, role or criticality; none is recorded.")

    return "\n".join(lines)


def _finding_lines(finding: GroundedFinding) -> List[str]:
    return [
        f"finding_id: {finding.finding_id}",
        f"rule_id: {finding.rule_id}",
        f"category: {finding.category}",
        f"severity: {finding.severity or NOT_RECORDED}",
        f"title: {finding.title or NOT_RECORDED}",
        f"description: {finding.description or NOT_RECORDED}",
        f"reason: {finding.reason or NOT_RECORDED}",
        f"condition: {finding.condition or NOT_RECORDED}",
        f"source: {finding.source or NOT_RECORDED}",
        f"related_variable: {finding.related_variable or NOT_RECORDED}",
        f"expected_value: {_render_value(finding.expected_value)}",
        f"observed_value: {_render_value(finding.observed_value)}",
        "score_contribution: "
        + (str(finding.score_contribution) if finding.score_contribution is not None
           else NOT_RECORDED),
        "rule_weight: "
        + (str(finding.rule_weight) if finding.rule_weight is not None else NOT_RECORDED),
    ]


def _render_value(value: Any) -> str:
    """Render one recorded value, or the explicit not-recorded marker."""
    if value is None:
        return NOT_RECORDED
    if isinstance(value, str):
        return value if value.strip() else NOT_RECORDED
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    try:
        return json.dumps(value, sort_keys=True, default=str)
    except (TypeError, ValueError):
        return str(value)


def build_messages(
    question: str,
    context: GroundingContext,
    scope: ScopeDecision,
    *,
    history: Sequence[Dict[str, str]] = (),
) -> List[Dict[str, str]]:
    """The full message list for one question.

    ``history`` is prior turns of the same conversation, alternating user and
    assistant. It is included as context for follow-up phrasing, and it is not
    treated as evidence: a follow-up may refer to something said earlier, but
    every value still has to come from the CONTEXT block.
    """
    system = SYSTEM_PROMPT
    if scope.intent == INTENT_DECISION_REQUEST:
        system = system + DECISION_APPENDIX
    messages = [{"role": "system", "content": system}]
    for turn in history:
        role = str(turn.get("role") or "").strip().lower()
        content = str(turn.get("content") or "").strip()
        if role in ("user", "assistant") and content:
            messages.append({"role": role, "content": content})
    messages.append(
        {
            "role": "user",
            "content": (
                f"CONTEXT\n---\n{render_context(context)}\n---\n\n"
                f"INTENT: {scope.intent}\n"
                f"QUESTION: {question.strip()}\n\n"
                "Answer the question using only the CONTEXT block above."
            ),
        }
    )
    return messages


def intent_hint(scope: ScopeDecision) -> Optional[str]:
    """A one-line steer for the intent, kept beside the prompt for auditing."""
    return {
        INTENT_RISK: (
            "Restate the recorded severity, the recorded expected and observed "
            "values, and the recorded contribution. Do not restate the score as if "
            "it were yours to explain the arithmetic of; just say what it is."
        ),
        INTENT_EXPECTED_VS_OBSERVED: (
            "Quote the recorded expected and observed values side by side and name "
            "the recorded comparison status for that variable."
        ),
        INTENT_EVIDENCE: (
            "Cite only the evidence identifiers present in the context. If none are "
            "present, say no evidence identifiers were recorded."
        ),
        INTENT_TERMINOLOGY: (
            "Explain the protocol term, then say whether this assessment records a "
            "value for it. If it does not, say the field is not recorded."
        ),
        INTENT_DECISION_REQUEST: (
            "Explain the recorded finding and configuration, then decline the "
            "decision explicitly."
        ),
    }.get(scope.intent)
