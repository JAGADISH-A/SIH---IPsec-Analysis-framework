"""The context boundary for Gemini.

This module is the *only* thing that decides what a language model is allowed to
see. Everything the model is told about the assessment passes through
:func:`build_gemini_context`, and nothing else does.

Why a separate builder
----------------------
The deterministic template renders every recorded value the engine holds, which
is correct for a template: it needs the whole picture to compose prose, and the
guard checks the result against the full identifier set. A language model is a
different risk. Handing it the whole context invites three failures that no
prompt can fully prevent:

* **Volume.** More context is more surface for a plausible-sounding invention.
* **Authority confusion.** The full context contains drift, criticality, custody,
  ML and configuration values side by side, so the model can easily present a
  non-authoritative value as if the backend had recorded it.
* **Exfiltration.** Raw packet streams, the whole XDP journal, chain of custody
  and system configuration are not needed to answer "why is this MEDIUM", and
  sending them to a third-party API is a disclosure this system should never make
  implicitly.

So the whitelist below is small on purpose. It carries the recorded severity and
score, the selected finding's identity and its own recorded reason, a bounded
list of the comparison rows that actually bear on the finding, a bounded
evidence summary, and four authoritative verdicts restated field by field: the
declared asset context, the control plane's root cause, the recorded drift
comparison, and the recorded ML traffic profile. Gemini explains each of them;
it never recomputes, softens, or substitutes one.

What the model may be told
--------------------------
* the recorded severity, risk score and risk policy version
* the selected finding's title, severity, category, condition, reason,
  description, source and booked score contribution
* the comparison rows that bear on that finding, bounded
* a bounded evidence summary
* the declared asset/mission context, **including the operator-declared
  ``profile.criticality``**. Criticality is deliberately whitelisted: "how
  critical is the affected asset?" asks about recorded state, and answering it
  from anything other than the mission profile the store already resolved would
  let the assistant contradict the asset panel the analyst is reading beside it.
* the control plane's recorded ``root_cause`` and the confidence it recorded
* the recorded drift comparison: ``configured``, ``status``, ``reason``, the
  changed variables and the baseline the comparison was made against
* the recorded ML traffic profile, its probability when the model supplied one,
  and the model version that produced it

What is deliberately excluded
-----------------------------
Whole assessment objects, whole finding objects, raw packets, the XDP journal,
the chain of custody, internal identifiers (``finding_id``, ``rule_id``,
``related_variable``, dataset and run identifiers), the expected and observed
configuration maps, and free-form internals.

Absence is never a negative result
----------------------------------
An absent value is reported as absent, and the three "nothing recorded" cases
each carry an explicit flag so none of them can be read as a verdict:

* ``asset is None`` -- no mission profile was declared. Never "not critical".
* ``drift.configured is False`` -- no baseline was compared. Never ``no_drift``;
  ``status`` is copied verbatim and stays absent when the backend recorded none.
* ``traffic_profile.present is False`` -- ML did not run. Never a classification;
  ``traffic_class`` stays absent rather than defaulting to anything.

Not serializing whole objects
-----------------------------
Every value below is copied field by field through an explicit ``_text`` /
``_number`` /``_list`` coercion. There is no ``json.dumps(obj.__dict__)`` and no
``asdict``: a new field added to :class:`~correlation.ai.models.GroundingContext`
is invisible to Gemini until someone deliberately adds it here, and values that
are not ``str``/``int``/``float``/``bool``/``None`` are dropped rather than
reflected. :func:`build_gemini_context` is therefore a whitelist, not a filter.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Sequence

from .models import (
    GroundedComparison,
    GroundedDrift,
    GroundedFinding,
    GroundedMl,
    GroundingContext,
)

#: Hard ceiling on comparison rows. A finding rarely implicates more than a
#: handful of variables, and the cap is what stops an assessment with many
#: recorded rows from turning into an unbounded prompt.
MAX_COMPARISON_ROWS = 6

#: Hard ceiling on the evidence summary lines.
MAX_EVIDENCE_LINES = 4

#: Hard ceiling on the drift variables the model may be told moved.
MAX_CHANGED_VARIABLES = 8

#: Per-field character ceiling. Recorded values are short; anything longer is a
#: blob that does not belong in a natural-language prompt.
MAX_VALUE_CHARS = 240


def _text(value: Any, limit: int = MAX_VALUE_CHARS) -> Optional[str]:
    """Return a trimmed ``str``, or ``None`` for anything that is not text.

    Deliberately refuses non-strings: a dict or list that reaches this function
    is an object being reflected wholesale, which is exactly what this module
    exists to prevent.
    """
    if value is None or isinstance(value, bool):
        return None
    if not isinstance(value, str):
        return None
    cleaned = " ".join(value.split())
    if not cleaned:
        return None
    return cleaned if len(cleaned) <= limit else cleaned[: limit - 1] + "…"


def _number(value: Any) -> Optional[float]:
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, (int, float)):
        return float(value)
    return None


def _bounded(items: Sequence[Any], limit: int) -> List[str]:
    """Trim, drop empties, deduplicate, and cap a list of short strings."""
    out: List[str] = []
    for item in items:
        text = _text(item, limit=120)
        if text and text not in out:
            out.append(text)
        if len(out) >= limit:
            break
    return out


def _finding_block(finding: Optional[GroundedFinding]) -> Optional[Dict[str, Any]]:
    """The selected finding, field by field.

    ``finding_id``, ``rule_id`` and ``related_variable`` are omitted: they are
    internal identifiers and add nothing to a natural-language explanation.
    """
    if finding is None:
        return None
    block: Dict[str, Any] = {
        "title": _text(finding.title),
        "severity": _text(finding.severity, 24),
        "category": _text(finding.category, 64),
        "condition": _text(finding.condition),
        "reason": _text(finding.reason),
        "description": _text(finding.description),
        "source": _text(finding.source, 64),
        "score_contribution": _number(finding.score_contribution),
    }
    return {key: value for key, value in block.items() if value is not None}


def _asset_block(asset: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """Declared asset criticality and mission risk, reduced for an explanation.

    ``asset`` is the store's already-resolved ``mission_context`` (see
    :func:`correlation.ai.context._asset`). It is restated here, never
    recomputed. Only the human-facing criticality and the contextualised risk
    travel; the profile's own weights, ids and thresholds do not, because
    re-deriving them is not this layer's job and the model has no business
    recomputing a risk number.

    ``None`` in, ``None`` out -- an assessment with no declared mission profile
    must read as "not recorded", never as "not critical".
    """
    if not isinstance(asset, dict) or not asset:
        return None
    profile = asset.get("profile") if isinstance(asset.get("profile"), dict) else {}
    risk = asset.get("risk") if isinstance(asset.get("risk"), dict) else {}
    block: Dict[str, Any] = {
        "asset_id": _text(asset.get("asset_id"), 128),
        "configured": asset.get("configured"),
        "criticality": _text(profile.get("criticality"), 32),
        "role": _text(profile.get("role"), 64),
        "mission_impact": _text(profile.get("mission_impact"), 200),
        "technical_risk": _number(risk.get("technical_risk")),
        "technical_severity": _text(risk.get("technical_severity"), 24),
        "contextualized_risk": _number(risk.get("contextualized_risk")),
        "contextualized_severity": _text(risk.get("contextualized_severity"), 24),
        "context_index": _number(risk.get("context_index")),
        "reason": _text(asset.get("reason"), 300),
    }
    return {key: value for key, value in block.items() if value is not None}


def _root_cause_block(recorded: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """The control plane's verdict, restated. Never re-derived from the finding.

    ``root_cause`` is the controller's own classification and ``confidence`` is
    the confidence *it* recorded. The model may explain what that label means;
    it may not soften it, upgrade it, or propose a different cause.
    """
    if not isinstance(recorded, dict) or not recorded.get("root_cause"):
        return None
    evidence = recorded.get("evidence")
    block: Dict[str, Any] = {
        "root_cause": _text(recorded.get("root_cause"), 64),
        "confidence": _text(recorded.get("confidence"), 32),
        "reason": _text(recorded.get("reason"), 400),
        "evidence": evidence if isinstance(evidence, (list, tuple)) else None,
        "job_status": _text(recorded.get("job_status"), 24),
    }
    return {key: value for key, value in block.items() if value is not None}


def _drift_block(drift: Optional[GroundedDrift]) -> Optional[Dict[str, Any]]:
    """The recorded drift comparison, restated. Never re-derived here.

    ``configured`` is always carried, because it is the whole difference between
    "no baseline was compared" and "the comparison found nothing to report". A
    store with no validated baseline produces ``configured: False`` with a
    reason, and that must never read as ``no_drift``: ``status`` is copied
    verbatim and stays absent when the backend recorded none, so the model is
    told what was actually established.

    ``changed_variables`` are the variable names the comparison layer already
    resolved. Their baseline and current values are not repeated here -- they
    are already available as ordinary comparison rows when the backend published
    them, and restating them would create a second copy that could disagree.

    They are omitted entirely when ``configured`` is ``False``. An empty list on
    an unconfigured store is itself the claim "no variable changed", and that
    claim requires a comparison to have happened.
    """
    if drift is None:
        return None
    block: Dict[str, Any] = {
        "configured": drift.configured,
        "status": _text(drift.status, 32),
        "reason": _text(drift.reason, 300),
        "baseline_id": _text(drift.baseline_id, 128),
    }
    if drift.configured:
        block["changed_variables"] = _bounded(
            drift.changed_variables, MAX_CHANGED_VARIABLES
        )
    return {key: value for key, value in block.items() if value is not None}


def _traffic_profile_block(ml: Optional[GroundedMl]) -> Optional[Dict[str, Any]]:
    """The recorded ML traffic profile, restated. Never inferred or re-derived.

    ``present`` is always carried and is what separates "ML did not run" from
    "ML ran and reported a profile". A block with ``present: False`` must not be
    read as a classification, so ``traffic_class`` stays absent rather than
    defaulting to anything at all.

    ``classification_confidence`` is the probability the model itself recorded.
    Where the producing path supplies none it remains absent, which is a
    different statement from ``0.0``. Only fields already present on
    :class:`~correlation.ai.models.GroundedMl` travel, so nothing new is computed
    for the model's benefit.
    """
    if ml is None:
        return None
    block: Dict[str, Any] = {
        "present": ml.present,
        "traffic_class": _text(ml.traffic_class, 32),
        "classification_confidence": _number(ml.classification_confidence),
        "model_version": _text(ml.model_version, 64),
        "anomaly": ml.anomaly if isinstance(ml.anomaly, bool) else None,
        "anomaly_score": _number(ml.anomaly_score),
        "reason": _text(ml.reason, 300),
    }
    return {key: value for key, value in block.items() if value is not None}


def _comparison_block(row: GroundedComparison) -> Optional[Dict[str, Any]]:
    """One expected-vs-observed row, reduced to what an explanation can use."""
    block = {
        "variable": _text(row.variable, 80),
        "status": _text(row.status, 24),
        "expected": _text(row.expected_value, 80),
        "observed": _text(row.observed_value, 80),
        "detail": _text(row.reason, 120),
    }
    block = {key: value for key, value in block.items() if value is not None}
    return block or None


def _relevant_comparisons(
    context: GroundingContext,
) -> List[Dict[str, Any]]:
    """The comparison rows that bear on the selected finding.

    Prefers rows whose ``variable`` is the finding's ``related_variable``; if
    the finding names none, the recorded rows are taken in order. Either way the
    list is capped, so the prompt cannot grow with the size of the assessment.
    """
    related = None
    if context.finding is not None:
        related = (context.finding.related_variable or "").strip().lower()
    rows = context.comparisons or ()
    ordered = [
        row for row in rows
        if related and (row.variable or "").strip().lower() == related
    ]
    if not ordered:
        ordered = list(rows)
    out: List[Dict[str, Any]] = []
    for row in ordered[:MAX_COMPARISON_ROWS]:
        block = _comparison_block(row)
        if block:
            out.append(block)
    return out


def build_gemini_context(
    context: GroundingContext,
) -> Dict[str, Any]:
    """The complete, whitelisted payload sent to Gemini for one question.

    Always returns the same top-level keys so the shape is auditable, and fills
    unavailable values with ``None``/``[]`` rather than omitting them, so the
    model is told explicitly that a value was not recorded instead of guessing
    whether it simply was not sent.
    """
    if not context.available:
        return {
            "available": False,
            "reason": _text(context.reason, 200),
            "finding": None,
            "assessment": None,
            "key_factors": [],
            "evidence_summary": [],
            "recorded_comparisons": [],
            "asset": None,
            "root_cause": None,
            "drift": None,
            "traffic_profile": None,
        }

    assessment: Dict[str, Any] = {
        "severity": _text(context.severity, 24),
        "risk_score": _number(context.risk_score),
        "risk_policy_version": _text(context.risk_policy_version, 64),
    }
    assessment = {key: value for key, value in assessment.items() if value is not None}

    factors: List[str] = []
    if context.finding is not None:
        factors.extend(
            line for line in (
                _text(context.finding.condition),
                _text(context.finding.reason),
            ) if line
        )
    else:
        factors.extend(context.finding_summaries)

    evidence = _bounded(context.evidence_sources, MAX_EVIDENCE_LINES)
    if not evidence and context.evidence_count:
        evidence = [f"{context.evidence_count} recorded evidence reference(s)"]

    return {
        "available": True,
        "reason": None,
        "finding": _finding_block(context.finding),
        "assessment": assessment,
        "key_factors": _bounded(factors, MAX_COMPARISON_ROWS),
        "evidence_summary": evidence,
        "recorded_comparisons": _relevant_comparisons(context),
        "asset": _asset_block(context.asset),
        "root_cause": _root_cause_block(context.root_cause),
        "drift": _drift_block(context.drift),
        "traffic_profile": _traffic_profile_block(context.ml),
    }


def context_keys() -> List[str]:
    """The exact top-level keys Gemini is allowed to receive.

    Exposed so the boundary test can assert against the whitelist rather than a
    hand-copied list that could itself drift.
    """
    return [
        "available",
        "reason",
        "finding",
        "assessment",
        "key_factors",
        "evidence_summary",
        "recorded_comparisons",
        "asset",
        "root_cause",
        "drift",
        "traffic_profile",
    ]