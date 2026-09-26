"""Analysis-stage audit layer — the authoritative record of what was
observed, compared, inferred, assessed and explained.

Scope
-----
This module audits the *analysis* half of the pipeline:

    observation -> expected state -> comparison -> ML -> risk -> explainability

It does **not** own the two audit implementations that already exist, and it
deliberately does not duplicate them:

* ``controller/audit.py`` owns the **observation journal**
  (``results/audit/events.jsonl``): raw TAP/TShark/Zeek packet-level events.
  This module never re-records a packet; it *references* that journal through
  the existing :class:`~correlation.models.evidence.EvidenceRef`
  ``audit_event_reference`` field.
* ``correlation/response/audit.py`` owns the **response-lifecycle ledger**
  (a hash-chained, in-memory ``AuditLedger``) for
  proposed -> authorized -> executed.  This module never restates an
  authorization or an execution result; when a response exists it records only
  a reference so the two records can be joined without a second source of truth.

Why this layer exists
---------------------
The engines already refuse to fabricate evidence, but that refusal was not
*recorded anywhere*.  A protocol comparison outcome carries no machine-readable
provenance (``source`` is ``None``; only ML outcomes are labelled
``source="ml"``), so an auditor reading a stored result cannot tell whether an
observed value came from real observation, from a model, or was never
established.  This layer persists that provenance.

The non-conflation contract
---------------------------
Every event declares a ``source`` from a fixed vocabulary, and both the pair
``(source, authoritative)`` (checked against :data:`SOURCE_AUTHORITATIVE`) and the
pair ``(event_type, source)`` (checked against :data:`EVENT_SOURCE`) are validated
at construction.  A record can therefore not present a model result as an
observation, nor present a derived comparison as authoritative.  The nine
distinctions an auditor must be able to make map onto event types and sources as
follows, and they can never be collapsed:

    EXPECTED          expected_state      source=plan/expected-state  authoritative=False
    OBSERVED          observed_state      source=observation/state-builder  authoritative=True
    COMPARED          comparison          source=comparison-engine   authoritative=False
    INFERRED_BY_ML    ml_result           source=ml                   authoritative=False
    ML_FAILURE        ml_failure          source=ml                   authoritative=False
    RISK_ASSESSMENT   risk_assessment     source=risk-engine          authoritative=False
    EXPLANATION       explanation         source=explainability-engine authoritative=False
    PROPOSED_RESPONSE response_proposal   source=response-recommendation authoritative=False
    AUTHORIZED        (response/audit.py AuditLedger owns this event type)
    EXECUTED          (response/audit.py AuditLedger owns this event type)

Note that only ``observed_state`` is authoritative.  Expected state is *not*
authoritative evidence (it is an intent, from the plan); a comparison is a
*derived judgement* rather than a fresh observation (so it is non-authoritative,
while each of its variables still carries the real observed-side source and
authority it inherited); and a risk score or an explanation is a judgement about
evidence, not evidence.

Identity and integrity
----------------------
Each event carries a ``CorrelationIdentity`` (run / experiment / sequence /
window) and a content-addressed ``event_id`` derived from its own fields by
:func:`derive_event_id`.  Because the id covers the content, replaying the same
inputs reproduces byte-identical records, and a persisted record whose fields
were edited after the fact is rejected by :meth:`AuditEvent.from_dict` rather
than being trusted.  ``recorded_at`` is optional and caller-supplied for the same
reason: no wall clock is consulted, so replays stay deterministic.

Non-fabrication
---------------
The recorder derives events only from objects that were actually produced.  It
never synthesizes an expected value, never substitutes a model's output for an
observation, and never marks a missing stage as complete.  When ML fails, the
observation/comparison/risk/explanation events are still written and the ML
event is recorded as a failure with its error -- the authoritative path is never
erased by a model failure.  When a value was not established, the recorded
``observed_value`` is ``None`` and the comparison status stays ``UNKNOWN``.

Invariants enforced mechanically
--------------------------------
1. Observed state comes only from real observation sources.
2. Expected state comes only from the plan.
3. ML output is advisory and non-authoritative.
4. ML output never overwrites an authoritative protocol observation.
5. Missing evidence stays UNKNOWN; it is never fabricated.
6. Expected values are never copied into the observed-evidence channel.
7. Records preserve source/provenance.
8. Persisting an audit event does not mutate ExpectedState or ObservedState
   (all recorded models are frozen and are converted to plain dicts).
9-11. No enforcement import, no XDP action, no hidden execution path -- the
   module imports no execution/enforcement package at all (asserted by AST
   tests in ``tests/test_audit_layer.py``).
12. Deterministic: no wall-clock read. ``recorded_at`` is caller-supplied or
   omitted, so replaying the same inputs reproduces byte-identical events.
13. Response authorization boundaries are untouched: this module records
   references, never authorization or execution decisions.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from .models._base import JsonModel
from .models.evidence import EvidenceRef
from .models.identity import CorrelationIdentity

#: Schema version for analysis-stage audit events. Independent of
#: ``controller.audit.AUDIT_EVENTS_SCHEMA_VERSION`` ("v1", observation journal)
#: and of ``correlation_schema_version``, because this record shape is its own
#: contract.
AUDIT_SCHEMA_VERSION = "v1"

# -- event types -------------------------------------------------------------

#: Expected state materialized from the experiment plan (an intent, not evidence).
EVENT_EXPECTED_STATE = "expected_state"
#: Observed IPsec state aggregated from real observation (the only authoritative
#: evidence class in this layer).
EVENT_OBSERVED_STATE = "observed_state"
#: Expected-vs-observed comparison outcome, with per-variable provenance.
EVENT_COMPARISON = "comparison"
#: An ML inference result. Advisory; never authoritative.
EVENT_ML_RESULT = "ml_result"
#: An ML inference attempt that failed. The authoritative path is unaffected.
EVENT_ML_FAILURE = "ml_failure"
#: A risk assessment derived from comparison (and optionally ML) evidence.
EVENT_RISK_ASSESSMENT = "risk_assessment"
#: An explainability result derived from a risk assessment.
EVENT_EXPLANATION = "explanation"
#: A reference to a response proposal that exists in the response layer.
#: This module never records authorization or execution -- see
#: ``correlation/response/audit.py``.
EVENT_RESPONSE_PROPOSAL = "response_proposal"

ANALYSIS_EVENT_TYPES: Tuple[str, ...] = (
    EVENT_EXPECTED_STATE,
    EVENT_OBSERVED_STATE,
    EVENT_COMPARISON,
    EVENT_ML_RESULT,
    EVENT_ML_FAILURE,
    EVENT_RISK_ASSESSMENT,
    EVENT_EXPLANATION,
    EVENT_RESPONSE_PROPOSAL,
)

# -- source vocabulary -------------------------------------------------------

#: Expected state. Reuses the existing "plan" notion from
#: ``ExpectedStateAdapter`` rather than inventing a new term. Not authoritative:
#: an expected value is an intent, never evidence of what happened.
SOURCE_EXPECTED = "plan/expected-state"
#: Observed state from the real passive state builder. The only authoritative
#: source; aligns with the documented ``EvidenceRef`` ``live_xdp`` / ``audit_tap``
#: evidence vocabulary.
SOURCE_OBSERVED = "observation/state-builder"
#: ML inference. Reuses ``correlation.comparison.ml_comparison.SOURCE_ML``
#: verbatim so the two layers cannot disagree about the label.
SOURCE_ML = "ml"
#: Risk engine output.
SOURCE_RISK = "risk-engine"
#: Explainability engine output.
SOURCE_EXPLAINABILITY = "explainability-engine"
#: A response proposal living in the response layer.
SOURCE_RESPONSE_RECOMMENDATION = "response-recommendation"
#: Comparison output from ``correlation.comparison.ComparisonEngine``. This is a
#: *derived* judgement, not a new observation, so it is deliberately a separate
#: source from :data:`SOURCE_OBSERVED` and is never authoritative. Each compared
#: variable still carries its own ``observed_value_source`` /
#: ``observed_value_authoritative`` pair, so the real observation provenance
#: survives even though the comparison event itself does not claim authority.
SOURCE_COMPARISON = "comparison-engine"

AUDIT_SOURCES: Tuple[str, ...] = (
    SOURCE_EXPECTED,
    SOURCE_OBSERVED,
    SOURCE_ML,
    SOURCE_RISK,
    SOURCE_EXPLAINABILITY,
    SOURCE_RESPONSE_RECOMMENDATION,
    SOURCE_COMPARISON,
)

#: The single source of truth for which sources may claim authority.
#: Only real observation is authoritative; everything else is advisory. This is
#: what makes invariants 3, 4 and 6 machine-checked rather than documentary.
SOURCE_AUTHORITATIVE: Dict[str, bool] = {
    SOURCE_EXPECTED: False,
    SOURCE_OBSERVED: True,
    SOURCE_ML: False,
    SOURCE_RISK: False,
    SOURCE_EXPLAINABILITY: False,
    SOURCE_RESPONSE_RECOMMENDATION: False,
    SOURCE_COMPARISON: False,
}

#: The only source permitted to carry each analysis event type. Recording an
#: ML result as if it came from the observation builder (or vice versa) is a
#: provenance forgery, so it is rejected at construction time rather than left
#: to reviewer vigilance. Together with :data:`SOURCE_AUTHORITATIVE` this makes
#: the "EXPECTED vs OBSERVED vs COMPARED" distinction machine-enforced.
EVENT_SOURCE: Dict[str, str] = {
    EVENT_EXPECTED_STATE: SOURCE_EXPECTED,
    EVENT_OBSERVED_STATE: SOURCE_OBSERVED,
    EVENT_COMPARISON: SOURCE_COMPARISON,
    EVENT_ML_RESULT: SOURCE_ML,
    EVENT_ML_FAILURE: SOURCE_ML,
    EVENT_RISK_ASSESSMENT: SOURCE_RISK,
    EVENT_EXPLANATION: SOURCE_EXPLAINABILITY,
    EVENT_RESPONSE_PROPOSAL: SOURCE_RESPONSE_RECOMMENDATION,
}


def derive_event_id(payload: Dict[str, Any]) -> str:
    """Derive a stable ``event_id`` from the full event content.

    Content-addressed rather than random so that replaying the same pipeline
    with the same inputs produces byte-identical records (invariant 12). The
    digest covers every other field, so :meth:`AuditEvent.from_dict` can also
    use it to detect a record that was edited after it was written.
    """
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"),
                           default=str)
    return "audit-" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:32]


def validate_source(source: str, authoritative: bool) -> str:
    """Reject any (source, authoritative) pair that is not the declared truth."""
    if source not in AUDIT_SOURCES:
        raise ValueError(
            f"source must be one of {AUDIT_SOURCES}, got {source!r}"
        )
    expected = SOURCE_AUTHORITATIVE[source]
    if authoritative is not expected:
        raise ValueError(
            f"source {source!r} is authoritative={expected}; refusing to record "
            f"it as authoritative={authoritative}"
        )
    return source


@dataclass(frozen=True)
class AuditEvent(JsonModel):
    """One immutable analysis-stage audit event.

    ``identity`` carries ``dataset_run_id`` / ``experiment_id`` / ``sequence``
    and the window bounds, reusing :class:`CorrelationIdentity` rather than
    duplicating those fields.

    Stage-specific payloads are optional by design: a run may legitimately end
    after comparison, or after an ML failure, and an absent field means "this
    stage did not produce a result" -- never "this stage produced a default".
    """

    event_type: str
    source: str
    authoritative: bool
    identity: CorrelationIdentity
    provenance: Dict[str, Any] = field(default_factory=dict)
    recorded_at: Optional[str] = None
    expected_ref: Optional[Dict[str, Any]] = None
    observed_ref: Optional[Dict[str, Any]] = None
    comparison: Optional[Dict[str, Any]] = None
    ml_ref: Optional[Dict[str, Any]] = None
    risk_ref: Optional[Dict[str, Any]] = None
    explanation_ref: Optional[Dict[str, Any]] = None
    decision: Optional[Dict[str, Any]] = None
    response_proposal_ref: Optional[str] = None
    evidence_refs: Tuple[EvidenceRef, ...] = field(default_factory=tuple)
    schema_version: str = AUDIT_SCHEMA_VERSION
    event_id: Optional[str] = None

    def __post_init__(self) -> None:
        if self.event_type not in ANALYSIS_EVENT_TYPES:
            raise ValueError(
                f"event_type must be one of {ANALYSIS_EVENT_TYPES}, "
                f"got {self.event_type!r}"
            )
        validate_source(self.source, self.authoritative)
        required_source = EVENT_SOURCE[self.event_type]
        if self.source != required_source:
            raise ValueError(
                f"event_type {self.event_type!r} may only be recorded with "
                f"source={required_source!r}, refusing to record it as "
                f"{self.source!r}"
            )
        if not isinstance(self.identity, CorrelationIdentity):
            raise TypeError("identity must be a CorrelationIdentity")
        if self.recorded_at is not None and not isinstance(self.recorded_at, str):
            raise TypeError("recorded_at must be an ISO string or None")
        if not isinstance(self.provenance, dict):
            raise TypeError("provenance must be a dict")
        for name in (
            "expected_ref", "observed_ref", "comparison", "ml_ref",
            "risk_ref", "explanation_ref", "decision",
        ):
            value = getattr(self, name)
            if value is not None and not isinstance(value, dict):
                raise TypeError(f"{name} must be a dict or None")
        if not isinstance(self.evidence_refs, tuple):
            raise TypeError("evidence_refs must be a tuple of EvidenceRef")
        for ref in self.evidence_refs:
            if not isinstance(ref, EvidenceRef):
                raise TypeError("evidence_refs must contain EvidenceRef objects")
        self._seal_event_id()

    def _seal_event_id(self) -> None:
        """Assign the content-addressed id, or verify a supplied one.

        Called from ``__post_init__`` so a freshly built event and a replayed one
        agree, and so a persisted record whose content was edited after the fact
        is rejected on read instead of being trusted.
        """
        computed = derive_event_id(self._base_payload())
        if self.event_id is None:
            object.__setattr__(self, "event_id", computed)
        elif self.event_id != computed:
            raise ValueError(
                f"event_id {self.event_id!r} does not match the event content "
                f"(expected {computed!r}); this record was modified after it "
                f"was written"
            )

    def _base_payload(self) -> Dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "event_type": self.event_type,
            "source": self.source,
            "authoritative": self.authoritative,
            "identity": dataclass_asdict(self.identity),
            "provenance": dataclass_asdict(self.provenance),
            "recorded_at": self.recorded_at,
            "expected_ref": _plain(self.expected_ref),
            "observed_ref": _plain(self.observed_ref),
            "comparison": _plain(self.comparison),
            "ml_ref": _plain(self.ml_ref),
            "risk_ref": _plain(self.risk_ref),
            "explanation_ref": _plain(self.explanation_ref),
            "decision": _plain(self.decision),
            "response_proposal_ref": self.response_proposal_ref,
            "evidence_refs": [dataclass_asdict(ref) for ref in self.evidence_refs],
        }

    def to_dict(self) -> Dict[str, Any]:
        payload = self._base_payload()
        payload["event_id"] = self.event_id
        return payload

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AuditEvent":
        return cls(
            event_type=data["event_type"],
            source=data["source"],
            authoritative=data["authoritative"],
            identity=CorrelationIdentity.from_dict(data["identity"]),
            provenance=data.get("provenance") or {},
            recorded_at=data.get("recorded_at"),
            expected_ref=data.get("expected_ref"),
            observed_ref=data.get("observed_ref"),
            comparison=data.get("comparison"),
            ml_ref=data.get("ml_ref"),
            risk_ref=data.get("risk_ref"),
            explanation_ref=data.get("explanation_ref"),
            decision=data.get("decision"),
            response_proposal_ref=data.get("response_proposal_ref"),
            evidence_refs=tuple(
                EvidenceRef.from_dict(ref) for ref in data.get("evidence_refs") or ()
            ),
            schema_version=data.get("schema_version", AUDIT_SCHEMA_VERSION),
            event_id=data.get("event_id"),
        )


def dataclass_asdict(obj: Any) -> Dict[str, Any]:
    """Recursively convert a frozen dataclass model to plain JSON data."""
    import dataclasses

    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        return {k: dataclass_asdict(v) for k, v in dataclasses.asdict(obj).items()}
    if isinstance(obj, dict):
        return {k: dataclass_asdict(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [dataclass_asdict(v) for v in obj]
    return obj


def _plain(value: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """Coerce an optional ref payload to plain JSON-serializable data.

    Stage payloads legitimately contain nested frozen dataclasses (e.g. the
    explainability summary, or an ``ExpectedState`` sub-model). Converting here
    keeps :meth:`AuditEvent.to_dict` total, so an audit record can always be
    serialized and replayed without the recorder knowing every stage's shape.
    """
    if value is None:
        return None
    return dataclass_asdict(value)


# -- journal -----------------------------------------------------------------


class AuditJournal:
    """Append-only JSONL journal of analysis-stage audit events.

    Mirrors the durability convention already used by the observation journal
    (``controller/audit.py``): one JSON object per line, flushed and ``fsync``'d
    on every append, and a reader that raises on any corrupt line so a
    truncated log can never silently pass validation.

    Unlike the observation journal this stage does not require a wall-clock
    ``recorded_at``; an event without one is valid, which keeps replays
    deterministic (invariant 12).
    """

    def __init__(self, path: Optional[str] = None) -> None:
        self.path = Path(path) if path is not None else None

    def append(self, event: AuditEvent) -> AuditEvent:
        if not isinstance(event, AuditEvent):
            raise TypeError("append requires an AuditEvent")
        if self.path is None:
            raise ValueError("this journal has no path; pass path= to persist")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.path, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(event.to_dict(), sort_keys=True) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        return event

    def extend(self, events: Iterable[AuditEvent]) -> List[AuditEvent]:
        return [self.append(event) for event in events]

    def read(self) -> List[AuditEvent]:
        if self.path is None or not self.path.exists():
            return []
        events: List[AuditEvent] = []
        for number, line in enumerate(
            self.path.read_text(encoding="utf-8").splitlines(), 1
        ):
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"corrupt audit event (line {number}): {exc}")
            events.append(AuditEvent.from_dict(record))
        return events

    def of_type(self, event_type: str) -> List[AuditEvent]:
        return [e for e in self.read() if e.event_type == event_type]


# -- lifecycle recording -----------------------------------------------------


def _expected_ref(expected: Any) -> Dict[str, Any]:
    """Reference the expected state without copying it into an evidence channel."""
    return {
        "source": SOURCE_EXPECTED,
        "authoritative": SOURCE_AUTHORITATIVE[SOURCE_EXPECTED],
        "mode": expected.mode,
        "address_family": expected.address_family,
        "ike": expected.ike.to_dict(),
        "esp": expected.esp.to_dict(),
        "traffic_profile": expected.traffic.profile,
    }


def _observed_ref(observed: Any) -> Dict[str, Any]:
    """Reference observed state as recorded by the real state builder."""
    return {
        "source": SOURCE_OBSERVED,
        "authoritative": SOURCE_AUTHORITATIVE[SOURCE_OBSERVED],
        "timestamp_ns": observed.timestamp_ns,
        "tunnel_seen": observed.tunnel_seen,
        "esp_seen": observed.esp_seen,
        "ah_seen": observed.ah_seen,
        "ike_seen": observed.ike_seen,
        "packets_seen": observed.packets_seen,
        "bytes_seen": observed.bytes_seen,
        "spi_count": len(observed.spis),
    }


def _comparison_ref(correlation: Any) -> Dict[str, Any]:
    """Per-variable comparison outcomes with their observed-side provenance.

    Protocol comparison records do not carry a ``source`` field of their own, so
    the provenance of each observed value is recorded here explicitly:

    * an established observed value came from real observation -> authoritative
    * a value the model produced is kept separate and never authoritative
    * a value that was never established is ``None`` and stays UNKNOWN
    """
    observed_authoritative = True
    established = sum(
        len(getattr(correlation, name, ()) or ())
        for name in ("matches", "mismatches", "unknowns", "not_applicable")
    )
    variables = []
    for name in ("matches", "mismatches", "unknowns", "not_applicable"):
        for record in getattr(correlation, name, ()) or ():
            variables.append(
                {
                    "variable": record.get("variable"),
                    "status": record.get("status"),
                    "comparison_rule": record.get("comparison_rule"),
                    "expected_value": record.get("expected_value"),
                    "observed_value": record.get("observed_value"),
                    "observed_value_source": (
                        None
                        if record.get("observed_value") is None
                        else SOURCE_OBSERVED
                    ),
                    "observed_value_authoritative": (
                        False if record.get("observed_value") is None
                        else observed_authoritative
                    ),
                    "reason": record.get("reason"),
                }
            )
    return {
        "status": correlation.status,
        "correlation_schema_version": correlation.correlation_schema_version,
        "established_variable_count": established,
        "observation_completeness": correlation.metadata.get(
            "observation_completeness"
        ),
        "ml_evaluated": bool(correlation.metadata.get("ml_evaluated")),
        "variables": variables,
    }


def _ml_ref(ml_result: Any) -> Dict[str, Any]:
    return {
        "source": SOURCE_ML,
        "authoritative": SOURCE_AUTHORITATIVE[SOURCE_ML],
        "model_version": ml_result.model_version,
        "traffic_class": ml_result.traffic_class,
        "classification_confidence": ml_result.classification_confidence,
        "anomaly": ml_result.anomaly,
        "anomaly_score": ml_result.anomaly_score,
        "feature_schema_version": ml_result.extras.get("feature_schema_version"),
        "window_id": ml_result.extras.get("window_id"),
        "timestamp": ml_result.extras.get("timestamp"),
        "probabilities": ml_result.extras.get("probabilities"),
        "non_interference": (
            "ML output is model-derived inference evidence; it does not "
            "represent an authoritative protocol observation and never "
            "overwrites one."
        ),
    }


def audit_correlation_result(
    result: Any,
    *,
    expected: Any,
    identity: CorrelationIdentity,
    recorded_at: Optional[str] = None,
    response_proposal_ref: Optional[str] = None,
    evidence_refs: Sequence[EvidenceRef] = (),
    window_index: Optional[int] = None,
) -> List[AuditEvent]:
    """Build the audit events for one seam result (no persistence).

    ``identity`` is required: an audit record with no run/experiment identity
    cannot be joined to anything, so the recorder refuses to guess one.

    ``window_index`` is the position of the window within its run, supplied by
    :func:`audit_run`. It is left ``None`` when a caller correlates a window on
    its own; the window's own start/end timestamps are recorded regardless, so
    the index is a convenience for joining rather than the window's identity.

    Only stages that actually produced a result become events.  ``result`` is a
    :class:`correlation.ml.live_correlation.LiveCorrelationResult`; its
    ``ml_result`` may be ``None`` when inference failed, in which case an
    ``ml_failure`` event is emitted instead of an ``ml_result`` event and every
    other stage is still recorded.
    """
    window = result.window
    window_identity = CorrelationIdentity(
        dataset_run_id=identity.dataset_run_id,
        sequence=identity.sequence,
        experiment_id=identity.experiment_id,
        attempt_number=identity.attempt_number,
        window_index=window_index,
        window_start_ns=window.window_start_ns,
        window_end_ns=window.window_end_ns,
    )
    common = dict(
        identity=window_identity,
        recorded_at=recorded_at,
        evidence_refs=tuple(evidence_refs),
    )
    events = [
        AuditEvent(
            event_type=EVENT_EXPECTED_STATE,
            source=SOURCE_EXPECTED,
            authoritative=SOURCE_AUTHORITATIVE[SOURCE_EXPECTED],
            provenance={"origin": "ExpectedStateAdapter.from_plan"},
            expected_ref=_expected_ref(expected),
            **common,
        ),
        AuditEvent(
            event_type=EVENT_OBSERVED_STATE,
            source=SOURCE_OBSERVED,
            authoritative=SOURCE_AUTHORITATIVE[SOURCE_OBSERVED],
            provenance={"origin": "ebpf.ipsec_state_builder.IPsecStateBuilder"},
            observed_ref=_observed_ref(result.observed),
            **common,
        ),
        AuditEvent(
            event_type=EVENT_COMPARISON,
            source=SOURCE_COMPARISON,
            authoritative=SOURCE_AUTHORITATIVE[SOURCE_COMPARISON],
            provenance={
                "origin": "correlation.comparison.ComparisonEngine",
                "note": (
                    "Comparison is a derived judgement and is not itself "
                    "authoritative; each variable carries its own observed-side "
                    "provenance."
                ),
            },
            expected_ref=_expected_ref(expected),
            observed_ref=_observed_ref(result.observed),
            comparison=_comparison_ref(result.correlation),
            **common,
        ),
    ]

    ml_result = getattr(result, "ml_result", None)
    if ml_result is not None:
        events.append(
            AuditEvent(
                event_type=EVENT_ML_RESULT,
                source=SOURCE_ML,
                authoritative=SOURCE_AUTHORITATIVE[SOURCE_ML],
                provenance={"origin": "controller.ml_inference (committed RF)"},
                ml_ref=_ml_ref(ml_result),
                **common,
            )
        )
    else:
        events.append(
            AuditEvent(
                event_type=EVENT_ML_FAILURE,
                source=SOURCE_ML,
                authoritative=SOURCE_AUTHORITATIVE[SOURCE_ML],
                provenance={
                    "origin": "controller.ml_inference (committed RF)",
                    "failure": str(getattr(result, "ml_error", "unknown")),
                    "authoritative_path_intact": True,
                },
                **common,
            )
        )

    assessment = getattr(result, "assessment", None)
    if assessment is not None:
        events.append(
            AuditEvent(
                event_type=EVENT_RISK_ASSESSMENT,
                source=SOURCE_RISK,
                authoritative=SOURCE_AUTHORITATIVE[SOURCE_RISK],
                provenance={
                    "origin": "correlation.risk.RiskEngine",
                    "risk_engine_version": assessment.risk_engine_version,
                    "risk_policy_version": assessment.risk_policy_version,
                },
                risk_ref={
                    "severity": assessment.severity,
                    "overall_score": assessment.overall_score,
                    "finding_count": len(assessment.findings),
                },
                decision={
                    "kind": "risk_finding",
                    "executed": False,
                    "enforced": False,
                    "note": (
                        "A risk finding is a proposal/assessment. No enforcement "
                        "action was performed by this audit layer."
                    ),
                },
                **common,
            )
        )

    explanation = getattr(result, "explanation", None)
    if explanation is not None:
        events.append(
            AuditEvent(
                event_type=EVENT_EXPLANATION,
                source=SOURCE_EXPLAINABILITY,
                authoritative=SOURCE_AUTHORITATIVE[SOURCE_EXPLAINABILITY],
                provenance={
                    "origin": "correlation.xai.ExplainabilityEngine",
                    "explainability_engine_version": explanation.metadata.get(
                        "explainability_engine_version"
                    ),
                },
                explanation_ref={
                    "summary": explanation.summary,
                    "ml_explanation_count": len(explanation.ml_explanations),
                    "unknown_explanation_count": len(
                        explanation.unknown_explanations
                    ),
                    "not_applicable_explanation_count": len(
                        explanation.not_applicable_explanations
                    ),
                },
                **common,
            )
        )

    if response_proposal_ref is not None:
        events.append(
            AuditEvent(
                event_type=EVENT_RESPONSE_PROPOSAL,
                source=SOURCE_RESPONSE_RECOMMENDATION,
                authoritative=SOURCE_AUTHORITATIVE[
                    SOURCE_RESPONSE_RECOMMENDATION
                ],
                provenance={
                    "origin": "correlation.response (proposal only)",
                    "note": (
                        "Authorization and execution are recorded exclusively by "
                        "correlation/response/audit.py; this layer records a "
                        "reference so the records can be joined."
                    ),
                },
                response_proposal_ref=response_proposal_ref,
                decision={"kind": "response_proposal", "authorized": False,
                          "executed": False},
                **common,
            )
        )
    return events


def audit_run(
    run: Any,
    *,
    journal: Optional[AuditJournal] = None,
    recorded_at: Optional[str] = None,
    response_proposal_refs: Optional[Dict[str, str]] = None,
    evidence_refs: Sequence[EvidenceRef] = (),
) -> List[AuditEvent]:
    """Audit every window of a :class:`LiveCorrelationRun`, optionally persisting.

    The run's ``expected`` and ``observed`` objects are only *read*; audit
    persistence never mutates them (invariant 8).  ``recorded_at`` is forwarded
    verbatim so a replay reproduces byte-identical events.
    """
    expected = run.expected
    events: List[AuditEvent] = []
    for index, result in enumerate(run.results):
        ref = None
        if response_proposal_refs:
            ref = response_proposal_refs.get(result.window_id)
        events.extend(
            audit_correlation_result(
                result,
                expected=getattr(expected, "expected", expected),
                identity=run.identity,
                recorded_at=recorded_at,
                response_proposal_ref=ref,
                evidence_refs=evidence_refs,
                window_index=index,
            )
        )
    if journal is not None:
        journal.extend(events)
    return events
