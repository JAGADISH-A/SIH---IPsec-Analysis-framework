"""Production live controller -> correlation seam (Phase 10+).

This is the production entry point that connects the genuinely live controller
side to the genuinely implemented correlation side.  It adds no classifier, no
feature extraction, no correlation engine, no risk semantics and no XAI logic;
it only wires the existing components together in the order the architecture
requires:

    live 100 ms feature window  (controller.live_features.LiveFeatureExtractor)
        -> controller/ml_inference.py            (real committed RF artifact)
        -> correlation/ml/controller_bridge.py  (the existing boundary bridge)
        -> correlation.models.MLResult
        -> existing ComparisonEngine             (correlation.comparison)
        -> existing RiskEngine                   (correlation.risk)
        -> existing ExplainabilityEngine         (correlation.xai)

Real observed IPsec state travels the same path, but on its own terms:

    live observation events  (ebpf.xdp_window_aggregator PacketEvent shape)
        -> ebpf.ipsec_state_builder.IPsecStateBuilder   (the real state engine)
        -> correlation.models.ObservedState

Authority boundaries (all verified by tests/test_live_correlation_seam.py):

* **ML is evidence, never truth.**  The RF is a 6-class traffic-profile
  classifier.  It never sources tunnel / IKE / ESP / AH / SPI state, security
  posture or protocol observations.  ``ObservedState`` is built from real
  observations only; when no observation is available the state is empty and
  the ML verdict is still only an observation.
* **Expected state stays independent.**  It is sourced from the materialized
  plan through the existing :class:`ExpectedStateAdapter`; this module never
  derives expected state from ML, observed state, risk or XAI output.
* **Observed values are only what a passive observer can evidence.**  A passive
  non-inline observer sees that ESP/AH was observed, so ``mode`` is derived from
  ``ObservedState.tunnel_seen``.  Crypto parameters (cipher, integrity, DH
  group, PFS) are deliberately NOT supplied: the state engine refuses to infer
  them, and mirroring the expected values into the observed channel -- as the
  demo store does -- would fabricate observation.
* **Protocol comparison is untouched by ML.**  Protocol matches / mismatches /
  unknowns / not_applicable and the overall comparison status come exclusively
  from the existing ``ComparisonEngine``.  ML outcomes are attached as
  source-labeled metadata (``source="ml"``) exactly as
  :func:`correlation.ml.integration.correlate_with_ml` already does.
* **Anomaly stays DEFERRED.**  The bridge pins ``anomaly``/``anomaly_score`` to
  ``None``; ``ML_ANOMALY`` therefore reports ``NOT_APPLICABLE``.  No anomaly
  model, dataset, detector, threshold or inference path exists here.
* **SHAP stays observational.**  This module never imports ``shap`` and never
  calls ``controller.ml_inference.explain``; classification and the downstream
  risk/XAI output are byte-identical whether or not SHAP is computed.
* **Passive architecture.**  Nothing here enforces anything.  No XDP_DROP,
  XDP_TX or XDP_REDIRECT, no nftables/iptables, no strongSwan SA teardown, no
  VICI, no response/policy execution, no analyst approval, no Kafka, no Zeek
  live consumer, no dataset or model retraining.

The module is import-safe: the controller ML dependencies (numpy / sklearn /
joblib / matplotlib) are imported lazily inside the functions that need them,
matching :mod:`correlation.ml.controller_bridge`.  Importing this module costs
only the stdlib plus the already-imported correlation engines.

Run it as a one-shot JSONL stage, the same convention the live controller
stages use (``controller.live_features``, ``controller.ml_inference``,
``ebpf.xdp_window_aggregator``, ``ebpf.ipsec_state_builder``)::

    python -m correlation.ml.live_correlation \\
        --events xdp.jsonl \\
        --plan results/datasets/<run>/staging/plan.json --sequence 1 \\
        --output correlation_result.json

``--events`` accepts the XDP reader event shape (``ts``/``type``/``src``/``dst``/
``spi``/``seq``) and the TShark observation shape (``timestamp``/``source_ip``/
``destination_ip``); both normalize through ``PacketEvent.from_dict``.
"""

from __future__ import annotations

import argparse
import datetime
import json
import sys
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Union

from ebpf.ipsec_state_builder import IPsecStateBuilder
from ebpf.xdp_window_aggregator import WINDOW_SIZE_MS

from ..adapters import ExpectedStateAdapter, MaterializedExpectedState
from ..comparison import ComparisonEngine, ComparisonEngineOptions
from ..models import (
    CorrelationIdentity,
    CorrelationResult,
    ExpectedState,
    LiveFeatureWindow,
    MLResult,
    ObservedState,
)
from ..risk import RiskEngine, RiskPolicy
from ..sa_correlation import SaResolver
from ..xai import ExplainabilityEngine
from .controller_bridge import infer_controller_ml_result
from .integration import correlate_with_ml

__all__ = [
    "LiveCorrelationResult",
    "LiveCorrelationRun",
    "correlate_live_events",
    "correlate_live_window",
    "feature_windows_from_events",
    "load_rf_artifact",
    "observed_state_from_events",
    "observed_state_from_windows",
    "observed_values_from_state",
    "read_event_jsonl",
    "state_snapshot_to_dict",
    "window_timestamp",
]

#: Fixed materialization stamp: the plan is a static artifact, so the seam stays
#: deterministic and never calls a wall clock for expected state.
DEFAULT_MATERIALIZED_AT = "2026-09-20T00:00:00+00:00"

#: ``mode`` is the one comparison variable a passive observer can evidence.
#: Every other expected variable is either a configuration property (unknown to
#: a passive sensor) or a crypto parameter the state engine must never infer.
OBSERVED_MODE_TUNNEL = "tunnel"
OBSERVED_MODE_TRANSPORT = "transport"


def load_rf_artifact(model_path=None) -> Dict[str, Any]:
    """Load the committed Random Forest artifact exactly once per batch.

    ``controller.ml_inference.predict`` re-loads and re-validates the ~1 MB
    artifact on every call when ``artifact`` is omitted, which is unusable for a
    100 ms window loop.  A batch run must hoist this and pass it through, so the
    real RF is still exercised but the model is read from disk once.
    """
    from controller.evaluate_model import MODEL_PATH, load_artifact

    return load_artifact(MODEL_PATH if model_path is None else model_path)


def window_timestamp(window: LiveFeatureWindow) -> str:
    """Deterministic ISO-8601 UTC timestamp derived from the window itself.

    Using the window instead of the wall clock keeps a batch run reproducible
    (this project forbids clock reads in deterministic stages).  A caller may
    still pass an explicit ``timestamp`` to
    :func:`correlation.ml.controller_bridge.correlate_with_controller_ml`.
    """
    ns = window.window_end_ns or window.window_start_ns
    moment = datetime.datetime.fromtimestamp(
        ns / 1_000_000_000, datetime.timezone.utc
    )
    return moment.isoformat()


def state_snapshot_to_dict(snapshot: Mapping[str, Any]) -> Dict[str, Any]:
    """Translate an ``IPsecStateBuilder.snapshot()`` into ``ObservedState`` input.

    This is a *schema translation only*.  The two existing production engines
    agree on every top-level field and on every per-SPI field; they disagree on
    exactly one thing, the transition record:

    ==========================================  ==========================
    ``IPsecStateBuilder`` (ebpf)                ``TransitionObservation``
    ==========================================  ==========================
    ``{"timestamp_ns", "type", <flat payload>}  ``{"name", "timestamp_ns", "details"}``
    ==========================================  ==========================

    Rather than editing either engine -- the state engine has many consumers and
    the correlation model is the immutable observation contract -- the seam
    performs the mechanical rename and keeps every original payload key intact
    inside ``details``, so nothing is dropped, renamed away or invented.  The
    transition label is carried across verbatim (e.g. ``SPI_OBSERVED``).
    """
    translated = dict(snapshot)
    transitions: List[Dict[str, Any]] = []
    for record in snapshot.get("transitions") or ():
        record = dict(record)
        label = record.pop("type", None) or record.pop("name", None)
        if not label:
            raise ValueError(
                "state transition record carries neither 'type' nor 'name': "
                f"{record!r}"
            )
        timestamp_ns = record.pop("timestamp_ns", 0)
        transitions.append(
            {
                "name": str(label),
                "timestamp_ns": int(timestamp_ns),
                "details": record,
            }
        )
    translated["transitions"] = transitions
    return translated


def _builder(endpoints=None, active_timeout_ms=None) -> IPsecStateBuilder:
    kwargs: Dict[str, Any] = {}
    if endpoints is not None:
        kwargs["endpoints"] = dict(endpoints)
    if active_timeout_ms is not None:
        kwargs["active_timeout_ms"] = int(active_timeout_ms)
    return IPsecStateBuilder(**kwargs)


def observed_state_from_events(
    events: Iterable[Any],
    *,
    endpoints: Optional[Mapping[str, str]] = None,
    active_timeout_ms: Optional[int] = None,
) -> ObservedState:
    """Build a REAL ``ObservedState`` from live observation events.

    The authoritative state engine (:class:`~ebpf.ipsec_state_builder.IPsecStateBuilder`)
    does all the work: counters, per-SPI state (SPI, direction, first/last/highest
    sequence, sequence delta), IKE/ESP/AH activity and transitions.  This function
    only feeds it events and converts its ``snapshot()`` through the existing
    ``ObservedState.from_dict`` contract -- it invents no field and never consults
    ML output.
    """
    builder = _builder(endpoints, active_timeout_ms)
    seen = 0
    for event in events:
        if isinstance(event, Mapping):
            builder.consume_event_dict(dict(event))
        else:
            builder.consume_event(event)
        seen += 1
    if seen == 0:
        raise ValueError(
            "observed_state_from_events requires at least one observation "
            "event; refusing to fabricate an observed state"
        )
    return ObservedState.from_dict(state_snapshot_to_dict(builder.snapshot()))


def observed_state_from_windows(
    windows: Iterable[Mapping[str, Any]],
    *,
    endpoints: Optional[Mapping[str, str]] = None,
    active_timeout_ms: Optional[int] = None,
) -> ObservedState:
    """Build a REAL ``ObservedState`` from aggregated 100 ms window records.

    Windows carry aggregate counters only, so the state engine records them
    faithfully and -- by design -- refuses to fabricate SPI state from
    ``unique_esp_spi_count``.  When SPI detail is required, feed the raw events
    to :func:`observed_state_from_events` instead.
    """
    builder = _builder(endpoints, active_timeout_ms)
    seen = 0
    for window in windows:
        builder.consume_window(dict(window))
        seen += 1
    if seen == 0:
        raise ValueError(
            "observed_state_from_windows requires at least one window record; "
            "refusing to fabricate an observed state"
        )
    return ObservedState.from_dict(state_snapshot_to_dict(builder.snapshot()))


def observed_values_from_state(observed: ObservedState) -> Dict[str, Any]:
    """Observed-value channel containing only what passive observation supports.

    A non-inline observer sees ESP/AH frames, so tunnel-vs-transport is
    observable.  It cannot see the negotiated cipher, integrity algorithm, DH
    group or PFS state, and the state engine deliberately never infers them, so
    those variables are left absent and the comparison rules report them as
    unknown rather than matching a value nobody observed.

    ``mode`` is derived from ``esp_seen or ah_seen`` -- the encapsulating
    protocols themselves -- and deliberately NOT from ``tunnel_seen``: the state
    engine sets ``tunnel_seen`` for *any* observed traffic on the IPsec
    observation path, so using it would report "tunnel" for a cleartext capture
    that happened to be observed.
    """
    encapsulating = observed.esp_seen or observed.ah_seen
    return {
        "mode": OBSERVED_MODE_TUNNEL if encapsulating else OBSERVED_MODE_TRANSPORT
    }


@dataclass(frozen=True)
class LiveCorrelationResult:
    """One live 100 ms window carried all the way to a risk + XAI result.

    ``ml_result`` is ``None`` only when ``on_ml_error="record"`` was requested
    and inference actually failed; ``ml_error`` then carries the reason. The
    observed/comparison/risk/explanation results are still fully populated in
    that case, because a model failure must never erase the authoritative
    observation path.
    """

    window: LiveFeatureWindow
    correlation: CorrelationResult
    assessment: Any
    explanation: Any
    observed: ObservedState
    ml_result: Optional[MLResult] = None
    ml_error: Optional[str] = None
    observed_identity: Optional[CorrelationIdentity] = None

    @property
    def window_id(self) -> str:
        return f"{self.window.window_start_ns}-{self.window.window_end_ns}"

    @property
    def sa_identity(self) -> Optional[Dict[str, Any]]:
        """The passive SA/tunnel this result belongs to, or ``None``.

        Sourced from the window's identity, so it is present whenever the run
        was SA-scoped and absent on the single-SA path -- the same
        backward-compatible optional shape used by the stored models.
        """
        return self.window.sa_identity

    @property
    def sa_group_id(self) -> Optional[str]:
        identity = self.window.sa_identity or {}
        return identity.get("sa_group_id") or None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "window_id": self.window_id,
            "sa_group_id": self.sa_group_id,
            "sa_identity": self.sa_identity,
            "window": self.window.to_dict(),
            "ml_result": None if self.ml_result is None else self.ml_result.to_dict(),
            "ml_error": self.ml_error,
            "correlation": self.correlation.to_dict(),
            "assessment": self.assessment.to_dict(),
            "explanation": self.explanation.to_dict(),
            "observed": self.observed.to_dict(),
        }


@dataclass(frozen=True)
class LiveCorrelationRun:
    """Everything one live observation batch produced."""

    observed: ObservedState
    results: List[LiveCorrelationResult] = field(default_factory=list)
    identity: Optional[CorrelationIdentity] = None
    expected: Optional[Union[ExpectedState, MaterializedExpectedState]] = None
    #: Per-SA observed states, keyed by SA group id.  Populated only on the
    #: ``sa_scoped`` path; ``observed`` still holds the aggregate state there.
    observed_per_sa: Dict[str, ObservedState] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "passive_only": True,
            "identity": self.identity.to_dict() if self.identity else None,
            "expected_source": "materialized_plan",
            "observed": self.observed.to_dict(),
            "window_count": len(self.results),
            "observed_per_sa": {
                key: value.to_dict()
                for key, value in self.observed_per_sa.items()
            },
            "windows": [result.to_dict() for result in self.results],
        }


def correlate_live_window(
    *,
    expected: Union[ExpectedState, MaterializedExpectedState],
    observed: ObservedState,
    window: LiveFeatureWindow,
    observed_identity: CorrelationIdentity,
    artifact: Optional[Mapping[str, Any]] = None,
    timestamp: Optional[str] = None,
    identity: Optional[CorrelationIdentity] = None,
    evidence_refs: Sequence = (),
    clock_alignment=None,
    observed_values: Optional[Mapping[str, Any]] = None,
    engine: Optional[ComparisonEngine] = None,
    risk_engine: Optional[RiskEngine] = None,
    xai: Optional[ExplainabilityEngine] = None,
    on_ml_error: str = "raise",
) -> LiveCorrelationResult:
    """Carry ONE live window through the existing engines.

    The committed Random Forest is invoked exactly once per window through the
    existing bridge (:func:`infer_controller_ml_result`), which owns the strict
    controller-result validation, the ``controller result -> MLResult`` mapping
    and all model/window/timestamp/probability provenance.  The resulting
    ``MLResult`` is then handed to the existing correlation, risk and XAI
    entry points unchanged -- no semantics are reimplemented here.

    ``on_ml_error`` controls what a real inference failure does:

    ``"raise"``  (default) propagate, so a caller that requires ML sees the error.
    ``"record"`` record the failure and continue with ``ml_result=None``. The
        observed / comparison / risk / explanation results are still produced in
        full, because a broken or missing model must never erase the
        authoritative observation path or downgrade real evidence.
    """
    if on_ml_error not in ("raise", "record"):
        raise ValueError(
            f"on_ml_error must be 'raise' or 'record', got {on_ml_error!r}"
        )
    ml_result: Optional[MLResult] = None
    ml_error: Optional[str] = None
    try:
        ml_result = infer_controller_ml_result(
            window,
            artifact=artifact,
            timestamp=(
                timestamp if timestamp is not None else window_timestamp(window)
            ),
        )
    except Exception as exc:
        if on_ml_error == "raise":
            raise
        ml_result = None
        ml_error = f"{type(exc).__name__}: {exc}"
    values = (
        observed_values_from_state(observed)
        if observed_values is None
        else dict(observed_values)
    )
    correlation = correlate_with_ml(
        engine if engine is not None else ComparisonEngine(ComparisonEngineOptions()),
        expected,
        observed,
        identity=identity,
        observed_identity=observed_identity,
        ml_result=ml_result,
        evidence_refs=evidence_refs,
        clock_alignment=clock_alignment,
        observed_values=values,
    )
    assessment = (risk_engine or RiskEngine(RiskPolicy.default())).assess(
        expected=expected,
        observed=observed,
        correlation=correlation,
        ml_result=ml_result,
        evidence_refs=evidence_refs,
    )
    explanation = (xai or ExplainabilityEngine()).explain(
        assessment,
        correlation=correlation,
        ml_result=ml_result,
        evidence_refs=evidence_refs,
    )
    return LiveCorrelationResult(
        window=window,
        correlation=correlation,
        assessment=assessment,
        explanation=explanation,
        observed=observed,
        ml_result=ml_result,
        ml_error=ml_error,
        observed_identity=observed_identity,
    )


def feature_windows_from_events(
    events: Sequence[Any],
    *,
    capture_ip: Optional[str] = None,
    window_ms: int = WINDOW_SIZE_MS,
    sa_scoped: bool = False,
) -> List[LiveFeatureWindow]:
    """Real 100 ms feature windows from a live event batch.

    Delegates to ``controller.ml_inference.iter_window_records``, i.e. the same
    bucketing + ``LiveFeatureExtractor`` pair the live controller path uses, so
    features are never re-extracted on the correlation side and the 100 ms
    alignment stays owned by ``ebpf.xdp_window_aggregator.WINDOW_SIZE_MS``.

    ``sa_scoped=True`` additionally buckets by SA/tunnel, so one 100 ms window
    holding several simultaneous SAs yields one window per SA.  Each returned
    window then carries its own ``sa_identity``.
    """
    from controller.ml_inference import iter_window_records

    records = list(
        iter_window_records(
            events,
            capture_ip=capture_ip,
            window_ms=window_ms,
            sa_scoped=sa_scoped,
        )
    )
    return [LiveFeatureWindow.from_dict(record) for record in records]


def observed_states_per_sa(
    events: Sequence[Any],
    *,
    capture_ip: Optional[str] = None,
    endpoints: Optional[Mapping[str, str]] = None,
    active_timeout_ms: Optional[int] = None,
) -> Dict[str, ObservedState]:
    """Build one real ``ObservedState`` per observed SA/tunnel.

    This is what keeps SA-A's findings off SA-B's observations.  Each SA is
    fed to its *own* :class:`~ebpf.ipsec_state_builder.IPsecStateBuilder`, so
    the per-SPI counters, sequences and timestamps in an assessment describe
    that SA alone.  There is one state builder per SA -- not a second
    observation path; the same authoritative engine and the same events are
    used, merely partitioned by the identity the resolver derived from them.

    Keys are the SA group ids from :mod:`correlation.sa_correlation`; the
    ambiguous and unknown groups are included so uncertain traffic keeps its own
    state instead of being folded into a resolved SA.
    """
    resolver = SaResolver(capture_ip=capture_ip)
    resolver.index(events)
    partitions: Dict[str, List[Any]] = {}
    for event, identity in resolver.resolve_all(events):
        partitions.setdefault(identity.group_key, []).append(event)

    states: Dict[str, ObservedState] = {}
    for group_key, members in partitions.items():
        builder = _builder(endpoints, active_timeout_ms)
        for event in members:
            if isinstance(event, Mapping):
                builder.consume_event_dict(dict(event))
            else:
                builder.consume_event(event)
        if not members:
            continue
        identities = [resolver.resolve(event) for event in members]
        assignments = {}
        for identity in identities:
            if not identity.spi:
                continue
            if identity.state == "RESOLVED":
                assignments[identity.spi] = (identity.sa_id, identity.sa_group_id)
            else:
                # An AMBIGUOUS/UNKNOWN SPI still gets recorded, with the reason
                # that produced it, so unattributable traffic stays visible.
                assignments[identity.spi] = (
                    identity.state,
                    identity.reason,
                    identity.candidates,
                )
        if assignments:
            builder.assign_sa_identities(assignments)
        states[group_key] = ObservedState.from_dict(
            state_snapshot_to_dict(builder.snapshot())
        )
    return states


def read_event_jsonl(path: str) -> List[Dict[str, Any]]:
    """Read a live event JSONL stream (XDP reader or TShark observation shape)."""
    events: List[Dict[str, Any]] = []
    with open(path, "r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            events.append(json.loads(line))
    return events


def correlate_live_events(
    events: Iterable[Any],
    *,
    expected: Optional[Union[ExpectedState, MaterializedExpectedState]] = None,
    plan_path: Optional[str] = None,
    sequence: int = 1,
    materialized_at: str = DEFAULT_MATERIALIZED_AT,
    experiment_id: Optional[str] = None,
    attempt_number: Optional[int] = None,
    run_id: Optional[str] = None,
    observed: Optional[ObservedState] = None,
    capture_ip: Optional[str] = None,
    window_ms: int = WINDOW_SIZE_MS,
    endpoints: Optional[Mapping[str, str]] = None,
    active_timeout_ms: Optional[int] = None,
    artifact: Optional[Mapping[str, Any]] = None,
    model_path=None,
    evidence_refs: Sequence = (),
    clock_alignment=None,
    active_only: bool = False,
    on_ml_error: str = "raise",
    sa_scoped: bool = False,
) -> LiveCorrelationRun:
    """The full production seam: live events -> real state + real correlation.

    ``expected`` is caller-owned.  When only ``plan_path`` is supplied it is
    materialized through the existing :class:`ExpectedStateAdapter` -- the same
    independent plan/configuration source the dashboard store uses.  Expected
    state is never derived from ML, observed state, risk or XAI output.

    ``sa_scoped=False`` (the default) is the single-SA behavior, byte for byte.
    ``sa_scoped=True`` additionally buckets the 100 ms windows and the observed
    state by passively observed SA, so a gateway holding several SAs over the
    same UDP/4500 transport yields one correlated result per SA per window.
    """
    materialized: Optional[MaterializedExpectedState] = None
    if expected is None:
        if not plan_path:
            raise ValueError(
                "correlate_live_events needs either an expected state or a "
                "plan_path to materialize it from the plan/configuration"
            )
        materialized = ExpectedStateAdapter(
            materialized_at=materialized_at
        ).from_plan(
            plan_path,
            sequence=sequence,
            experiment_id=experiment_id,
            attempt_number=attempt_number,
            run_id=run_id,
        )
        expected = materialized.expected
    resolved_expected: Union[ExpectedState, MaterializedExpectedState] = (
        materialized if materialized is not None else expected
    )
    identity = (
        materialized.identity
        if materialized is not None
        else CorrelationIdentity(dataset_run_id="live", sequence=sequence)
    )

    event_list = list(events)
    if observed is None:
        observed = observed_state_from_events(
            event_list, endpoints=endpoints, active_timeout_ms=active_timeout_ms
        )

    # On the SA-scoped path each SA gets its *own* observed state, so a finding
    # about SA-A never cites SA-B's counters or sequences.  ``observed`` above
    # stays as the aggregate view for callers that want it.
    observed_per_sa: Dict[str, ObservedState] = {}
    if sa_scoped:
        observed_per_sa = observed_states_per_sa(
            event_list,
            capture_ip=capture_ip,
            endpoints=endpoints,
            active_timeout_ms=active_timeout_ms,
        )

    windows = feature_windows_from_events(
        event_list,
        capture_ip=capture_ip,
        window_ms=window_ms,
        sa_scoped=sa_scoped,
    )
    if active_only:
        windows = [w for w in windows if w.window_end_ns > w.window_start_ns]

    # Hoisted once: predict() re-reads the artifact per call otherwise.
    resolved_artifact = artifact if artifact is not None else load_rf_artifact(
        model_path
    )

    results: List[LiveCorrelationResult] = []
    for window in windows:
        sa = window.sa_identity or {}
        group_id = sa.get("sa_group_id")
        sa_id = sa.get("sa_id")
        # The observed side is stamped per window so correlation provenance
        # carries the window it was produced from.  The SA keys are part of the
        # identity, and the identity feeds the audit event_id, so SA-A and
        # SA-B records are content-distinct and can never be conflated.
        window_identity = CorrelationIdentity(
            dataset_run_id=identity.dataset_run_id,
            sequence=sequence,
            experiment_id=identity.experiment_id,
            attempt_number=identity.attempt_number,
            window_index=len(results),
            window_start_ns=window.window_start_ns,
            window_end_ns=window.window_end_ns,
            sa_group_id=group_id,
            sa_id=sa_id,
        )
        window_observed = observed_per_sa.get(group_id or "", observed)
        results.append(
            correlate_live_window(
                expected=resolved_expected,
                observed=window_observed,
                window=window,
                identity=identity,
                observed_identity=window_identity,
                artifact=resolved_artifact,
                evidence_refs=evidence_refs,
                clock_alignment=clock_alignment,
                on_ml_error=on_ml_error,
            )
        )
    return LiveCorrelationRun(
        observed=observed,
        results=results,
        identity=identity,
        expected=resolved_expected,
        observed_per_sa=observed_per_sa,
    )


def _parse_endpoints(raw: Optional[str]) -> Optional[Dict[str, str]]:
    if not raw:
        return None
    endpoints: Dict[str, str] = {}
    for item in raw.split(","):
        key, _, value = item.partition("=")
        if not value:
            raise ValueError(f"malformed --endpoints entry {item!r}; use a=IP,b=IP")
        endpoints[key.strip()] = value.strip()
    return endpoints or None


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m correlation.ml.live_correlation",
        description=(
            "Connect live controller observations and 100 ms feature windows to "
            "the existing correlation / risk / XAI engines. Passive only."
        ),
    )
    parser.add_argument(
        "--events", required=True,
        help="live observation event JSONL (XDP reader or TShark shape)",
    )
    parser.add_argument(
        "--plan", default=None,
        help="materialized plan.json supplying expected state (independent source)",
    )
    parser.add_argument(
        "--sequence", type=int, default=1,
        help="plan sequence to materialize expected state from",
    )
    parser.add_argument(
        "--run-id", default=None,
        help="dataset run id for correlation identity (default: inferred from plan path)",
    )
    parser.add_argument(
        "--experiment-id", default=None,
        help="experiment id matching the <run_id>-exp-<seq> protocol",
    )
    parser.add_argument(
        "--attempt-number", type=int, default=None,
        help="experiment attempt number for correlation identity",
    )
    parser.add_argument("--capture-ip", default=None, help="capture-side address")
    parser.add_argument(
        "--window-ms", type=int, default=WINDOW_SIZE_MS,
        help="feature window size in ms (default 100)",
    )
    parser.add_argument(
        "--endpoints", default=None,
        help="observed endpoint map, e.g. a=192.168.100.1,b=192.168.100.2",
    )
    parser.add_argument(
        "--active-timeout-ms", type=int, default=None,
        help="SPI activity timeout for the observed state engine",
    )
    parser.add_argument(
        "--model", default=None,
        help="explicit RF artifact path (default: committed model)",
    )
    parser.add_argument(
        "--on-ml-error", choices=("raise", "record"), default="raise",
        help="on a real ML inference failure: raise, or record the failure "
             "and keep the authoritative observation path intact",
    )
    parser.add_argument(
        "--active-only", action="store_true",
        help="correlate only windows that contain traffic",
    )
    parser.add_argument(
        "--output", default=None,
        help="write the result JSON here (default: stdout)",
    )
    parser.add_argument(
        "--audit-out", default=None,
        help="write the analysis-stage audit events as JSONL here "
             "(correlation.audit; never records authorization/execution)",
    )
    parser.add_argument(
        "--recorded-at", default=None,
        help="deterministic ISO stamp recorded on every audit event "
             "(default: omitted, so replays stay reproducible)",
    )
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    events = read_event_jsonl(args.events)
    run = correlate_live_events(
        events,
        plan_path=args.plan,
        sequence=args.sequence,
        experiment_id=args.experiment_id,
        attempt_number=args.attempt_number,
        run_id=args.run_id,
        capture_ip=args.capture_ip,
        window_ms=args.window_ms,
        endpoints=_parse_endpoints(args.endpoints),
        active_timeout_ms=args.active_timeout_ms,
        model_path=args.model,
        active_only=args.active_only,
        on_ml_error=args.on_ml_error,
    )
    if args.audit_out:
        from ..audit import AuditJournal, audit_run

        events = audit_run(
            run,
            journal=AuditJournal(args.audit_out),
            recorded_at=args.recorded_at,
        )
        print(
            f"[live-correlation] {len(events)} audit event(s) written to "
            f"{args.audit_out}",
            file=sys.stderr,
        )
    payload = json.dumps(run.to_dict(), indent=2, sort_keys=True, default=str)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as handle:
            handle.write(payload + "\n")
        print(
            f"[live-correlation] {len(run.results)} window(s) correlated; "
            f"written to {args.output}",
            file=sys.stderr,
        )
    else:
        print(payload)
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    raise SystemExit(main())
