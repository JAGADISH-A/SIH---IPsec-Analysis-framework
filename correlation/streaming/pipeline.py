"""Continuous correlation pipeline (Phase 10).

Reuses the authoritative Phase 4-7 + Phase 9 engines without modification:

    WindowRecord
        -> ObservedStateBuilder  (deterministic, window aggregate only)
        -> feature window        (authoritative extractor via topology, or a
                                  clearly-labelled TEST_DOUBLE builder)
        -> MLInferenceProvider   (unavailable / real model / test double)
        -> ComparisonEngine      (Phase 4)
        -> RiskEngine            (Phase 6; consumes the authoritative
                                  security_posture, never recomputes it)
        -> ExplainabilityEngine  (Phase 7)
        -> ResponseEngine.plan   (Phase 9; recommendation events only --
                                  NO execution happens here)

The pipeline NEVER executes network actions. Execution is the Phase 10
``correlation.execution`` gateway's remit, gated by approval + authorization.

Determinism: the pipeline is fully deterministic given the injected clock and
the inputs; no ``now()``/``random``/network calls.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union

from ..comparison import ComparisonEngine, ComparisonEngineOptions
from ..models import (
    CorrelationIdentity,
    CorrelationResult,
    EvidenceRef,
    ExpectedState,
    LiveFeatureWindow,
    MLResult,
    ObservedState,
    SpiObservation,
)
from ..response.engine import ResponseEngine
from ..risk.engine import RiskEngine
from ..risk.models import RiskAssessment
from ..xai.engine import ExplainabilityEngine
from ..xai.models import ExplainabilityResult
from .ml_provider import (
    MLInferenceProvider,
    MLProviderResult,
    TestDoubleWindowBuilder,
)
from .models import (
    EVENT_TYPE_CORRELATION,
    EVENT_TYPE_RISK,
    EVENT_TYPE_XAI,
    EVENT_TYPE_RECOMMENDATION,
    StreamEvent,
)
from .windowing import WindowRecord


def _endpoints_default() -> Dict[str, str]:
    return {"a": "192.0.2.1", "b": "192.0.2.2"}


@dataclass(frozen=True)
class ObservedStateBuilder:
    """Deterministic WindowRecord -> ObservedState (no crypto inference)."""

    endpoints: Dict[str, str] = field(default_factory=_endpoints_default)

    def from_record(self, record: WindowRecord, ts_now_ns: Optional[int] = None) -> ObservedState:
        spis: List[SpiObservation] = []
        per_spi: Dict[Any, dict] = {}
        for event in record.events:
            spi = event.get("spi")
            if spi is None:
                continue
            entry = per_spi.setdefault(
                spi, {"count": 0, "first_seq": None, "last_seq": None,
                      "direction": event.get("direction")}
            )
            entry["count"] += 1
            seq = event.get("seq")
            if seq is not None:
                if entry["first_seq"] is None:
                    entry["first_seq"] = seq
                entry["last_seq"] = seq
        first_seen = record.window_start_ns
        for spi, entry in sorted(per_spi.items(), key=lambda kv: str(kv[0])):
            spis.append(
                SpiObservation(
                    spi=spi,
                    direction=entry["direction"],
                    active=True,
                    first_seen_ns=first_seen,
                    last_seen_ns=record.window_end_ns if record.window_end_ns else first_seen,
                    packet_count=entry["count"],
                    first_sequence=entry["first_seq"],
                    last_sequence=entry["last_seq"],
                    highest_sequence=entry["last_seq"],
                    sequence_delta=(
                        (entry["last_seq"] - entry["first_seq"]) % (1 << 32)
                        if entry["first_seq"] is not None and entry["last_seq"] is not None
                        else None
                    ),
                )
            )
        timestamp_ns = ts_now_ns if ts_now_ns is not None else (
            record.window_end_ns if record.window_end_ns else record.window_start_ns
        )
        return ObservedState(
            timestamp_ns=timestamp_ns,
            endpoints=dict(self.endpoints),
            tunnel_seen=record.esp_packets > 0 or record.ah_packets > 0,
            active=record.total_packets > 0,
            packets_seen=record.total_packets,
            bytes_seen=record.bytes_seen,
            packets_a_to_b=record.packets_a_to_b,
            packets_b_to_a=record.packets_b_to_a,
            bytes_a_to_b=record.bytes_a_to_b,
            bytes_b_to_a=record.bytes_b_to_a,
            ike_seen=record.ike_packets > 0,
            ike_nat_t_seen=record.ike_nat_t_packets > 0,
            esp_seen=record.esp_packets > 0,
            ah_seen=record.ah_packets > 0,
            spis=spis,
            transitions=[],
        )


@dataclass(frozen=True)
class PipelineResult:
    """Everything one window produced (identity-stamped)."""

    identity: CorrelationIdentity
    observed: ObservedState
    feature_window: Optional[LiveFeatureWindow]
    ml: Optional[MLProviderResult]
    correlation: CorrelationResult
    assessment: Optional[RiskAssessment]
    explanation: Optional[ExplainabilityResult]
    recommendations: Tuple[Any, ...] = ()

    def to_events(self, source: str, created_at: Optional[int] = None) -> List[StreamEvent]:
        events: List[StreamEvent] = []
        events.append(
            StreamEvent.from_identity(
                self.identity,
                EVENT_TYPE_CORRELATION,
                payload=self.correlation.to_dict(),
                source=source,
                created_at=created_at,
            )
        )
        if self.assessment is not None:
            events.append(
                StreamEvent.from_identity(
                    self.identity,
                    EVENT_TYPE_RISK,
                    payload=self.assessment.to_dict(),
                    source=source,
                    created_at=created_at,
                )
            )
        if self.explanation is not None:
            events.append(
                StreamEvent.from_identity(
                    self.identity,
                    EVENT_TYPE_XAI,
                    payload=self.explanation.to_dict(),
                    source=source,
                    created_at=created_at,
                )
            )
        for rec in self.recommendations:
            events.append(
                StreamEvent.from_identity(
                    self.identity,
                    EVENT_TYPE_RECOMMENDATION,
                    payload=rec.to_dict(),
                    source=source,
                    created_at=created_at,
                )
            )
        return events


@dataclass
class ContinuousPipeline:
    """Continuous correlation pipeline (windows in -> stream events out)."""

    expected: Union[ExpectedState, Any]
    identity: CorrelationIdentity
    comparison: Optional[ComparisonEngine] = None
    risk: Optional[RiskEngine] = None
    xai: Optional[ExplainabilityEngine] = None
    ml: Optional[MLInferenceProvider] = None
    window_builder: Optional[TestDoubleWindowBuilder] = None
    response: Optional[ResponseEngine] = None
    observed_builder: Optional[ObservedStateBuilder] = None
    source: str = "correlation_pipeline"
    clock: Any = None

    def __post_init__(self) -> None:
        from ..comparison import ComparisonEngine as _CE

        self.comparison = self.comparison or _CE(ComparisonEngineOptions())
        self.risk = self.risk or RiskEngine()
        self.xai = self.xai or ExplainabilityEngine()
        self.observed_builder = self.observed_builder or ObservedStateBuilder()

    def _now(self) -> Optional[int]:
        if self.clock is None:
            return None
        value = self.clock()
        return None if value is None else int(value)

    def _window_identity(self, record: WindowRecord) -> CorrelationIdentity:
        return CorrelationIdentity(
            dataset_run_id=self.identity.dataset_run_id,
            sequence=self.identity.sequence,
            experiment_id=self.identity.experiment_id,
            attempt_number=self.identity.attempt_number,
            window_index=record.window_index,
            window_start_ns=record.window_start_ns,
            window_end_ns=record.window_end_ns,
        )

    def process(self, record: WindowRecord, *, created_at: Optional[int] = None) -> PipelineResult:
        identity = self._window_identity(record)
        observed = self.observed_builder.from_record(record, ts_now_ns=created_at)
        feature_window: Optional[LiveFeatureWindow] = None
        ml: Optional[MLProviderResult] = None
        if self.window_builder is not None and hasattr(record, "events"):
            feature_window = self.window_builder.build(record)
        if self.ml is not None and feature_window is not None:
            ml = self.ml.infer(feature_window)
        ml_result: Optional[MLResult] = None
        if ml is not None and ml.status == "completed" and ml.ml_result is not None:
            ml_result = ml.ml_result

        correlation = self.comparison.compare(
            self.expected,
            observed,
            identity=identity,
            observed_identity=identity,
            live_features=feature_window,
            ml_result=ml_result,
            evidence_refs=(),
        )
        assessment: Optional[RiskAssessment] = None
        if self.risk is not None:
            assessment = self.risk.assess(
                self.expected,
                observed,
                correlation=correlation,
                ml_result=ml_result,
                evidence_refs=(),
            )
        explanation: Optional[ExplainabilityResult] = None
        if self.xai is not None and assessment is not None:
            explanation = self.xai.explain(
                assessment, correlation=correlation, ml_result=ml_result
            )

        recommendations: Tuple[Any, ...] = ()
        if self.response is not None and assessment is not None:
            plan = self.response.plan(
                assessment,
                xai=explanation,
                correlation=correlation,
                ml_result=ml_result,
                evidence_refs=(),
            )
            recommendations = tuple(plan.recommendations)

        return PipelineResult(
            identity=identity,
            observed=observed,
            feature_window=feature_window,
            ml=ml,
            correlation=correlation,
            assessment=assessment,
            explanation=explanation,
            recommendations=recommendations,
        )

    def process_events(self, record: WindowRecord) -> List[StreamEvent]:
        result = self.process(record)
        return result.to_events(self.source, created_at=self._now())