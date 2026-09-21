"""Live ML provider bridge (Phase 10).

Bridges a ``feature.window`` stream event into Phase 5 inference
(``correlation/ml/inference.MLInferencePipeline``) and emits a ``ml.result``
stream event. Explicit provider modes keep the integration honest:

    UNAVAILABLE   no trained model is available -> ``ml.result`` status
                  ``unrequested`` is emitted with the reason; never a fabricated
                  verdict, never a fabricated confidence
    REAL_MODEL    a real Phase-5-validated model artifact (inference maps
                  1:1 to ``run_ml_inference``)
    TEST_DOUBLE   a clearly-labelled deterministic test double (used only by
                  tests); carries ``test_double: true`` provenance and NEVER
                  claims accuracy/precision/recall/F1

Model outputs NEVER translate into blocking actions here; the ML layer stays a
pure classification/advisory consumer and congestion input for the executors'
governed supply chain.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, Optional, Tuple

from ..ml.errors import MLIntegrationError
from ..ml.feature_contract import canonical_feature_names, normalize_feature_values
from ..ml.inference import MLInferencePipeline
from ..ml.model_metadata import ModelMetadata
from ..models import ALLOWED_TRAFFIC_PROFILES, LiveFeatureWindow, MLResult
from .models import (
    EVENT_TYPE_ML_RESULT,
    StreamEvent,
)

MODE_UNAVAILABLE = "unavailable"
MODE_REAL_MODEL = "real_model"
MODE_TEST_DOUBLE = "test_double"

STATUS_UNREQUESTED = "unrequested"
STATUS_COMPLETED = "completed"
STATUS_FAILED = "failed"


@dataclass(frozen=True)
class MLProviderResult:
    status: str
    ml_result: Optional[MLResult] = None
    error: Optional[str] = None
    latency_ns: Optional[int] = None
    extras: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status,
            "ml_result": self.ml_result.to_dict() if self.ml_result else None,
            "error": self.error,
            "latency_ns": self.latency_ns,
            "extras": dict(self.extras),
        }


@dataclass(frozen=True)
class TestDoubleClassifierModel:
    """DETERMINISTIC TEST-DOUBLE model (tests only). No accuracy claimed.

    This is NOT a trained model and NEVER claims accuracy/precision/recall/F1.
    It exists so the live path (and integration tests) exercise the exact
    Phase-5 adapter interface (``predict`` + ``ModelMetadata``) with a fixed,
    reproducible label derived from a stable hash of the feature vector sum.
    """

    metadata: ModelMetadata = field(default_factory=lambda: ModelMetadata.from_values(
        model_version="test-double-v0",
        class_labels=ALLOWED_TRAFFIC_PROFILES,
    ))

    def supports_probability(self) -> bool:
        return False

    def predict(self, vector) -> str:
        total = 0
        for value in vector:
            total += float(value)
        index = int(round(total)) % len(ALLOWED_TRAFFIC_PROFILES)
        return ALLOWED_TRAFFIC_PROFILES[index]

    def predict_proba(self, vector) -> dict:
        return {label: 0.0 for label in ALLOWED_TRAFFIC_PROFILES}

    def supports_anomaly(self) -> bool:
        return False

    def score_anomaly(self, vector) -> float:
        return 0.0


def _clock_ns(clock) -> int:
    if clock is None:
        return 0
    return clock()


@dataclass
class MLInferenceProvider:
    """Continuous inference provider feeding the streaming pipeline."""

    model: Any = None
    mode: Optional[str] = None
    source: str = "ml_provider"
    clock: Any = None

    def __post_init__(self) -> None:
        if self.mode is None:
            self.mode = MODE_REAL_MODEL if self.model is not None else MODE_UNAVAILABLE
        if self.mode not in (MODE_UNAVAILABLE, MODE_REAL_MODEL, MODE_TEST_DOUBLE):
            raise ValueError(f"unsupported provider mode: {self.mode!r}")
        if self.mode == MODE_REAL_MODEL and self.model is None:
            raise ValueError(
                "mode=real_model requires a model; use unavailable otherwise"
            )
        self._pipeline = None
        if self.mode != MODE_UNAVAILABLE:
            self._pipeline = MLInferencePipeline(self.model)

    @property
    def availability(self) -> str:
        return self.mode

    def infer(self, window: LiveFeatureWindow) -> MLProviderResult:
        if self.mode == MODE_UNAVAILABLE:
            return MLProviderResult(
                status=STATUS_UNREQUESTED,
                error=(
                    "no trained model available; ml.result is intentionally "
                    "unproduced (integration must treat ML as unavailable)"
                ),
                extras={
                    "source": self.source,
                    "provider_mode": self.mode,
                    "reason": "model_unavailable",
                },
                latency_ns=None,
            )
        started = _clock_ns(self.clock)
        try:
            result = self._pipeline.run(window)
        except MLIntegrationError as exc:
            return MLProviderResult(
                status=STATUS_FAILED,
                error=str(exc),
                extras={
                    "source": self.source,
                    "provider_mode": self.mode,
                },
                latency_ns=_clock_ns(self.clock) - started,
            )
        extras = {
            "source": self.source,
            "provider_mode": self.mode,
        }
        if self.mode == MODE_TEST_DOUBLE:
            extras["test_double"] = True
            extras[
                "disclaimer"
            ] = "test double; no accuracy/precision/recall/F1 metrics claimed"
        return MLProviderResult(
            status=STATUS_COMPLETED,
            ml_result=result,
            extras=extras,
            latency_ns=_clock_ns(self.clock) - started,
        )

    def to_stream_event(
        self,
        window: LiveFeatureWindow,
        result: MLProviderResult,
        identity,
        *,
        source_override: Optional[str] = None,
    ) -> Optional[StreamEvent]:
        payload = result.to_dict()
        payload["window_start_ns"] = window.window_start_ns
        payload["window_end_ns"] = window.window_end_ns
        payload["feature_schema_version"] = getattr(window, "feature_schema_version", None)
        return StreamEvent.from_identity(
            identity,
            EVENT_TYPE_ML_RESULT,
            payload=payload,
            source=source_override or self.source,
        )


class TestDoubleWindowBuilder:
    """DETERMINISTIC TEST-DOUBLE window -> feature builder (tests only).

    Rebuilds the 59 canonical v2 features from a ``WindowRecord`` aggregate
    using a simplified, honest computation (real packet sizes / timestamps /
    counts / IKE counters from the folded events). It is labelled
    ``TEST_DOUBLE`` and must NEVER be used as the production feature supplier;
    production features come from the authoritative extractor
    (``D:\\sihipsec\\controller\\live_features.py``) via ``feature.window``
    events.
    """

    def __init__(self, window_ns: int = 100_000_000) -> None:
        self.window_ns = window_ns
        self.label = "TEST_DOUBLE"

    def build(self, record) -> LiveFeatureWindow:
        events = record.events
        lengths = [int(e.get("length") or 0) for e in events]
        sizes = sorted(lengths)
        total = record.total_packets
        size_count = len(sizes)
        mean_size = sum(sizes) / size_count if size_count else 0.0
        variants = sorted(set(sizes))
        quantiles = self._quantiles(sizes)

        durations = []
        prev = None
        for e in events:
            ts = e.get("ts_ns")
            if isinstance(ts, (int, float)) and prev is not None:
                durations.append(ts - prev)
            prev = ts
        mean_iat = sum(durations) / len(durations) if durations else 0.0
        variance = (
            sum((d - mean_iat) ** 2 for d in durations) / len(durations)
            if durations
            else 0.0
        )
        small = sum(1 for s in sizes if 0 < s <= 128)
        large = sum(1 for s in sizes if s >= 1024)

        features = {
            "packet_count": total,
            "total_bytes": record.bytes_seen,
            "mean_packet_size": mean_size,
            "packet_size_std": self._std(sizes, mean_size),
            "min_packet_size": sizes[0] if sizes else 0,
            "max_packet_size": sizes[-1] if sizes else 0,
            "packet_size_p10": quantiles[0],
            "packet_size_p50": quantiles[1],
            "packet_size_p90": quantiles[2],
            "packet_size_p95": quantiles[3],
            "packet_size_p99": quantiles[4],
            "unique_packet_size_count": len(variants),
            "packet_size_entropy": self._entropy(sizes),
            "small_packet_ratio": small / total if total else 0.0,
            "large_packet_ratio": large / total if total else 0.0,
            "mean_inter_arrival_time": mean_iat,
            "inter_arrival_time_std": variance ** 0.5,
            "min_inter_arrival_time": min(durations) if durations else 0,
            "max_inter_arrival_time": max(durations) if durations else 0,
            "packets_per_second": (total * 1e9 / self.window_ns) if self.window_ns else 0.0,
            "bytes_per_second": (record.bytes_seen * 1e9 / self.window_ns) if self.window_ns else 0.0,
            "flow_duration": self.window_ns,
            "outbound_packet_count": record.packets_a_to_b,
            "inbound_packet_count": record.packets_b_to_a,
            "outbound_bytes": record.bytes_a_to_b,
            "inbound_bytes": record.bytes_b_to_a,
            "outbound_packet_ratio": record.packets_a_to_b / total if total else 0.0,
            "inbound_packet_ratio": record.packets_b_to_a / total if total else 0.0,
            "outbound_byte_ratio": record.bytes_a_to_b / record.bytes_seen if record.bytes_seen else 0.0,
            "inbound_byte_ratio": record.bytes_b_to_a / record.bytes_seen if record.bytes_seen else 0.0,
            "outbound_mean_packet_size": record.bytes_a_to_b / record.packets_a_to_b if record.packets_a_to_b else 0.0,
            "inbound_mean_packet_size": record.bytes_b_to_a / record.packets_b_to_a if record.packets_b_to_a else 0.0,
            "outbound_packets_per_second": (record.packets_a_to_b * 1e9 / self.window_ns) if self.window_ns else 0.0,
            "inbound_packets_per_second": (record.packets_b_to_a * 1e9 / self.window_ns) if self.window_ns else 0.0,
            "outbound_packet_size_p10": 0.0,
            "outbound_packet_size_p50": 0.0,
            "outbound_packet_size_p90": 0.0,
            "outbound_packet_size_p95": 0.0,
            "outbound_packet_size_p99": 0.0,
            "inbound_packet_size_p10": 0.0,
            "inbound_packet_size_p50": 0.0,
            "inbound_packet_size_p90": 0.0,
            "inbound_packet_size_p95": 0.0,
            "inbound_packet_size_p99": 0.0,
            "burst_count": self._bursts(events, 100_000_000),
            "mean_burst_packets": 0.0,
            "mean_burst_duration": 0.0,
            "burst_packet_ratio": 0.0,
            "burst_count_10ms": self._bursts(events, 10_000_000),
            "mean_burst_packets_10ms": 0.0,
            "burst_count_50ms": self._bursts(events, 50_000_000),
            "mean_burst_packets_50ms": 0.0,
            "burst_count_200ms": self._bursts(events, 200_000_000),
            "mean_burst_packets_200ms": 0.0,
            "ike_packet_count": record.ike_packets + record.ike_nat_t_packets,
            "ike_datagram_bytes": 0,  # datagram length not tracked at window level
            "ike_min_packet_size": 0,
            "ike_max_packet_size": 0,
            "ike_mean_packet_size": 0.0,
        }
        normalize_feature_values(features)
        return LiveFeatureWindow(
            feature_schema_version="v2",
            window_start_ns=record.window_start_ns,
            window_end_ns=record.window_end_ns,
            features=features,
        )

    @staticmethod
    def _quantiles(sizes: list) -> list:
        if not sizes:
            return [0.0, 0.0, 0.0, 0.0, 0.0]
        n = len(sizes)
        out = []
        for p in (0.1, 0.5, 0.9, 0.95, 0.99):
            idx = int((n - 1) * p)
            out.append(float(sizes[idx]))
        return out

    @staticmethod
    def _std(values: list, mean: float) -> float:
        return (sum((v - mean) ** 2 for v in values) / len(values)) ** 0.5 if values else 0.0

    @staticmethod
    def _entropy(sizes: list) -> float:
        if not sizes:
            return 0.0
        from collections import Counter

        return _shannon(Counter(sizes), len(sizes))

    @staticmethod
    def _bursts(events: list, span_ns: int) -> int:
        if not events:
            return 0
        bursts = 1
        prev = events[0].get("ts_ns")
        for e in events[1:]:
            ts = e.get("ts_ns")
            if isinstance(prev, (int, float)) and isinstance(ts, (int, float)):
                if ts - prev > span_ns:
                    bursts += 1
            prev = ts
        return bursts


def _shannon(counts, n: int) -> float:
    import math

    return -sum((c / n) * math.log2(c / n) for c in counts.values()) if n else 0.0