"""Phase 10 — streaming contract models.

Deterministic, JSON/JSONL-compatible event model for the production streaming
layer. Every event carries the correlation identity spine plus event metadata:

    stream-schema-v1
    event_type / schema_version / source / created_at
    dataset_run_id / sequence / experiment_id / attempt_number
    window_index / window_start_ns / window_end_ns
    payload

The identity spine matches ``CorrelationIdentity`` exactly; attempt_number is
part of the identity, so repeated experiment attempts are NEVER merged.

Serialization is deterministic (``sort_keys`` + compact separators) and never
uses pickle.
"""

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

from ..models._base import JsonModel
from ..models.identity import CorrelationIdentity

STREAM_SCHEMA_VERSION = "stream-schema-v1"

# ---------------------------------------------------------------------------
# event types (explicit, versioned)
# ---------------------------------------------------------------------------

EVENT_TYPE_PACKET = "ipsec.packet"
EVENT_TYPE_IKE = "ipsec.ike"
EVENT_TYPE_STATE = "ipsec.state"
EVENT_TYPE_FEATURE_WINDOW = "feature.window"
EVENT_TYPE_ML_RESULT = "ml.result"
EVENT_TYPE_CORRELATION = "correlation.result"
EVENT_TYPE_RISK = "risk.assessment"
EVENT_TYPE_XAI = "xai.explanation"
EVENT_TYPE_RECOMMENDATION = "response.recommendation"
EVENT_TYPE_APPROVAL = "response.approval"
EVENT_TYPE_AUTHORIZATION = "response.authorization"
EVENT_TYPE_RESPONSE_EXECUTION = "response.execution"
EVENT_TYPE_AUDIT = "audit.event"
EVENT_TYPE_EVIDENCE = "evidence.reference"

EVENT_TYPES = (
    EVENT_TYPE_PACKET,
    EVENT_TYPE_IKE,
    EVENT_TYPE_STATE,
    EVENT_TYPE_FEATURE_WINDOW,
    EVENT_TYPE_ML_RESULT,
    EVENT_TYPE_CORRELATION,
    EVENT_TYPE_RISK,
    EVENT_TYPE_XAI,
    EVENT_TYPE_RECOMMENDATION,
    EVENT_TYPE_APPROVAL,
    EVENT_TYPE_AUTHORIZATION,
    EVENT_TYPE_RESPONSE_EXECUTION,
    EVENT_TYPE_AUDIT,
    EVENT_TYPE_EVIDENCE,
)

EVENT_TYPE_SET = frozenset(EVENT_TYPES)


def validate_event_type(value: Any) -> str:
    if value not in EVENT_TYPE_SET:
        raise ValueError(
            f"event_type must be one of the stream-schema-v1 event types, got "
            f"{value!r}"
        )
    return value


# ---------------------------------------------------------------------------
# event identity
# ---------------------------------------------------------------------------


def _int_field(name: str, value: Any, *, minimum: Optional[int] = 0) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError(f"{name} must be an integer")
    if minimum is not None and value < minimum:
        raise ValueError(f"{name} must be >= {minimum}, got {value}")
    return value


@dataclass(frozen=True)
class StreamEvent(JsonModel):
    """One canonical streaming event (immutable, deterministic)."""

    dataset_run_id: str
    sequence: int
    experiment_id: str
    attempt_number: int
    event_type: str
    schema_version: str = STREAM_SCHEMA_VERSION
    source: str = ""
    created_at: Optional[int] = None
    window_index: Optional[int] = None
    window_start_ns: Optional[int] = None
    window_end_ns: Optional[int] = None
    payload: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.dataset_run_id, str) or not self.dataset_run_id.strip():
            raise ValueError("dataset_run_id must be a non-empty string")
        if not isinstance(self.experiment_id, str) or not self.experiment_id.strip():
            raise ValueError("experiment_id must be a non-empty string")
        if self.schema_version != STREAM_SCHEMA_VERSION:
            raise ValueError(
                f"schema_version must be {STREAM_SCHEMA_VERSION!r}, got "
                f"{self.schema_version!r}"
            )
        validate_event_type(self.event_type)
        _int_field("sequence", self.sequence, minimum=1)
        _int_field("attempt_number", self.attempt_number, minimum=1)
        if self.window_index is not None:
            _int_field("window_index", self.window_index)
        if self.window_start_ns is not None:
            _int_field("window_start_ns", self.window_start_ns)
        if self.window_end_ns is not None:
            _int_field("window_end_ns", self.window_end_ns)
        if self.window_end_ns is not None and self.window_start_ns is None:
            raise ValueError("window_end_ns requires window_start_ns")
        if (
            self.window_start_ns is not None
            and self.window_end_ns is not None
            and self.window_end_ns < self.window_start_ns
        ):
            raise ValueError("window_end_ns must be >= window_start_ns")
        if self.created_at is not None:
            _int_field("created_at", self.created_at)
        if not isinstance(self.source, str):
            raise ValueError("source must be a string")
        if not isinstance(self.payload, dict):
            raise ValueError("payload must be a dict")

    # -- identity helpers ---------------------------------------------------

    def correlation_identity(self) -> CorrelationIdentity:
        return CorrelationIdentity(
            dataset_run_id=self.dataset_run_id,
            sequence=self.sequence,
            experiment_id=self.experiment_id,
            attempt_number=self.attempt_number,
            window_index=self.window_index,
            window_start_ns=self.window_start_ns,
            window_end_ns=self.window_end_ns,
        )

    @classmethod
    def from_identity(
        cls,
        identity: CorrelationIdentity,
        event_type: str,
        *,
        payload: Optional[Dict[str, Any]] = None,
        source: str = "",
        created_at: Optional[int] = None,
        schema_version: str = STREAM_SCHEMA_VERSION,
    ) -> "StreamEvent":
        return cls(
            dataset_run_id=identity.dataset_run_id,
            sequence=identity.sequence,
            experiment_id=identity.experiment_id,
            attempt_number=identity.attempt_number,
            event_type=event_type,
            schema_version=schema_version,
            source=source,
            created_at=created_at,
            window_index=identity.window_index,
            window_start_ns=identity.window_start_ns,
            window_end_ns=identity.window_end_ns,
            payload=dict(payload or {}),
        )

    # -- deterministic serialization ---------------------------------------

    def canonical(self) -> str:
        return json.dumps(
            self.to_dict(), sort_keys=True, separators=(",", ":")
        )

    def to_jsonl(self) -> str:
        return self.canonical() + "\n"

    @property
    def event_identity(self) -> str:
        """Deterministic deduplication / event identity (no UUID)."""
        raw = self.canonical().encode("utf-8")
        return hashlib.sha256(raw).hexdigest()

    @classmethod
    def from_jsonl(cls, line: str) -> "StreamEvent":
        return cls.from_dict(json.loads(line))

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "StreamEvent":
        return cls(
            dataset_run_id=data["dataset_run_id"],
            sequence=data["sequence"],
            experiment_id=data["experiment_id"],
            attempt_number=data["attempt_number"],
            event_type=data["event_type"],
            schema_version=data.get("schema_version", STREAM_SCHEMA_VERSION),
            source=data.get("source") or "",
            created_at=data.get("created_at"),
            window_index=data.get("window_index"),
            window_start_ns=data.get("window_start_ns"),
            window_end_ns=data.get("window_end_ns"),
            payload=dict(data.get("payload") or {}),
        )


def make_payload_event(
    identity: CorrelationIdentity,
    event_type: str,
    payload: Dict[str, Any],
    *,
    source: str,
    created_at: Optional[int],
) -> StreamEvent:
    return StreamEvent.from_identity(
        identity, event_type, payload=payload, source=source, created_at=created_at
    )