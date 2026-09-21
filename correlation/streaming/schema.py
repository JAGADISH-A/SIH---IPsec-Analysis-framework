"""Versioned streaming contract (stream-schema-v1).

Defines the event-type vocabulary, the event-type -> topic mapping, and
deterministic canonical serialization helpers. The Phase-5 feature contract
(``feature_schema_version = v2``, exact 59 columns, no labels inside the
vector) remains authoritative and is never re-declared here.
"""

from typing import Any, Dict, Iterable, List, Mapping

from .models import (
    EVENT_TYPE_AUDIT,
    EVENT_TYPE_AUTHORIZATION,
    EVENT_TYPE_APPROVAL,
    EVENT_TYPE_CORRELATION,
    EVENT_TYPE_EVIDENCE,
    EVENT_TYPE_FEATURE_WINDOW,
    EVENT_TYPE_IKE,
    EVENT_TYPE_ML_RESULT,
    EVENT_TYPE_PACKET,
    EVENT_TYPE_RESPONSE_EXECUTION,
    EVENT_TYPE_RECOMMENDATION,
    EVENT_TYPE_RISK,
    EVENT_TYPE_STATE,
    EVENT_TYPE_XAI,
    EVENT_TYPE_SET,
    STREAM_SCHEMA_VERSION,
    StreamEvent,
    validate_event_type,
)

STREAM_SCHEMA_CONTRACT = {
    "schema_version": STREAM_SCHEMA_VERSION,
    "event_types": tuple(sorted(EVENT_TYPE_SET)),
    "serialization": "JSON/JSONL deterministic (sort_keys, compact separators)",
    "identity": (
        "dataset_run_id, sequence, experiment_id, attempt_number, "
        "window_index, window_start_ns, window_end_ns"
    ),
    "feature_contract": {
        "authority": "Phase-5 v2 59-feature contract (D:\\sihipsec)",
        "labels_and_provenance": "never inside the feature vector",
        "no_v1_feature_columns": True,
    },
    "pickle": "forbidden",
}

STREAM_SCHEMA_NAME = STREAM_SCHEMA_VERSION


def schema_contract() -> Dict[str, Any]:
    return dict(STREAM_SCHEMA_CONTRACT)


def validate_event(event: StreamEvent) -> None:
    if event.schema_version != STREAM_SCHEMA_VERSION:
        raise ValueError(
            f"unsupported schema_version {event.schema_version!r}; expected "
            f"{STREAM_SCHEMA_VERSION!r}"
        )
    validate_event_type(event.event_type)


def canonical_field_order() -> List[str]:
    return [
        "dataset_run_id",
        "sequence",
        "experiment_id",
        "attempt_number",
        "window_index",
        "window_start_ns",
        "window_end_ns",
        "event_type",
        "schema_version",
        "source",
        "created_at",
        "payload",
    ]


def serialize_jsonl(events: Iterable[StreamEvent]) -> str:
    return "".join(event.to_jsonl() for event in events)


def deserialize_jsonl(lines: Iterable[str]) -> List[StreamEvent]:
    return [StreamEvent.from_jsonl(line) for line in lines if line.strip()]


def default_event_type_to_topic() -> Dict[str, str]:
    return {
        EVENT_TYPE_PACKET: "ipsec.raw",
        EVENT_TYPE_IKE: "ipsec.raw",
        EVENT_TYPE_STATE: "ipsec.state",
        EVENT_TYPE_FEATURE_WINDOW: "ipsec.features",
        EVENT_TYPE_ML_RESULT: "ipsec.ml",
        EVENT_TYPE_CORRELATION: "ipsec.correlation",
        EVENT_TYPE_RISK: "ipsec.risk",
        EVENT_TYPE_XAI: "ipsec.xai",
        EVENT_TYPE_RECOMMENDATION: "ipsec.response",
        EVENT_TYPE_APPROVAL: "ipsec.response",
        EVENT_TYPE_AUTHORIZATION: "ipsec.response",
        EVENT_TYPE_RESPONSE_EXECUTION: "ipsec.response",
        EVENT_TYPE_AUDIT: "ipsec.audit",
        EVENT_TYPE_EVIDENCE: "ipsec.evidence",
    }


def topic_for_event_type(
    event_type: str, mapping: Mapping[str, str] | None = None
) -> str:
    topic_map = dict(mapping) if mapping is not None else default_event_type_to_topic()
    validate_event_type(event_type)
    if event_type not in topic_map:
        raise KeyError(f"no topic configured for event_type {event_type!r}")
    return topic_map[event_type]


def roundtrip_identity(event: StreamEvent) -> Dict[str, Any]:
    """Deterministic event identity portion (no payload)."""
    return {
        "dataset_run_id": event.dataset_run_id,
        "sequence": event.sequence,
        "experiment_id": event.experiment_id,
        "attempt_number": event.attempt_number,
        "window_index": event.window_index,
        "window_start_ns": event.window_start_ns,
        "window_end_ns": event.window_end_ns,
        "event_type": event.event_type,
    }