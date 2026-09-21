"""Dead-letter queue: invalid events must not crash the pipeline.

A ``DeadLetterRecord`` always preserves:

    original event (unmutated canonical dict)
    failure reason
    schema version
    source
    timestamp
    event identity
    retry count

The original event is never mutated: it is captured via its canonical dict
before any handling. Records serialize deterministically.
"""

import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .models import StreamEvent

DLQ_SCHEMA_VERSION = "stream-dlq-v1"


@dataclass(frozen=True)
class DeadLetterRecord:
    """One DLQ record preserving the original event and failure context."""

    event_identity: str
    original: Dict[str, Any]
    failure_reason: str
    schema_version: str
    source: str
    timestamp: Optional[int]
    retry_count: int

    def to_dict(self) -> Dict[str, Any]:
        return {
            "dlq_schema_version": DLQ_SCHEMA_VERSION,
            "event_identity": self.event_identity,
            "original_event": dict(self.original),
            "failure_reason": self.failure_reason,
            "schema_version": self.schema_version,
            "source": self.source,
            "timestamp": self.timestamp,
            "retry_count": self.retry_count,
        }

    def to_json(self, *, sort_keys: bool = True, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), sort_keys=sort_keys, indent=indent)

    @classmethod
    def from_event(
        cls,
        event: StreamEvent,
        failure_reason: str,
        retry_count: int,
    ) -> "DeadLetterRecord":
        return cls(
            event_identity=event.event_identity,
            original=event.to_dict(),
            failure_reason=failure_reason,
            schema_version=event.schema_version,
            source=event.source,
            timestamp=event.created_at,
            retry_count=retry_count,
        )

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "DeadLetterRecord":
        return cls(
            event_identity=data["event_identity"],
            original=dict(data["original_event"]),
            failure_reason=data["failure_reason"],
            schema_version=data["schema_version"],
            source=data["source"],
            timestamp=data.get("timestamp"),
            retry_count=int(data.get("retry_count") or 0),
        )


class DeadLetterQueue:
    """Append-only DLQ (in-memory; persists via the caller's storage)."""

    def __init__(self, max_records: int = 10_000) -> None:
        if max_records < 1:
            raise ValueError("max_records must be positive")
        self.max_records = max_records
        self._records: List[DeadLetterRecord] = []
        self._by_identity: Dict[str, int] = {}

    def __len__(self) -> int:
        return len(self._records)

    def record(
        self, event: StreamEvent, failure_reason: str, retry_count: int
    ) -> DeadLetterRecord:
        rec = DeadLetterRecord.from_event(event, failure_reason, retry_count)
        self._records.append(rec)
        self._by_identity[rec.event_identity] = self._by_identity.get(
            rec.event_identity, 0
        ) + 1
        if len(self._records) > self.max_records:
            self._records.pop(0)
        return rec

    def records(self) -> List[DeadLetterRecord]:
        return list(self._records)

    def count_for(self, event_identity: str) -> int:
        return self._by_identity.get(event_identity, 0)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "dlq_schema_version": DLQ_SCHEMA_VERSION,
            "total": len(self._records),
            "records": [rec.to_dict() for rec in self._records],
        }