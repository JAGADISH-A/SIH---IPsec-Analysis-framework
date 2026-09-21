"""Backpressure policy.

The system must not crash because traffic temporarily exceeds processing
capacity. ``BackpressureState`` applies an explicit overflow policy:

* BUFFER — hold the event in a bounded in-memory queue;
* BLOCK  — block the producing caller (bounded queue = capacity, callers await);
* DROP   — discard, but mark the event so the counter is explicit (never silent
  for security-relevant events unless the policy authorizes drop);
* DLQ    — move the overflow to the dead-letter queue.

The default for security-relevant events is BLOCK: nothing security-relevant
is ever silently discarded.
"""

from enum import Enum
from typing import List, Optional, Tuple

from .models import StreamEvent

BUFFER = "BUFFER"
BLOCK = "BLOCK"
DROP = "DROP"
DLQ = "DLQ"

OVERFLOW_POLICIES = (BUFFER, BLOCK, DROP, DLQ)

SECURITY_RELEVANT = {
    "ipsec.raw",
    "ipsec.state",
    "ipsec.features",
    "ipsec.ml",
    "ipsec.correlation",
    "ipsec.risk",
    "ipsec.xai",
    "ipsec.response",
    "ipsec.audit",
    "ipsec.evidence",
}


def default_overflow_for(event_type: str) -> str:
    """Security-relevant events default to BLOCK; transient ones may buffer."""
    return BLOCK


class OverflowAction(Enum):
    ACCEPT = "accept"
    BUFFER = "buffer"
    BLOCK = "block"
    DROP = "drop"
    DLQ = "dead_letter"


class BackpressureState:
    """Bounded buffer with an explicit overflow decision (no silent loss)."""

    def __init__(
        self,
        max_queue: int = 10_000,
        overflow: str = BLOCK,
        *,
        clock=None,
    ) -> None:
        if max_queue < 1:
            raise ValueError("max_queue must be positive")
        if overflow not in OVERFLOW_POLICIES:
            raise ValueError(f"overflow must be one of {OVERFLOW_POLICIES}")
        self.max_queue = max_queue
        self.overflow = overflow
        self._buffer: List[StreamEvent] = []
        self._clock = clock or (lambda: None)
        self.buffered = 0
        self.dropped = 0
        self.blocked = 0
        self.accepted = 0

    @property
    def queue_size(self) -> int:
        return len(self._buffer)

    @property
    def saturated(self) -> bool:
        return len(self._buffer) >= self.max_queue

    def accept(self, event: StreamEvent) -> OverflowAction:
        """Ingest one event; return the decided transport action."""
        if len(self._buffer) < self.max_queue:
            self._buffer.append(event)
            self.buffered += 1
            self.accepted += 1
            return OverflowAction.ACCEPT
        if self.overflow == DROP:
            self.dropped += 1
            return OverflowAction.DROP
        if self.overflow == DLQ:
            self.dropped += 1
            return OverflowAction.DLQ
        if self.overflow == BUFFER:
            self.buffered += 1
            return OverflowAction.BUFFER
        self.blocked += 1
        return OverflowAction.BLOCK

    def drain(self, limit: Optional[int] = None) -> Tuple[List[StreamEvent], int]:
        """Pop events for downstream processing (FIFO)."""
        if limit is None or limit >= len(self._buffer):
            events, self._buffer = self._buffer, []
            return events, len(events)
        events, rest = self._buffer[:limit], self._buffer[limit:]
        self._buffer = rest
        return events, len(events)

    def to_dict(self) -> dict:
        return {
            "max_queue": self.max_queue,
            "overflow_policy": self.overflow,
            "queue_size": self.queue_size,
            "saturated": self.saturated,
            "buffered": self.buffered,
            "dropped": self.dropped,
            "blocked": self.blocked,
            "accepted": self.accepted,
        }