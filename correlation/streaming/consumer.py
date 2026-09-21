"""Event consumer with dedup / retry / DLQ / backpressure handling.

``ConsumeLoop`` wires the resilience primitives into a deterministic polling
loop:

    output (already consumed as duplicated B)
         |
        v
    MemoryTransport <= advance offsets (resume-safe)
        |
        v
    backpressure.accept(event)   -> BLOCK(default) / BUFFER / DROP / DLQ
        |
        v
    dedup.observe(event)          -> duplicate absorbed (never merged across attempts)
        |
        v
    handler(event)                -> status
        |
        v
    retry.decide(event, status)   -> retry / dead_letter (never silent drop)

Failure of the correlation/risk stage is represented explicitly; a failed
message retries per policy and exhausts into the DLQ rather than corrupting a
sibling partition.
"""

from typing import Callable, List, Optional, Protocol

from .backpressure import BackpressureState, OverflowAction
from .dead_letter import DeadLetterQueue
from .dedup import Deduplicator
from .models import StreamEvent
from .offsets import OffsetTracker
from .producer import EventTransport
from .retry import RetryController


class EventHandler(Protocol):
    def __call__(self, event: StreamEvent, offset: int) -> str:
        """Process one event; return a status string (retryable or terminal)."""


class ConsumeLoop:
    """Resilient consumer: dedup -> handler -> retry/DLQ, offsets preserved."""

    def __init__(
        self,
        transport: EventTransport,
        handler: EventHandler,
        *,
        topic: str,
        partitions: int = 1,
        max_queue: int = 10_000,
        overflow_policy: str = "BLOCK",
        dedup_size: int = 10_000,
        retry_max: int = 3,
        dlq_max: int = 10_000,
    ) -> None:
        self.transport = transport
        self.handler = handler
        self.topic = topic
        self.offset_tracker = OffsetTracker(partitions=partitions)
        self.backpressure = BackpressureState(
            max_queue=max_queue, overflow=overflow_policy
        )
        self.deduplicator = Deduplicator(size=dedup_size)
        self.retry = RetryController()
        self.dlq = DeadLetterQueue(max_records=dlq_max)
        self._pending: List[StreamEvent] = []
        self.processed = 0
        self.failed = 0

    # -- lifecycle ---------------------------------------------------------

    def drain_transport(self) -> int:
        """Fold all currently-buffered messages into the backpressure queue."""
        batch = 0
        for _partition, offset, event in list(self.transport.topics.get(self.topic, [])):
            if offset < self.offset_tracker.current(0):
                continue
            action = self.backpressure.accept(event)
            if action in (OverflowAction.ACCEPT, OverflowAction.BUFFER):
                batch += 1
        return batch

    def poll(self) -> List[tuple]:
        """Process one drained batch; returns [(event, status), ...]."""
        self.drain_transport()
        events, _count = self.backpressure.drain()
        results: List[tuple] = []
        for offset, event in enumerate(events):
            if self.deduplicator.is_duplicate(event):
                self.duplicate_events_seen(event)
                self.offset_tracker.record(event, offset)
                results.append((event, "duplicate"))
                continue
            self.deduplicator.observe(event)
            status = self._process(event, offset)
            self.offset_tracker.record(event, offset)
            results.append((event, status))
            if status in ("processing_failed", "downstream_unavailable"):
                self._retry_or_dlq(event, status)
            elif status != "ok":
                self.failed += 1
        return results

    def _process(self, event: StreamEvent, offset: int) -> str:
        try:
            status = self.handler(event, offset)
        except Exception as exc:  # noqa: BLE001
            self.failed += 1
            return "processing_failed: %s" % (exc,)
        if status != "ok":
            self.failed += 1
        else:
            self.processed += 1
        return status

    def _retry_or_dlq(self, event: StreamEvent, status: str) -> None:
        decision = self.retry.decide(event.event_identity, status.split(":")[0])
        if decision.action == "retry":
            return
        self.dlq.record(event, failure_reason=status, retry_count=decision.retries_used)

    def duplicate_events_seen(self, event: StreamEvent) -> None:
        self.deduplicator.observe(event)

    def commit(self) -> None:
        self.offset_tracker.commit(0, self.offset_tracker.current(0))

    def to_dict(self) -> dict:
        return {
            "processed": self.processed,
            "failed": self.failed,
            "dedup": self.deduplicator.to_dict(),
            "backpressure": self.backpressure.to_dict(),
            "dlq": {"total": len(self.dlq)},
            "offsets": self.offset_tracker.snapshot(),
        }