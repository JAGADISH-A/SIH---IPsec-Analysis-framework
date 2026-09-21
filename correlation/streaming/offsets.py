"""Offset tracking for consumer restarts.

``OffsetTracker`` records the last committed offset per partition so a
consumer restart can resume exactly where it left off (at-least-once). A
restart re-delivers the last batch (consumer group rebalance semantics) — the
deduplicator absorbs the duplicates; different attempts are never merged
because partition keys isolate attempts.
"""

from dataclasses import dataclass, field
from typing import Dict, Optional

from .partitioning import partition_for


@dataclass
class OffsetTracker:
    """Explicit per-partition offset bookkeeping (resume-safe)."""

    partitions: int = 1
    _offsets: Dict[int, int] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.partitions, int) or self.partitions < 1:
            raise ValueError("partitions must be a positive integer")

    def partition_index(self, event) -> int:
        return partition_for(event, self.partitions)

    def current(self, partition: int) -> int:
        return self._offsets.get(partition, 0)

    def next_offset(self, partition: int) -> int:
        return self.current(partition) + 1

    def commit(self, partition: int, offset: int) -> None:
        if partition not in self._offsets or offset > self._offsets[partition]:
            self._offsets[partition] = offset

    def record(self, event, offset: int) -> int:
        partition = self.partition_index(event)
        self.commit(partition, offset)
        return partition

    def snapshot(self) -> Dict[str, Dict[str, int]]:
        return {
            "partitions": self.partitions,
            "offsets": {str(p): o for p, o in sorted(self._offsets.items())},
        }

    def lag_batch(self, assigned: Dict[int, int]) -> Dict[str, int]:
        """Per-partition lag given the transport's high-water mark."""
        return {
            str(p): max(0, high - self.current(p))
            for p, high in sorted(assigned.items())
        }