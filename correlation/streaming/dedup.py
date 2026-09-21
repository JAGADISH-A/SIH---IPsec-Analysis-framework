"""Deterministic, attempt-aware duplicate detection.

Kafka consumers must tolerate duplicates, retries, restarts and repeated
experiment attempts. This module implements a bounded, deterministic seen-set:

* the dedup key is the event's ``event_identity`` (SHA-256 of the canonical
  JSON, which includes the attempt identity);
* two copies of the SAME message collapse to one;
* two different attempts (different ``attempt_number``) NEVER collapse — the
  key differs, so attempts are never silently merged;
* the registry is size-bounded (LRU-style eviction) so memory cannot grow
  without bound.

No UUIDs, no current-time dependence in the key.
"""

from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Dict, Optional

from .models import StreamEvent


@dataclass
class Deduplicator:
    """Bounded set of seen event identities."""

    size: int = 10_000
    _seen: OrderedDict = field(default_factory=OrderedDict)
    _duplicates_seen: Dict[str, int] = field(default_factory=dict)
    duplicate_count: int = 0
    admitted_count: int = 0

    def _key_for(self, event: StreamEvent) -> str:
        return event.event_identity

    def is_duplicate(self, event: StreamEvent) -> bool:
        return self._key_for(event) in self._seen

    def observe(self, event: StreamEvent) -> bool:
        """Record the event; returns True when it is a duplicate."""
        key = self._key_for(event)
        if key in self._seen:
            self.duplicate_count += 1
            self._duplicates_seen[key] = self._duplicates_seen.get(key, 0) + 1
            return True
        self._seen[key] = True
        while len(self._seen) > self.size:
            self._seen.popitem(last=False)
        self.admitted_count += 1
        return False

    def reset(self) -> None:
        self._seen.clear()
        self._duplicates_seen.clear()
        self.duplicate_count = 0
        self.admitted_count = 0

    def to_dict(self) -> dict:
        return {
            "size": self.size,
            "seen_unique": len(self._seen),
            "admitted_count": self.admitted_count,
            "duplicate_count": self.duplicate_count,
        }


def make_dedup_key(event: StreamEvent) -> str:
    return event.event_identity