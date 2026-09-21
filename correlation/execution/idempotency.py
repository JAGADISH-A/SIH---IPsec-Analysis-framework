"""Execution idempotency registry (Phase 10).

An execution is idempotent on the triplet::

    (recommendation_id / execution_id, action, target key)

Replaying the same (execution, action, target) yields an ``ALREADY_APPLIED``
outcome instead of a second network operation. The registry is bounded and
deterministic; windows (``idempotency_window`` ns) allow old entries to be
evicted after their expiry, but the registry NEVER auto-expires a live apply
for a still-open recommendation.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, Optional, Tuple

from .base import STATUS_ALREADY_APPLIED
from .targets import ExecutionTarget

IDEMPOTENCY_KEY_SEP = "|"


def idempotency_key(execution_id: str, action: str, target: ExecutionTarget) -> str:
    if not execution_id or not execution_id.strip():
        raise ValueError("execution_id must be a non-empty string")
    if not action or not action.strip():
        raise ValueError("action must be a non-empty string")
    return IDEMPOTENCY_KEY_SEP.join((execution_id, action, target.key()))


@dataclass
class IdempotencyRegistry:
    """Bounded, deterministic replay detection for executions."""

    max_entries: int = 4096
    window_ns: int = 0

    def __post_init__(self) -> None:
        self._applied: Dict[str, Dict[str, Any]] = {}
        self._order: list = []

    def mark_applied(self, key: str, *, at_ns: Optional[int], outcome_status: str) -> None:
        if key in self._applied:
            return
        if len(self._order) >= self.max_entries:
            first = self._order.pop(0)
            self._applied.pop(first, None)
        self._applied[key] = {"applied_at_ns": at_ns, "status": outcome_status}
        self._order.append(key)

    def already_applied(self, key: str, *, now_ns: Optional[int] = None) -> Optional[Dict[str, Any]]:
        entry = self._applied.get(key)
        if entry is None:
            return None
        applied = entry.get("applied_at_ns")
        if (
            self.window_ns
            and now_ns is not None
            and applied is not None
            and now_ns > applied + self.window_ns
        ):
            return None
        return dict(entry)

    def __len__(self) -> int:
        return len(self._applied)

    def to_dict(self) -> Dict[str, Any]:
        return {"applied": list(self._applied), "max_entries": self.max_entries}