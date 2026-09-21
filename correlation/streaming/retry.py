"""Retry policy with deterministic exponential backoff.

``RetryPolicy`` decides how many attempts a message may take and how long to
wait between them; ``RetryState`` tracks one message's progression. Backoff is
computed deterministically (no random jitter) so tests and behaviour are fully
reproducible::

    delay_ns = min(max_delay_ns, base_delay_ns * factor**attempt)

When a message exceeds ``max_retries`` it is moved to the dead-letter queue
(never silently dropped).
"""

from dataclasses import dataclass
from typing import Iterable, Optional, Sequence

DEFAULT_RETRYABLE_STATUSES = ("processing_failed", "downstream_unavailable")


@dataclass(frozen=True)
class RetryPolicy:
    """Configurable retry behaviour."""

    max_retries: int = 3
    base_delay_ns: int = 100_000_000
    max_delay_ns: int = 4_000_000_000
    factor: float = 2.0
    retryable_statuses: Sequence[str] = DEFAULT_RETRYABLE_STATUSES

    def __post_init__(self) -> None:
        if not isinstance(self.max_retries, int) or self.max_retries < 0:
            raise ValueError("max_retries must be a non-negative integer")
        if self.base_delay_ns < 0 or self.max_delay_ns < 0:
            raise ValueError("delays must be non-negative")
        if self.base_delay_ns > self.max_delay_ns:
            raise ValueError("base_delay_ns must be <= max_delay_ns")
        if self.factor <= 1.0:
            raise ValueError("factor must be > 1.0")

    def backoff_ns(self, attempt: int) -> int:
        """Deterministic delay before retrying ``attempt`` (0-based)."""
        if attempt < 0:
            raise ValueError("attempt must be >= 0")
        delay = int(self.base_delay_ns * (self.factor ** attempt))
        return min(delay, self.max_delay_ns)

    def should_retry(self, status: str, retries_used: int) -> bool:
        if status not in self.retryable_statuses:
            return False
        return retries_used < self.max_retries

    def is_retryable(self, status: str) -> bool:
        return status in self.retryable_statuses


@dataclass(frozen=True)
class RetryState:
    """Exactly-once-progress record for one event."""

    event_identity: str
    retries_used: int
    next_retry_at_ns: Optional[int]
    status: str
    exhausted: bool = False

    def backoff_ns(self, policy: RetryPolicy) -> int:
        return policy.backoff_ns(self.retries_used)


class RetryController:
    """Drives retry decisions for consumed events."""

    def __init__(self, policy: Optional[RetryPolicy] = None) -> None:
        self.policy = policy or RetryPolicy()
        self.retry_counts: dict = {}
        self.total_retries = 0

    def decide(
        self, event_identity: str, status: str, now_ns: Optional[int] = None
    ) -> "Decisions":
        used = self.retry_counts.get(event_identity, 0)
        if not self.policy.is_retryable(status):
            return Decisions(
                action="dead_letter",
                retries_used=used,
                next_retry_at_ns=None,
                exhausted=True,
            )
        if self.policy.should_retry(status, used):
            self.retry_counts[event_identity] = used + 1
            self.total_retries += 1
            delay = self.policy.backoff_ns(used)
            return Decisions(
                action="retry",
                retries_used=used + 1,
                next_retry_at_ns=None if now_ns is None else now_ns + delay,
                exhausted=False,
            )
        return Decisions(
            action="dead_letter",
            retries_used=used,
            next_retry_at_ns=None,
            exhausted=True,
        )


@dataclass(frozen=True)
class Decisions:
    """Outcome of one retry decision."""

    action: str
    retries_used: int
    next_retry_at_ns: Optional[int]
    exhausted: bool