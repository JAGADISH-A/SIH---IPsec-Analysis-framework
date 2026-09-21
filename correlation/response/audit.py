"""Phase 9 — append-only response audit ledger with a SHA-256 chain.

Every lifecycle step (recommendation, authorization, approval, rejection,
execution, dry-run, cancellation, expiry) appends a ``ResponseAuditEvent``.
Events are append-only within the ledger: previous events are never mutated or
overwritten. Each event carries ``previous_hash`` + ``event_hash`` forming a
deterministic hash chain:

    Event 1 (previous_hash = 0*64)
       | h1
    Event 2 (previous_hash = h1)
       | h2
    Event 3 ...

``verify()`` recomputes the entire chain and raises on tampering. This provides
deterministic integrity DETECTION for the domain model — explicitly NOT
tamper-evident persistent storage (that belongs to Phase 10 / the hosting
platform).
"""

from typing import Dict, List, Optional, Sequence, Tuple

from ..models.identity import CorrelationIdentity
from .models import (
    ResponseAuditEvent,
    compute_event_hash,
    validate_event_type,
)

GENESIS_HASH = "0" * 64


class AuditIntegrityError(Exception):
    """Raised when the appended chain does not verify."""


class AuditLedger:
    """Append-only event ledger with deterministic SHA-256 chaining."""

    def __init__(self, engine_version: str = "v1") -> None:
        self._events: List[ResponseAuditEvent] = []
        self.engine_version = engine_version

    # -- queries ------------------------------------------------------------

    def __len__(self) -> int:
        return len(self._events)

    def events(self) -> Tuple[ResponseAuditEvent, ...]:
        return tuple(self._events)

    def last_event(self) -> Optional[ResponseAuditEvent]:
        return self._events[-1] if self._events else None

    def last_hash(self) -> str:
        last = self.last_event()
        return last.event_hash if last else GENESIS_HASH

    def for_assessment(self, dataset_run_id: str, sequence: int) -> List[ResponseAuditEvent]:
        return [event for event in self._events
                if (event.assessment_identity.dataset_run_id == dataset_run_id
                    and event.assessment_identity.sequence == sequence)]

    def for_recommendation(self, recommendation_id: str) -> List[ResponseAuditEvent]:
        return [event for event in self._events
                if event.recommendation_id == recommendation_id]

    # -- mutation (append only) ---------------------------------------------

    def append(
        self,
        *,
        timestamp: Optional[int],
        assessment_identity: CorrelationIdentity,
        event_type: str,
        principal: str,
        reason: str = "",
        policy_version: str = "",
        recommendation_id: Optional[str] = None,
        approval_id: Optional[str] = None,
        action: Optional[str] = None,
        previous_status: Optional[str] = None,
        new_status: Optional[str] = None,
        evidence_refs: Sequence = (),
    ) -> ResponseAuditEvent:
        """Compute the chain link and append an event. Never mutates old ones."""
        validate_event_type(event_type)
        if not isinstance(reason, str):
            raise ValueError("reason must be a string")
        previous_hash = self.last_hash()
        next_index = len(self._events) + 1
        event = ResponseAuditEvent(
            event_id=f"EVT-{next_index:04d}",
            timestamp=timestamp,
            assessment_identity=assessment_identity,
            recommendation_id=recommendation_id,
            approval_id=approval_id,
            principal=principal,
            event_type=event_type,
            action=action,
            previous_status=previous_status,
            new_status=new_status,
            reason=reason,
            policy_version=policy_version or "",
            evidence_refs=tuple(evidence_refs) if evidence_refs else (),
            previous_hash=previous_hash,
            event_hash=GENESIS_HASH,
        )
        base = event.base_dict()
        event_hash = compute_event_hash(base, previous_hash)
        self._events.append(
            ResponseAuditEvent(
                event_id=event.event_id,
                timestamp=event.timestamp,
                assessment_identity=event.assessment_identity,
                recommendation_id=event.recommendation_id,
                approval_id=event.approval_id,
                principal=event.principal,
                event_type=event.event_type,
                action=event.action,
                previous_status=event.previous_status,
                new_status=event.new_status,
                reason=event.reason,
                policy_version=event.policy_version,
                evidence_refs=event.evidence_refs,
                previous_hash=previous_hash,
                event_hash=event_hash,
            )
        )
        return self._events[-1]

    # -- integrity ----------------------------------------------------------

    def verify(self) -> bool:
        """Recompute the whole chain; raises AuditIntegrityError on tampering."""
        previous = GENESIS_HASH
        for index, event in enumerate(self._events):
            if event.previous_hash != previous:
                raise AuditIntegrityError(
                    f"chain broken at {event.event_id}: previous_hash "
                    f"{event.previous_hash} != expected {previous}"
                )
            if event.event_id != f"EVT-{index + 1:04d}":
                raise AuditIntegrityError(f"misordered event id {event.event_id}")
            expected = compute_event_hash(event.base_dict(), previous)
            if event.event_hash != expected:
                raise AuditIntegrityError(
                    f"event_hash mismatch at {event.event_id}"
                )
            previous = event.event_hash
        return True

    def to_dicts(self) -> List[Dict]:
        return [event.to_dict() for event in self._events]

    @classmethod
    def from_dicts(cls, events: Sequence[Dict], engine_version: str = "v1") -> "AuditLedger":
        ledger = cls(engine_version=engine_version)
        for data in events:
            ledger._events.append(ResponseAuditEvent.from_dict(data))
        ledger.verify()
        return ledger

    def clone(self) -> "AuditLedger":
        ledger = AuditLedger(engine_version=self.engine_version)
        ledger._events = list(self._events)
        return ledger