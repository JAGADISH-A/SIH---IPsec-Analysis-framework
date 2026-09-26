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

Durability (``path=``)
----------------------
A ledger constructed with a ``path`` persists every append to that JSONL file
using the same convention as the two journals it now links to: one JSON object
per line, ``flush`` + ``fsync`` on every append, and a reader that raises on
any corrupt line so a truncated log can never silently pass validation.

The journal is written to its own file next to the observation journal
(``results/audit/events.jsonl``) rather than into it, because the two are
different record kinds: that file is the raw packet-level TAP/TShark/Zeek
observation stream that governance evidence *references*; the governance
journal is the human-authority stream. Mixing them would let an observation
record break the governance hash chain, and would make the observation journal
unreadable by the evidence path. What links them is the ``audit_tap``
``EvidenceRef`` on each governance event, which resolves against the
observation journal — so an approval can be walked back to the packets that
justified it.

Reading is *fail-closed*: :meth:`AuditLedger.open` verifies the persisted
chain before adopting it and raises :class:`AuditIntegrityError` rather than
continuing a chain it cannot vouch for. A ledger is never silently repaired,
rewritten or truncated.
"""

import json
import os
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

from ..models.evidence import SOURCE_AUDIT_TAP
from ..models.identity import CorrelationIdentity
from .models import (
    ResponseAuditEvent,
    compute_event_hash,
    validate_event_type,
)

GENESIS_HASH = "0" * 64

#: The governance journal sits beside the observation journal it references.
DEFAULT_GOVERNANCE_JOURNAL = "results/audit/governance.jsonl"
#: The observation journal ``audit_tap`` evidence references point into.
DEFAULT_OBSERVATION_JOURNAL = "results/audit/events.jsonl"

#: The documented reference form: ``audit://<journal file>#<offset>``.
_AUDIT_POINTER_PREFIX = "audit://"


def _audit_pointer_index(pointer: str) -> Optional[int]:
    """The line offset an ``audit://file#N`` reference points at, or None.

    A reference that does not carry a plain non-negative integer offset is
    treated as unresolvable rather than guessed at — the offset is the only
    thing that makes the reference a join rather than a label.
    """
    if not isinstance(pointer, str) or not pointer.startswith(_AUDIT_POINTER_PREFIX):
        return None
    _, separator, tail = pointer.partition("#")
    if not separator:
        return None
    try:
        index = int(tail)
    except ValueError:
        return None
    return index if index >= 0 else None


class AuditIntegrityError(Exception):
    """Raised when the appended chain does not verify."""


class AuditLedger:
    """Append-only event ledger with deterministic SHA-256 chaining.

    With ``path`` set, every :meth:`append` is also persisted to that JSONL
    journal. Without a path the ledger is pure in-memory, which is what the
    domain tests and the replay paths rely on.
    """

    def __init__(self, engine_version: str = "v1", path: Optional[str] = None) -> None:
        self._events: List[ResponseAuditEvent] = []
        self.engine_version = engine_version
        self.path = Path(path) if path is not None else None

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
        appended = self._events[-1]
        if self.path is not None:
            self._persist(appended)
        return appended

    def _persist(self, event: ResponseAuditEvent) -> ResponseAuditEvent:
        """Append one event to the journal: flush + fsync, never rewritten."""
        if not isinstance(event, ResponseAuditEvent):
            raise TypeError("only ResponseAuditEvent may be persisted")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        line = json.dumps(event.to_dict(), sort_keys=True)
        with open(self.path, "a", encoding="utf-8") as handle:
            handle.write(line + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        return event

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

    # -- persistence --------------------------------------------------------

    def read_journal(self, path: Optional[str] = None) -> List[ResponseAuditEvent]:
        """Read a governance journal back into events.

        Fail-closed on a corrupt line: a truncated or hand-edited journal must
        not be silently reduced to the events that happen to parse, because the
        chain would then verify over a silently shortened history. A missing
        file is an empty journal, not an error.
        """
        target = Path(path) if path is not None else self.path
        if target is None:
            raise ValueError("no governance journal path configured")
        if not target.exists():
            return []
        events: List[ResponseAuditEvent] = []
        for number, line in enumerate(
            target.read_text(encoding="utf-8").splitlines(), 1
        ):
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(
                    f"corrupt governance audit event (line {number}): {exc}"
                )
            events.append(ResponseAuditEvent.from_dict(record))
        return events

    @classmethod
    def open(cls, path: str, engine_version: str = "v1") -> "AuditLedger":
        """Adopt an existing journal and keep appending to its chain.

        The persisted chain is verified *before* it is adopted; a tampered or
        out-of-order journal raises :class:`AuditIntegrityError` and is left
        exactly as it was found. Nothing is ever repaired, reordered or
        rewritten.
        """
        ledger = cls(engine_version=engine_version, path=path)
        ledger._events = ledger.read_journal()
        ledger.verify()
        return ledger

    # -- link to the observation journal ------------------------------------

    def audit_tap_refs(self) -> List[str]:
        """Every ``audit_tap`` event reference carried by the ledger.

        These are the joins back to the observation journal: each one names a
        line in ``results/audit/events.jsonl``. Collecting them is the whole
        point of persisting governance events — an approval that cannot be
        walked back to the observations behind it is not auditable.
        """
        refs: List[str] = []
        for event in self._events:
            for ref in event.evidence_refs:
                if getattr(ref, "source", None) == SOURCE_AUDIT_TAP:
                    pointer = getattr(ref, "audit_event_reference", None)
                    if pointer:
                        refs.append(pointer)
        return refs

    def verify_against(self, observation_journal: str) -> Dict[str, int]:
        """Check the ledger's ``audit_tap`` references against the real journal.

        Returns the counts of resolved and unresolvable references. A
        reference that does not resolve is reported, never repaired and never
        dropped: the ledger's own chain stays valid either way, and the caller
        decides what an unresolvable justification means.
        """
        target = Path(observation_journal)
        if not target.exists():
            return {"events": 0, "referenced": len(self.audit_tap_refs()),
                    "resolved": 0, "unresolved": len(self.audit_tap_refs())}
        lines = [line for line in target.read_text(encoding="utf-8").splitlines()
                 if line.strip()]
        resolved = 0
        unresolved = 0
        for pointer in self.audit_tap_refs():
            index = _audit_pointer_index(pointer)
            if index is not None and 0 <= index < len(lines):
                resolved += 1
            else:
                unresolved += 1
        return {
            "events": len(lines),
            "referenced": resolved + unresolved,
            "resolved": resolved,
            "unresolved": unresolved,
        }