"""Read-only audit store: a QUERY layer over the existing AuditJournal.

The authoritative analysis evidence is the append-only JSONL journal written by
``correlation/audit.py``. This module does not create a second log, does not
append, and does not re-derive anything: it reads that journal and projects the
frozen :class:`~correlation.audit.AuditEvent` objects it contains.

Why this is a separate class rather than an extension of
:class:`correlation.api.store.AssessmentStore`:

* ``AssessmentStore`` is a *derived* index. It re-runs the Phase-3 -> Phase-7
  pipeline over a plan fixture and rebuilds bundles in memory
  (``store.py:_build``). It holds no persisted evidence and has no notion of an
  event id.
* The analysis journal is *persisted* evidence whose authority is its own
  ``event_id``. Serving it from a store that recomputes pipelines would risk
  exactly the confusion this milestone forbids -- an analyst could not tell
  which bytes were written down and which were re-derived on the fly.

So the split is by authority, not by duplication: ``AuditJournal`` is the single
source of truth, ``AuditStore`` is the index that makes it queryable, and the
API layer is a projection of that index.

Integrity rules enforced here
-----------------------------
1. An event is read, never regenerated. ``event_id`` is taken from the record
   and round-tripped through :meth:`AuditEvent.from_dict`, which re-derives and
   verifies the content-addressed id. A record edited after it was written is
   rejected rather than served.
2. Reads never mutate. :meth:`list_events`, :meth:`get_event` and
   :meth:`run_trail` return fresh dictionaries over the parsed records; the
   frozen event objects are shared, never written to.
3. Provenance is passed through verbatim: ``source``, ``authoritative`` and
   ``event_id`` are never normalised, defaulted or upgraded. A comparison event
   is not relabelled as an observation and an ML result is never made
   authoritative.
4. Absence is reported as absence. A missing stage, reference or value stays
   ``None`` and is simply absent from an ordered trail; nothing is filled in
   from expected state.
5. A corrupt or unreadable journal is a hard error. Partial evidence is never
   served, because a truncated list would read as a complete one.

Nothing here imports ``correlation.execution`` or a response engine, and no
method performs I/O beyond reading the journal file.
"""

from __future__ import annotations

import os
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from ..audit import (
    EVENT_COMPARISON,
    EVENT_EVIDENCE,
    EVENT_EXPECTED_STATE,
    EVENT_EXPLANATION,
    EVENT_ML_FAILURE,
    EVENT_ML_RESULT,
    EVENT_OBSERVED_STATE,
    EVENT_RESPONSE_PROPOSAL,
    EVENT_RISK_ASSESSMENT,
    AuditEvent,
    AuditJournal,
)

#: The canonical analysis lifecycle, in stage order. Used to build the ordered
#: run trail. Stages with no recorded event are OMITTED, never emitted empty:
#: an absent stage is missing evidence, and the API must not imply otherwise.
AUDIT_STAGE_ORDER: Tuple[str, ...] = (
    "expected",
    "observed",
    "comparison",
    "ml",
    "risk",
    "explanation",
    "evidence",
    "response",
    "authorization",
    "execution",
)

#: Analysis event type -> lifecycle stage. ``ml_result`` and ``ml_failure`` share
#: the ``ml`` stage: both are the ML position in the pipeline, and a failure is
#: a real recorded outcome rather than a missing stage.
EVENT_STAGE: Dict[str, str] = {
    EVENT_EXPECTED_STATE: "expected",
    EVENT_OBSERVED_STATE: "observed",
    EVENT_COMPARISON: "comparison",
    EVENT_ML_RESULT: "ml",
    EVENT_ML_FAILURE: "ml",
    EVENT_RISK_ASSESSMENT: "risk",
    EVENT_EXPLANATION: "explanation",
    EVENT_EVIDENCE: "evidence",
    EVENT_RESPONSE_PROPOSAL: "response",
}

#: Response-layer event types that extend the lifecycle past a proposal. These
#: live in ``correlation/response/audit.py`` and are only ever surfaced through
#: the read-only join, never synthesised here. The proposal-side review steps
#: (``RECOMMENDATION_CREATED`` / approval / rejection) belong to the
#: ``response`` stage; only a real ``AUTHORIZATION_CHECKED`` counts as
#: ``authorization``, and only a real execution record as ``execution``.
RESPONSE_STAGE: Dict[str, str] = {
    "RECOMMENDATION_CREATED": "response",
    "APPROVAL_REQUESTED": "response",
    "APPROVED": "response",
    "REJECTED": "response",
    "STATUS_CHANGED": "response",
    "AUTHORIZATION_CHECKED": "authorization",
    "EXECUTION_REQUESTED": "execution",
    "DRY_RUN_EXECUTED": "execution",
    "EXECUTION_SUCCEEDED": "execution",
    "EXECUTION_FAILED": "execution",
}

#: Default page size. A caller may ask for more, but a list response is bounded
#: so a large journal cannot be pulled into a single response by accident.
DEFAULT_LIMIT = 200
MAX_LIMIT = 5_000


class AuditJournalUnreadable(Exception):
    """The journal exists but could not be read as intact audit evidence.

    Raised for a corrupt line or a record whose content no longer matches its
    ``event_id``. Callers must surface this rather than serving a partial list.
    """


def stage_for(event_type: str) -> Optional[str]:
    """Lifecycle stage for an analysis event type, or ``None`` if unknown."""
    return EVENT_STAGE.get(event_type)


def _as_bool(value: Any) -> Optional[bool]:
    """Parse a filter value into a tri-state bool (None = do not filter)."""
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in ("true", "1", "yes"):
            return True
        if lowered in ("false", "0", "no"):
            return False
        if lowered in ("", "any", "all"):
            return None
    raise ValueError(f"authoritative must be a boolean, got {value!r}")


def _as_int(value: Any, field: str) -> Optional[int]:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        raise ValueError(f"{field} must be an integer, got {value!r}") from None


def _as_list(value: Any) -> Tuple[str, ...]:
    """Accept a repeated param or a comma-separated list; empty -> no filter."""
    if value is None:
        return ()
    if isinstance(value, (list, tuple, set)):
        raw: Iterable[Any] = value
    else:
        raw = str(value).split(",")
    return tuple(str(item).strip() for item in raw if str(item).strip())


class AuditQuery:
    """A validated, immutable audit query.

    Built from raw query-string values so that a malformed filter is rejected at
    the edge (as a structured 400) rather than silently matching nothing.
    """

    __slots__ = (
        "run_id", "experiment_id", "sequence", "attempt_number", "event_types",
        "sources", "authoritative", "window_index", "window_from_ns",
        "window_to_ns", "event_ids", "limit", "offset",
    )

    def __init__(self, **kwargs: Any) -> None:
        for name in self.__slots__:
            setattr(self, name, kwargs.get(name))

    @classmethod
    def from_params(cls, params: Optional[Dict[str, Any]] = None) -> "AuditQuery":
        params = params or {}
        limit = _as_int(params.get("limit"), "limit")
        if limit is not None and limit < 1:
            raise ValueError(f"limit must be >= 1, got {limit}")
        if limit is None:
            limit = DEFAULT_LIMIT
        limit = min(limit, MAX_LIMIT)
        offset = _as_int(params.get("offset"), "offset")
        if offset is not None and offset < 0:
            raise ValueError(f"offset must be >= 0, got {offset}")
        return cls(
            run_id=params.get("run_id") or None,
            experiment_id=params.get("experiment_id") or None,
            sequence=_as_int(params.get("sequence"), "sequence"),
            attempt_number=_as_int(params.get("attempt_number"), "attempt_number"),
            event_types=_as_list(params.get("event_type")),
            sources=_as_list(params.get("source")),
            authoritative=_as_bool(params.get("authoritative")),
            window_index=_as_int(params.get("window_index"), "window_index"),
            window_from_ns=_as_int(
                params.get("window_from_ns"), "window_from_ns"
            ),
            window_to_ns=_as_int(params.get("window_to_ns"), "window_to_ns"),
            event_ids=_as_list(params.get("event_id")),
            limit=limit,
            offset=offset or 0,
        )

    def matches(self, event: AuditEvent) -> bool:
        identity = event.identity
        if self.run_id is not None and identity.dataset_run_id != self.run_id:
            return False
        if self.experiment_id is not None and identity.experiment_id != self.experiment_id:
            return False
        if self.sequence is not None and identity.sequence != self.sequence:
            return False
        if self.attempt_number is not None and identity.attempt_number != self.attempt_number:
            return False
        if self.event_types and event.event_type not in self.event_types:
            return False
        if self.sources and event.source not in self.sources:
            return False
        if self.authoritative is not None and event.authoritative is not self.authoritative:
            return False
        if self.event_ids and event.event_id not in self.event_ids:
            return False
        if self.window_index is not None and identity.window_index != self.window_index:
            return False
        # Window bounds are optional on the identity; an event that recorded no
        # window cannot satisfy a window-range filter, and saying so beats
        # matching it.
        if self.window_from_ns is not None:
            if identity.window_start_ns is None:
                return False
            if identity.window_start_ns < self.window_from_ns:
                return False
        if self.window_to_ns is not None:
            if identity.window_start_ns is None:
                return False
            if identity.window_start_ns > self.window_to_ns:
                return False
        return True

    def describe(self) -> Dict[str, Any]:
        """Echo the active filters so a client can see what it actually asked."""
        return {
            name: getattr(self, name)
            for name in self.__slots__
            if getattr(self, name) not in (None, (), 0)
        }


class AuditTrailWindow:
    """One window's ordered lifecycle, containing only recorded stages."""

    __slots__ = ("window_index", "window_start_ns", "window_end_ns", "stages", "events")

    def __init__(self, window_index, window_start_ns, window_end_ns):
        self.window_index = window_index
        self.window_start_ns = window_start_ns
        self.window_end_ns = window_end_ns
        self.stages: List[Dict[str, Any]] = []
        self.events: List[AuditEvent] = []

    def stage_names(self) -> List[str]:
        return [stage["stage"] for stage in self.stages]


class AuditStore:
    """Read-only, indexed view over an existing :class:`AuditJournal`.

    The journal is scanned at most once per on-disk change: a ``(mtime, size)``
    stamp is cached alongside the parsed index, so repeated API reads do not
    re-parse the file, while an appended-to journal is still picked up.
    """

    def __init__(
        self,
        journal_path: Optional[str] = None,
        *,
        journal: Optional[AuditJournal] = None,
        response_ledger: Optional[Any] = None,
    ) -> None:
        if journal is None:
            journal = AuditJournal(journal_path)
        self.journal = journal
        self.path = journal.path
        self.response_ledger = response_ledger
        self._index: Optional[List[AuditEvent]] = None
        self._by_event_id: Dict[str, AuditEvent] = {}
        self._stamp: Optional[Tuple[int, int]] = None
        self._runs: Dict[str, List[AuditEvent]] = {}
        self.reload()

    # -- index --------------------------------------------------------------

    def _disk_stamp(self) -> Optional[Tuple[int, int]]:
        if self.path is None or not os.path.exists(self.path):
            return None
        info = os.stat(self.path)
        return (info.st_mtime_ns, info.st_size)

    def reload(self) -> int:
        """Re-read the journal if it changed on disk; return the event count.

        A missing journal is an empty index, not an error: the API reports zero
        audit events rather than inventing any. A *corrupt* journal is an error.
        """
        stamp = self._disk_stamp()
        if self._index is not None and stamp == self._stamp:
            return len(self._index)
        try:
            events = self.journal.read()
        except (ValueError, TypeError, KeyError) as exc:
            raise AuditJournalUnreadable(str(exc)) from exc
        self._index = events
        self._by_event_id = {}
        self._runs = {}
        for event in events:
            self._by_event_id[event.event_id] = event
            self._runs.setdefault(event.identity.dataset_run_id, []).append(event)
        self._stamp = stamp
        return len(events)

    @property
    def available(self) -> bool:
        return self.path is not None and os.path.exists(self.path)

    def __len__(self) -> int:
        self.reload()
        return len(self._index or ())

    # -- queries ------------------------------------------------------------

    def select(self, query: Optional[AuditQuery] = None) -> List[AuditEvent]:
        """All events matching ``query``, in journal order, ignoring paging."""
        self.reload()
        if query is None:
            return list(self._index or ())
        return [event for event in (self._index or ()) if query.matches(event)]

    def list_events(self, query: Optional[AuditQuery] = None) -> Tuple[List[AuditEvent], int]:
        """Return ``(page, total)`` for a query, applying offset/limit.

        ``total`` is the count of ALL matching events, so a client can page
        without re-querying for the size.
        """
        matched = self.select(query)
        total = len(matched)
        if query is None:
            return matched, total
        start = query.offset
        return matched[start:start + query.limit], total

    def get_event(self, event_id: str) -> Optional[AuditEvent]:
        """Look up one event by its existing ``event_id``.

        Returns the recorded event or ``None``. The id is never regenerated and
        never guessed, so an unknown id is a miss rather than a new record.
        """
        self.reload()
        return self._by_event_id.get(event_id)

    def runs(self) -> List[Dict[str, Any]]:
        """Per-run summaries, for frontend discovery."""
        self.reload()
        summaries = []
        for run_id, events in self._runs.items():
            experiments = sorted({e.identity.experiment_id for e in events})
            sequences = sorted({e.identity.sequence for e in events})
            attempts = sorted({e.identity.attempt_number for e in events})
            windows = sorted({
                e.identity.window_index for e in events
                if e.identity.window_index is not None
            })
            counts: Dict[str, int] = {}
            for event in events:
                counts[event.event_type] = counts.get(event.event_type, 0) + 1
            summaries.append({
                "run_id": run_id,
                "event_count": len(events),
                "experiment_ids": experiments,
                "sequences": sequences,
                "attempt_numbers": attempts,
                "window_count": len(windows),
                "window_index_min": windows[0] if windows else None,
                "window_index_max": windows[-1] if windows else None,
                "event_type_counts": dict(sorted(counts.items())),
                "authoritative_event_count": sum(1 for e in events if e.authoritative),
            })
        return sorted(summaries, key=lambda item: item["run_id"])

    def window(self, run_id: str, window_index: int) -> Optional[Dict[str, Any]]:
        """The recorded window bounds for one run/window, or None.

        Read-only: returns exactly what the journal recorded so a downstream
        consumer (e.g. evidence packet-coverage) can compare a real analysis
        window against a capture interval instead of inventing bounds.
        """
        self.reload()
        events = self._runs.get(run_id)
        if not events:
            return None
        for event in events:
            if event.identity.window_index == window_index:
                return {
                    "run_id": run_id,
                    "experiment_id": event.identity.experiment_id,
                    "sequence": event.identity.sequence,
                    "attempt_number": event.identity.attempt_number,
                    "window_index": window_index,
                    "window_start_ns": event.identity.window_start_ns,
                    "window_end_ns": event.identity.window_end_ns,
                }
        return None

    def evidence_for_event(self, event_id: str) -> Tuple[Tuple[Any, ...], ...]:
        """The evidence references recorded on one event, as stored."""
        event = self.get_event(event_id)
        if event is None:
            return ()
        return tuple(event.evidence_refs)

    def run_trail(
        self, run_id: str, query: Optional[AuditQuery] = None
    ) -> Optional[Dict[str, Any]]:
        """Ordered per-window lifecycle for one run.

        Within a window the stages follow :data:`AUDIT_STAGE_ORDER`. Only stages
        that actually have a recorded event appear; a run whose ML inference
        failed shows an ``ml`` stage holding an ``ml_failure`` event, and a run
        that stopped after comparison simply has no later stage. ``None`` is
        returned for an unknown run so the caller can raise a structured 404.
        """
        self.reload()
        run_events = self._runs.get(run_id)
        if run_events is None:
            return None
        if query is not None:
            run_events = [event for event in run_events if query.matches(event)]

        # Pagination applies to the *filtered event* set, before windows are
        # grouped, so limit/offset means the same thing here as on the flat
        # event list. It used to be ignored entirely: the query's limit and
        # offset were echoed in the response while the whole run was returned,
        # so a client paging a long run silently re-fetched everything each
        # time and could never reach the end.
        event_count_total = len(run_events)
        offset = query.offset if query is not None else 0
        limit = query.limit if query is not None else None
        if limit is not None or offset:
            start = offset or 0
            if limit is None:
                run_events = run_events[start:]
            else:
                run_events = run_events[start:start + limit]

        windows: Dict[Tuple[Any, Any, Any], AuditTrailWindow] = {}
        order: List[Tuple[Any, Any, Any]] = []
        for event in run_events:
            identity = event.identity
            key = (identity.window_index, identity.window_start_ns, identity.window_end_ns)
            window = windows.get(key)
            if window is None:
                window = AuditTrailWindow(*key)
                windows[key] = window
                order.append(key)
            window.events.append(event)

        trail_windows = []
        for key in order:
            window = windows[key]
            stages: Dict[str, Dict[str, Any]] = {}
            for event in window.events:
                stage = stage_for(event.event_type)
                if stage is None:
                    # Not part of the analysis ladder (currently impossible:
                    # every analysis event type maps to a stage). Recorded here
                    # rather than skipped, so a new event type cannot vanish.
                    stage = "other"
                entry = stages.setdefault(stage, {"stage": stage, "events": []})
                entry["events"].append(event)
            ordered = []
            for stage in AUDIT_STAGE_ORDER:
                if stage in stages:
                    ordered.append(stages[stage])
            for stage, entry in stages.items():
                if stage not in AUDIT_STAGE_ORDER:
                    ordered.append(entry)
            window.stages = ordered
            trail_windows.append(window)

        shown = sum(len(window.events) for window in trail_windows)
        return {
            "run_id": run_id,
            "window_count": len(trail_windows),
            "stage_order": list(AUDIT_STAGE_ORDER),
            "stages_present": sorted({
                stage["stage"]
                for window in trail_windows for stage in window.stages
            }),
            "event_count": event_count_total,
            "returned_event_count": shown,
            "limit": limit,
            "offset": offset or 0,
            "has_more": (offset or 0) + shown < event_count_total,
            "windows": trail_windows,
        }

    # -- response proposal join (read-only) ---------------------------------

    def response_lifecycle(self, recommendation_id: str) -> Dict[str, Any]:
        """Read-only view of the response lifecycle for a proposal reference.

        ``response_proposal_ref`` on an analysis event holds a recommendation
        id. ``correlation/response/audit.py`` already answers "what happened to
        this recommendation?" via ``for_recommendation``, so this is a join
        over existing records, not a new event source.

        The ledger is attached by the application (``--governance-journal``),
        which is the write side that persists assessment/recommendation/
        authorization/approval events to disk. When none is attached the result
        reports the real absence. It never guesses a status, and it never
        creates an authorization or execution event.
        """
        if not recommendation_id:
            return {
                "available": False,
                "recommendation_id": recommendation_id,
                "reason": "no response_proposal_ref recorded on this event",
                "stages": [],
                "events": [],
            }
        ledger = self.response_ledger
        if ledger is None:
            return {
                "available": False,
                "recommendation_id": recommendation_id,
                "reason": (
                    "no response audit ledger is attached to this store; attach "
                    "one with --governance-journal <path> to resolve "
                    "authorization/execution from the persisted ledger"
                ),
                "stages": [],
                "events": [],
            }
        try:
            recorded = list(ledger.for_recommendation(recommendation_id))
        except Exception as exc:  # pragma: no cover - defensive
            return {
                "available": False,
                "recommendation_id": recommendation_id,
                "reason": f"response ledger query failed: {exc}",
                "stages": [],
                "events": [],
            }

        events: List[Dict[str, Any]] = []
        stages: List[str] = []
        for record in recorded:
            payload = record.to_dict()
            events.append(payload)
            stage = RESPONSE_STAGE.get(record.event_type)
            if stage is not None and stage not in stages:
                stages.append(stage)
        return {
            "available": True,
            "recommendation_id": recommendation_id,
            "reason": None,
            "event_count": len(events),
            "stages": [s for s in AUDIT_STAGE_ORDER if s in stages],
            "events": events,
            "chain_verified": bool(ledger.verify()),
        }
