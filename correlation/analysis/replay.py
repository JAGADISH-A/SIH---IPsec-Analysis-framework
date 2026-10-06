"""Area 3 -- replay protection analysis.

A real, deterministic analysis of the ESP sequence information the pipeline
already collects. It answers the brief's five questions per SPI and never
conflates them:

* normal monotonic progression -> ``NO_EVIDENCE`` (a clean analysis result)
* duplicate sequence numbers   -> ``OBSERVED`` (evidence exists)
* backward sequence numbers    -> ``OBSERVED`` (evidence exists)
* suspicious gaps              -> counted and reported as GAPS ONLY. A gap is
                                  the normal result of capture loss or of a
                                  sender skipping a sequence; RFC 4303's
                                  replay window tolerates it. A gap is never
                                  reported as replay evidence.
* insufficient evidence        -> ``INSUFFICIENT_DATA``

Two evidence levels are supported, and which one applies is stated:

``PER_PACKET``   the recorded packet journal (``events.jsonl``) names every
                 packet's SPI and sequence, so duplicates and gaps are counted
                 exactly. This is the only level that can ever produce an
                 ``OBSERVED`` status.
``AGGREGATE``    only the state builder's per-SPI summary exists. It can show
                 the highest sequence and a net backward progression, but it
                 cannot prove the absence of a duplicate, so ``duplicates``
                 stays ``None`` with the reason why.
``ABSENT``       no sequence information at all (no packets, or the snapshot
                 never recorded a sequence -- ESP sequence 0 is unused by
                 senders per RFC 4303, so 0 means "absent").

A security finding is generated only from ``OBSERVED`` evidence, and only in
the risk engine (``correlation.risk.rules.rule_replay_duplicate_sequence``);
this module produces evidence, never a finding.
"""

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence, Tuple

from ..artifacts import canonical_spi
from ..models import ObservedState
from .states import STATE_INFERRED, STATE_NOT_AVAILABLE, STATE_OBSERVED, STATE_UNKNOWN

#: Product statuses (the brief's vocabulary, kept exact).
REPLAY_STATUS_OBSERVED = "OBSERVED"
REPLAY_STATUS_NO_EVIDENCE = "NO_EVIDENCE"
REPLAY_STATUS_INSUFFICIENT_DATA = "INSUFFICIENT_DATA"
REPLAY_STATUSES = (
    REPLAY_STATUS_OBSERVED,
    REPLAY_STATUS_NO_EVIDENCE,
    REPLAY_STATUS_INSUFFICIENT_DATA,
)

EVIDENCE_PER_PACKET = "PER_PACKET"
EVIDENCE_AGGREGATE = "AGGREGATE"
EVIDENCE_ABSENT = "ABSENT"

#: Status precedence: an anomaly outranks an evidence gap, which outranks a
#: clean result. A clean result must never be reported while part of the
#: observation could not be analysed.
_STATUS_RANK = {
    REPLAY_STATUS_NO_EVIDENCE: 0,
    REPLAY_STATUS_INSUFFICIENT_DATA: 1,
    REPLAY_STATUS_OBSERVED: 2,
}

#: ``sequence_delta`` is ``(last - first) mod 2**32``. A net backwards movement
#: therefore lands above half the modulus; anything below it is a forward step
#: (a single wraparound included).
_BACKWARD_DELTA_THRESHOLD = 0x80000000

#: How established each per-SPI state is, so the product can state its own
#: state as the least-established state it rests on: an assessment that mixes
#: an exact journal with an unrecorded sequence is not fully observed.
_STATE_RANK: Dict[str, int] = {
    STATE_NOT_AVAILABLE: 0,
    STATE_UNKNOWN: 1,
    STATE_INFERRED: 2,
    STATE_OBSERVED: 3,
}

SEQUENCE_NOT_RECORDED_REASON = (
    "first_sequence and last_sequence are 0 while packets were seen. RFC 4303 "
    "starts the ESP sequence at 1 and never sends 0, so 0 means no sequence "
    "was recorded: there is nothing to analyse."
)
NO_PACKETS_REASON = (
    "No ESP packet was observed under this SPI, so there is no sequence "
    "progression to assess."
)


def normalize_spi(value: Any) -> str:
    """Canonical SPI token (``0x%08x``), shared with the artifact loaders."""
    return canonical_spi(value)


@dataclass(frozen=True)
class ReplaySpiAnalysis:
    """Replay analysis for one SPI."""

    spi: str
    packet_count: int
    evidence_level: str
    status: str
    state: str
    reason: str
    duplicate_sequences: Optional[int] = None
    backward_sequences: Optional[int] = None
    sequence_gaps: Optional[int] = None
    highest_sequence: Optional[int] = None
    monotonic: Optional[bool] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "spi": self.spi,
            "packet_count": self.packet_count,
            "evidence_level": self.evidence_level,
            "status": self.status,
            "state": self.state,
            "reason": self.reason,
            "duplicate_sequences": self.duplicate_sequences,
            "backward_sequences": self.backward_sequences,
            "sequence_gaps": self.sequence_gaps,
            "highest_sequence": self.highest_sequence,
            "monotonic": self.monotonic,
        }


@dataclass(frozen=True)
class ReplayAnalysis:
    """The complete replay-assessment product for one assessment.

    ``state`` is how established the assessment itself is: the
    least-established state among the per-SPI analyses (``NOT_AVAILABLE``
    when there are none), so a product that mixes exact journal evidence with
    an SPI whose sequence was never recorded never reports itself as fully
    observed. ``status`` is the brief's replay vocabulary and says what the
    evidence showed; the two are deliberately separate.
    """

    status: str
    reason: str
    source: str
    state: str
    duplicate_sequences: Optional[int] = None
    backward_sequences: Optional[int] = None
    sequence_gaps: Optional[int] = None
    highest_sequence: Optional[int] = None
    per_spi: tuple = ()
    evidence: tuple = ()
    limitations: tuple = ()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status,
            "state": self.state,
            "reason": self.reason,
            "source": self.source,
            "duplicate_sequences": self.duplicate_sequences,
            "backward_sequences": self.backward_sequences,
            "sequence_gaps": self.sequence_gaps,
            "highest_sequence": self.highest_sequence,
            "per_spi": [s.to_dict() for s in self.per_spi],
            "evidence": [dict(e) for e in self.evidence],
            "limitations": list(self.limitations),
        }


def _combine(per_spi: Sequence[ReplaySpiAnalysis], attribute: str) -> Optional[int]:
    """Sum one counter across SPIs, staying unknown if any SPI is unknown.

    An aggregate-only SPI reports ``None`` for duplicates because it cannot
    count them; summing only the known ones would silently turn "unknown" into
    "smaller", so one unknown makes the total unknown.
    """
    values = [getattr(entry, attribute) for entry in per_spi]
    if not values or any(value is None for value in values):
        return None
    return int(sum(values))


def _sequence_recorded(spi) -> bool:
    first = getattr(spi, "first_sequence", None)
    last = getattr(spi, "last_sequence", None)
    return not (first in (None, 0) and last in (None, 0))


def _per_packet_spi(spi, events: Sequence[Tuple[int, int]]) -> Tuple[ReplaySpiAnalysis, List[Dict[str, Any]]]:
    sequences = [seq for seq, _ts in events]
    total = len(sequences)
    unique = len(set(sequences))
    duplicates = total - unique

    backward = 0
    for previous, current in zip(sequences, sequences[1:]):
        if current < previous:
            backward += 1

    low, high = min(sequences), max(sequences)
    # Integers in the observed span that were never carried under this SPI.
    missing = max(0, (high - low + 1) - unique)

    monotonic = all(current >= previous for previous, current in zip(sequences, sequences[1:]))
    evidence: List[Dict[str, Any]] = []

    if duplicates:
        status = REPLAY_STATUS_OBSERVED
        reason = (
            f"{duplicates} duplicate ESP sequence number(s) were carried under "
            "this SPI in the recorded packet journal. A duplicate is replay "
            "evidence: an RFC 4303 replay window would discard the second "
            "copy. The journal does not say whether the copy was injected or "
            "duplicated by the capture path, so the finding this evidence "
            "supports is an anomaly, never an attack claim."
        )
        by_sequence: Dict[int, List[int]] = {}
        for seq, ts in events:
            by_sequence.setdefault(seq, []).append(ts)
        for seq, stamps in sorted(by_sequence.items()):
            if len(stamps) < 2:
                continue
            separation = (max(stamps) - min(stamps)) / 1_000_000_000
            evidence.append(
                {
                    "kind": "duplicate_sequence",
                    "spi": normalize_spi(spi.spi),
                    "sequence": seq,
                    "occurrence_count": len(stamps),
                    "timestamps_ns": list(stamps),
                    "separation_seconds": round(separation, 9),
                }
            )
    elif backward:
        status = REPLAY_STATUS_OBSERVED
        reason = (
            f"{backward} backwards step(s) in the ESP sequence progression "
            "were recorded under this SPI. Backwards movement is anomaly "
            "evidence worth reporting; it is also what a retransmission or a "
            "reordered capture looks like, so it is reported as an anomaly "
            "with this reason rather than as a confirmed replay attack."
        )
        evidence.append(
            {
                "kind": "backward_sequence",
                "spi": normalize_spi(spi.spi),
                "backward_steps": backward,
                "first_sequence": sequences[0],
                "last_sequence": sequences[-1],
            }
        )
    else:
        status = REPLAY_STATUS_NO_EVIDENCE
        reason = (
            f"All {total} recorded sequence number(s) under this SPI are "
            "distinct and non-decreasing: normal monotonic progression with no "
            "duplicate and no backwards step."
        )
        evidence.append(
            {
                "kind": "monotonic_progression",
                "spi": normalize_spi(spi.spi),
                "packet_count": total,
                "first_sequence": sequences[0],
                "last_sequence": sequences[-1],
                "distinct_sequences": unique,
            }
        )

    if missing:
        evidence.append(
            {
                "kind": "sequence_gap",
                "spi": normalize_spi(spi.spi),
                "missing_sequences": missing,
                "span": [low, high],
                "note": (
                    "Reported as a gap only. A gap is consistent with capture "
                    "loss or with a sender skipping a sequence and is NEVER "
                    "counted as replay evidence."
                ),
            }
        )

    return (
        ReplaySpiAnalysis(
            spi=normalize_spi(spi.spi),
            packet_count=spi.packet_count,
            evidence_level=EVIDENCE_PER_PACKET,
            status=status,
            state=STATE_OBSERVED,
            reason=reason,
            duplicate_sequences=duplicates,
            backward_sequences=backward,
            sequence_gaps=missing,
            highest_sequence=max(sequences),
            monotonic=monotonic,
        ),
        evidence,
    )


def _aggregate_spi(spi) -> Tuple[ReplaySpiAnalysis, List[Dict[str, Any]]]:
    evidence: List[Dict[str, Any]] = []
    if spi.packet_count <= 0:
        return (
            ReplaySpiAnalysis(
                spi=normalize_spi(spi.spi),
                packet_count=spi.packet_count,
                evidence_level=EVIDENCE_ABSENT,
                status=REPLAY_STATUS_INSUFFICIENT_DATA,
                state=STATE_NOT_AVAILABLE,
                reason=NO_PACKETS_REASON,
            ),
            [
                {
                    "kind": "insufficient_data",
                    "spi": normalize_spi(spi.spi),
                    "reason": NO_PACKETS_REASON,
                }
            ],
        )

    if not _sequence_recorded(spi):
        return (
            ReplaySpiAnalysis(
                spi=normalize_spi(spi.spi),
                packet_count=spi.packet_count,
                evidence_level=EVIDENCE_ABSENT,
                status=REPLAY_STATUS_INSUFFICIENT_DATA,
                state=STATE_NOT_AVAILABLE,
                reason=SEQUENCE_NOT_RECORDED_REASON,
            ),
            [
                {
                    "kind": "insufficient_data",
                    "spi": normalize_spi(spi.spi),
                    "reason": SEQUENCE_NOT_RECORDED_REASON,
                }
            ],
        )

    delta = spi.sequence_delta or 0
    backward: Optional[int] = None
    reason_parts: List[str] = []
    if delta > _BACKWARD_DELTA_THRESHOLD:
        backward = 1
        reason_parts.append(
            "the net first-to-last sequence movement is backwards "
            f"(sequence_delta={delta} exceeds half the 32-bit modulus), which "
            "is anomaly evidence"
        )
        status = REPLAY_STATUS_OBSERVED
        state = STATE_INFERRED
        evidence.append(
            {
                "kind": "backward_sequence",
                "spi": normalize_spi(spi.spi),
                "sequence_delta": delta,
                "note": (
                    "Inferred from the aggregate first/last difference only; "
                    "the packet journal that would count the individual "
                    "backwards steps is not available for this capture."
                ),
            }
        )
    else:
        reason_parts.append(
            "the net first-to-last sequence movement is forward "
            f"(sequence_delta={delta})"
        )
        status = REPLAY_STATUS_INSUFFICIENT_DATA
        state = STATE_UNKNOWN

    span = delta + 1
    excess = spi.packet_count - span
    if excess > 0:
        reason_parts.append(
            f"packet_count ({spi.packet_count}) exceeds the first-to-last span "
            f"({span}) by {excess}. That excess is consistent with EITHER a "
            "duplicate sequence OR an out-of-order packet below "
            "first_sequence, and the aggregate cannot distinguish the two -- "
            "so duplicate_sequences is reported as unknown, not as zero"
        )
    else:
        reason_parts.append(
            "duplicate sequences cannot be counted from the aggregate "
            "(packet_count vs span only bounds them), so duplicate_sequences "
            "is reported as unknown rather than as zero"
        )

    evidence.append(
        {
            "kind": "aggregate_progression",
            "spi": normalize_spi(spi.spi),
            "packet_count": spi.packet_count,
            "first_sequence": spi.first_sequence,
            "last_sequence": spi.last_sequence,
            "highest_sequence": spi.highest_sequence,
            "sequence_delta": spi.sequence_delta,
            "excess_packets_beyond_span": max(0, excess),
            "note": (
                "Aggregate only: this capture recorded no per-packet journal, "
                "so duplicates are not establishable in either direction."
            ),
        }
    )

    return (
        ReplaySpiAnalysis(
            spi=normalize_spi(spi.spi),
            packet_count=spi.packet_count,
            evidence_level=EVIDENCE_AGGREGATE,
            status=status,
            state=state,
            reason="; ".join(reason_parts) + ".",
            duplicate_sequences=None,
            backward_sequences=backward,
            sequence_gaps=None,
            highest_sequence=spi.highest_sequence,
            monotonic=None,
        ),
        evidence,
    )


def analyze_replay(
    observed: Optional[ObservedState],
    *,
    sequences: Optional[Dict[str, Sequence[Tuple[int, int]]]] = None,
    source: str = "observed-state snapshot",
) -> ReplayAnalysis:
    """Assess replay protection from the sequence information already collected.

    ``sequences`` optionally carries per-packet ``(sequence, timestamp_ns)``
    pairs keyed by canonical SPI token, straight from a recorded packet
    journal. When it is supplied the analysis is exact; when it is not, the
    analysis falls back to the state builder's aggregate and says so.
    """
    limitations: List[str] = [
        "A sequence gap is never treated as replay evidence: gaps are "
        "reported separately and contribute nothing to the status.",
        "A clean status means 'no anomaly was found in the evidence that "
        "exists', not 'replay is impossible'.",
        "This product produces no finding and no score; the risk engine is "
        "the only place a security judgement is made, and it fires only on "
        "OBSERVED duplicate-sequence evidence.",
    ]

    if observed is None or (observed.timestamp_ns == 0 and not observed.spis):
        return ReplayAnalysis(
            status=REPLAY_STATUS_INSUFFICIENT_DATA,
            reason=(
                "No ipsec_state_builder snapshot was supplied for this "
                "assessment, so no sequence information exists to analyse."
            ),
            source=source,
            state=STATE_NOT_AVAILABLE,
            per_spi=(),
            evidence=(),
            limitations=tuple(limitations),
        )

    sequences = sequences or {}
    per_spi: List[ReplaySpiAnalysis] = []
    evidence: List[Dict[str, Any]] = []
    journal_used = False

    for spi in observed.spis:
        events = sequences.get(normalize_spi(spi.spi))
        if events:
            journal_used = True
            analysis, entries = _per_packet_spi(spi, events)
        else:
            analysis, entries = _aggregate_spi(spi)
        per_spi.append(analysis)
        evidence.extend(entries)

    if not per_spi:
        status = REPLAY_STATUS_INSUFFICIENT_DATA
        reason = "The snapshot recorded no SPI, so there is no sequence to assess."
    else:
        status = max(
            (s.status for s in per_spi), key=lambda s: _STATUS_RANK[s]
        )
        observed_count = sum(
            1 for s in per_spi if s.status == REPLAY_STATUS_OBSERVED
        )
        insufficient = sum(
            1 for s in per_spi if s.status == REPLAY_STATUS_INSUFFICIENT_DATA
        )
        if status == REPLAY_STATUS_OBSERVED:
            reason = (
                f"{observed_count} of {len(per_spi)} security association(s) "
                "carry observed sequence anomalies in the recorded evidence; "
                "the status is OBSERVED because anomaly evidence exists, not "
                "because a gap was seen."
            )
        elif status == REPLAY_STATUS_INSUFFICIENT_DATA:
            reason = (
                f"{insufficient} of {len(per_spi)} security association(s) "
                "have no usable sequence information and none carried an "
                "anomaly, so the assessment is INSUFFICIENT_DATA rather than a "
                "clean bill of health."
            )
        else:
            reason = (
                f"All {len(per_spi)} security association(s) show normal "
                "monotonic progression with no duplicate and no backwards "
                "step in the evidence that exists."
            )

    duplicates = _combine(per_spi, "duplicate_sequences")
    backwards = _combine(per_spi, "backward_sequences")
    gaps = _combine(per_spi, "sequence_gaps")
    highests = [s.highest_sequence for s in per_spi if isinstance(s.highest_sequence, int)]

    # The product's own state is the least-established state it rests on: it
    # must never claim to be more established than the weakest association it
    # assessed.
    state = (
        min((s.state for s in per_spi), key=lambda name: _STATE_RANK[name])
        if per_spi
        else STATE_NOT_AVAILABLE
    )

    if not journal_used:
        limitations.append(
            "No per-packet journal was supplied for this capture, so the "
            "analysis used the state builder's aggregates: duplicates are "
            "unknown (reported as null) rather than zero."
        )

    return ReplayAnalysis(
        status=status,
        state=state,
        reason=reason,
        source=source,
        duplicate_sequences=duplicates,
        backward_sequences=backwards,
        sequence_gaps=gaps,
        highest_sequence=max(highests) if highests else None,
        per_spi=tuple(per_spi),
        evidence=tuple(evidence),
        limitations=tuple(limitations),
    )
