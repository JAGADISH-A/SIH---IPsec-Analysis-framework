"""IPsec observed-state construction from XDP packet events / 100 ms windows.

This layer turns short-term traffic observations into a continuously maintained
representation of the *observed* IPsec tunnel state.  It is the last stage of
the observation pipeline and the input to a future expected-vs-observed layer.

What it is
----------
* state construction only: endpoint identity, traffic counters, observed
  protocol activity, per-SPI ESP state and observed state transitions.

What it is NOT (deliberately out of scope)
------------------------------------------
* no ML, anomaly detection, classification, risk scoring or XAI
* no expected-vs-observed correlation
* no automatic response, mitigation, policy enforcement or blocking
* no audit/backend/dashboard integration
* no packet payload parsing, ESP decryption or IKE payload parsing

Terminology
-----------
Everything here is *observed*.  Seeing IKE traffic does **not** prove an IKE SA
is established, so this module never emits an ``ike_sa_established`` field; it
records ``ike_seen`` / ``observed_ike_activity``.  Likewise it never infers
cryptographic algorithms, encryption strength or authentication status.

Input sources
-------------
The 100 ms window record only carries ``unique_esp_spi_count`` -- it has no SPI
values, no per-SPI packet counts and no per-SPI sequence numbers.  Exact per-SPI
state therefore **requires the packet-event stream**.  This module accepts both:

* :meth:`IPsecStateBuilder.consume_event` -- authoritative; drives the
  aggregate counters *and* the per-SPI ESP state (SPI, direction, timestamps,
  packet count, sequence state).
* :meth:`IPsecStateBuilder.consume_window` -- drives the aggregate counters and
  observed-activity flags only.  It deliberately does **not** fabricate per-SPI
  data from ``unique_esp_spi_count``; the SPI list stays untouched.

Both feed the same internal update routines, so there is no duplicate logic.
Do not feed the same underlying packets to one builder as both events and
windows -- the aggregate counters would double count.  Use one source per
builder instance (live uses events for exact SPI state; a window-only builder
is also valid and is covered by the tests).

Timestamps are the kernel ``bpf_ktime_get_ns()`` nanoseconds carried by the
event stream; windows only expose their boundaries, so window-sourced
``last_*`` timestamps use ``window_end_ns`` as a documented approximation.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Callable, Iterable, Optional

from ebpf.xdp_window_aggregator import (
    A_TO_B,
    B_TO_A,
    DEFAULT_ENDPOINTS,
    PacketEvent,
    TYPE_AH,
    TYPE_ESP,
    TYPE_IKE,
    TYPE_IKE_NAT_T,
    iter_jsonl_events,
)

# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #

#: A tunnel is considered recently active if a packet was observed within this
#: many milliseconds.  Configurable; never hard-coded at use sites.
STATE_ACTIVE_TIMEOUT_MS = 1000

#: ESP/AH sequence numbers are 32-bit; wraparound is handled modulo this.
SEQUENCE_MODULUS = 1 << 32

#: Observed state-transition labels (descriptions, never verdicts).
TRANSITION_TRAFFIC_OBSERVED = "IPSEC_TRAFFIC_OBSERVED"
TRANSITION_SPI_OBSERVED = "SPI_OBSERVED"
TRANSITION_ACTIVE = "ACTIVE"
TRANSITION_INACTIVE = "INACTIVE"

# Protocol-type labels that must never appear as inferred facts.
_FORBIDDEN_INFERENCE_KEYS = (
    "ike_sa_established", "sa_established", "algorithm", "cipher",
    "encryption", "authentication", "mitm",
)


def _direction_for_src(src: str, endpoints: dict) -> Optional[str]:
    return endpoints.get(src)


def _hexspi(spi: int) -> str:
    return "0x%08x" % (spi & 0xFFFFFFFF)


def endpoint_pair(src: Optional[str], dst: Optional[str]) -> tuple:
    """Order-independent outer endpoint pair, or ``(src, dst)`` when partial.

    An SA is bidirectional, so its outer endpoints are an unordered pair.  This
    is the same ordering rule as
    :func:`correlation.models.sa_identity.endpoint_pair`, kept local so the
    state engine stays free of correlation imports.
    """
    if not src or not dst:
        return (src or "", dst or "")
    return (src, dst) if src <= dst else (dst, src)


class SpiState:
    """Observed state for a single ESP SPI."""

    __slots__ = (
        "spi", "direction", "first_seen_ns", "last_seen_ns", "packet_count",
        "first_sequence", "last_sequence", "highest_sequence",
        "outer_src", "outer_dst", "packet_count_esp", "packet_count_other",
        "_pairs", "_identity", "_identity_state", "_identity_reason",
        "_identity_candidates",
    )

    def __init__(self, spi: int, direction: Optional[str], first_seen_ns: int):
        self.spi = spi
        self.direction = direction
        self.first_seen_ns = first_seen_ns
        self.last_seen_ns = first_seen_ns
        self.packet_count = 0
        self.first_sequence: Optional[int] = None
        self.last_sequence: Optional[int] = None
        self.highest_sequence: Optional[int] = None
        # Outer endpoint evidence for this SPI.  Multi-SA capable: a gateway
        # may hold several SAs at once, so the peer is observed per SPI rather
        # than assumed to be the single ``endpoint_b``.
        self.outer_src: Optional[str] = None
        self.outer_dst: Optional[str] = None
        self.packet_count_esp = 0
        self.packet_count_other = 0
        self._pairs: Optional[set] = None
        self._identity: Optional[tuple] = None
        self._identity_state: Optional[str] = None
        self._identity_reason: Optional[str] = None
        self._identity_candidates: tuple = ()

    def observe_endpoint(self, src: Optional[str], dst: Optional[str]) -> None:
        """Record the outer addresses this SPI was seen on.

        A SPI is only unique per destination, so the peer is evidence, not an
        assumption.  Every distinct outer pair is remembered, so a SPI observed
        on two peers can be reported as a collision instead of being smoothed
        over into one false tunnel.
        """
        if not src or not dst:
            return
        if self._pairs is None:
            self._pairs = set()
        self._pairs.add(endpoint_pair(src, dst))
        if self.outer_src is None:
            self.outer_src = src
            self.outer_dst = dst

    @property
    def endpoint_conflict(self) -> bool:
        """True when this SPI was observed on more than one outer pair."""
        return self._pairs is not None and len(self._pairs) > 1

    @property
    def observed_endpoint_pairs(self) -> tuple:
        """Outer endpoint pairs this SPI has been seen on (observed only)."""
        if self._pairs is None:
            return ()
        return tuple(sorted(self._pairs))

    def observe(self, ts_ns: int, sequence: Optional[int], direction: Optional[str]) -> None:
        self.last_seen_ns = ts_ns
        self.packet_count += 1
        self.packet_count_esp += 1
        if self.direction is None and direction is not None:
            self.direction = direction
        if sequence is not None:
            seq = sequence & 0xFFFFFFFF
            if self.first_sequence is None:
                self.first_sequence = seq
            self.last_sequence = seq
            if self.highest_sequence is None or seq > self.highest_sequence:
                self.highest_sequence = seq

    def snapshot(self, now_ns: int, active_timeout_ns: int) -> dict:
        if self.first_sequence is None:
            seq_delta = 0
        else:
            # Modular difference: a single 32-bit wraparound is a small step,
            # not a huge negative jump.
            seq_delta = (self.last_sequence - self.first_sequence) % SEQUENCE_MODULUS
        active = (now_ns - self.last_seen_ns) <= active_timeout_ns
        return {
            "spi": _hexspi(self.spi),
            "direction": self.direction,
            "active": active,
            "first_seen_ns": self.first_seen_ns,
            "last_seen_ns": self.last_seen_ns,
            "packet_count": self.packet_count,
            "first_sequence": self.first_sequence if self.first_sequence is not None else 0,
            "last_sequence": self.last_sequence if self.last_sequence is not None else 0,
            "highest_sequence": self.highest_sequence if self.highest_sequence is not None else 0,
            "sequence_delta": seq_delta,
        }

    def sa_snapshot(self, active: bool = False) -> dict:
        """Per-SA view of this SPI's observed state.

        The correlation identity tokens (``sa_id`` / ``sa_group_id``) are the ones
        assigned by :mod:`correlation.sa_correlation`.  The state engine only
        *records* the token it was handed; it never derives identity itself,
        because the state engine sees raw packets while the correlation contract
        owns the naming rules.

        An SPI whose SA is ``AMBIGUOUS`` or ``UNKNOWN`` appears here too, with
        the reason and candidate set that produced it, so unattributable traffic
        is visible rather than absent.
        """
        pairs = self.observed_endpoint_pairs
        return {
            "sa_id": self._identity[0] if self._identity else None,
            "sa_group_id": self._identity[1] if self._identity else None,
            "sa_identity_state": self._identity_state,
            "sa_identity_reason": self._identity_reason,
            "sa_candidates": list(self._identity_candidates),
            "spi": _hexspi(self.spi),
            "direction": self.direction,
            "outer_src": self.outer_src,
            "outer_dst": self.outer_dst,
            "peer": pairs[0][1] if len(pairs) == 1 else None,
            "endpoint_conflict": self.endpoint_conflict,
            "packet_count": self.packet_count,
            "first_seen_ns": self.first_seen_ns,
            "last_seen_ns": self.last_seen_ns,
            "active": active,
        }

    def assign_identity(self, sa_id: Optional[str], sa_group_id: Optional[str]) -> None:
        """Attach the correlation identity for this SPI's observed state."""
        self._identity = (sa_id, sa_group_id)
        self._identity_state = "RESOLVED"
        self._identity_reason = None
        self._identity_candidates: tuple = ()

    def assign_uncertain_identity(self, state: str, reason: Optional[str],
                                  candidates: Optional[Iterable[str]] = None) -> None:
        """Record that this SPI's SA is ``AMBIGUOUS`` or ``UNKNOWN``.

        Stored rather than skipped: an analyst must be able to see that traffic
        was observed and *why* it could not be attributed, instead of finding a
        silently missing SA.  No id is invented in this state.
        """
        self._identity = (None, None)
        self._identity_state = state
        self._identity_reason = reason
        self._identity_candidates = tuple(sorted(candidates or ()))


class IPsecStateBuilder:
    """Maintain observed IPsec tunnel state from events and/or windows.

    The state model is independent of CLI and transport.  Feed recorded JSONL
    events (or window records) later without any live XDP process.
    """

    def __init__(
        self,
        endpoints: Optional[dict] = None,
        active_timeout_ms: int = STATE_ACTIVE_TIMEOUT_MS,
    ):
        if active_timeout_ms <= 0:
            raise ValueError("active_timeout_ms must be positive")
        self.endpoints = dict(endpoints or DEFAULT_ENDPOINTS)
        self.active_timeout_ms = active_timeout_ms
        self.active_timeout_ns = active_timeout_ms * 1_000_000
        self.reset()

    # -- endpoints --------------------------------------------------------- #

    @property
    def endpoint_a(self) -> Optional[str]:
        for addr, direction in self.endpoints.items():
            if direction == A_TO_B:
                return addr
        return None

    @property
    def endpoint_b(self) -> Optional[str]:
        for addr, direction in self.endpoints.items():
            if direction == B_TO_A:
                return addr
        return None

    # -- lifecycle --------------------------------------------------------- #

    def reset(self) -> None:
        self.observation_start_ns: Optional[int] = None
        self.last_packet_timestamp_ns: Optional[int] = None

        self.packets_seen = 0
        self.bytes_seen = 0
        self.packets_a_to_b = 0
        self.packets_b_to_a = 0
        self.bytes_a_to_b = 0
        self.bytes_b_to_a = 0

        self.ike_seen = False
        self.ike_nat_t_seen = False
        self.esp_seen = False
        self.ah_seen = False

        self.last_ike_timestamp_ns: Optional[int] = None
        self.last_ike_nat_t_timestamp_ns: Optional[int] = None
        self.last_esp_timestamp_ns: Optional[int] = None
        self.last_ah_timestamp_ns: Optional[int] = None

        self.spis: dict[int, SpiState] = {}
        self.transitions: list[dict] = []
        # Multi-SA evidence.  ``spi_less_esp_packets`` counts ESP frames whose
        # SPI the observer could not read: real traffic that cannot be pinned to
        # one SA, counted rather than dropped or guessed.
        self.spi_less_esp_packets = 0
        self._outer_pairs: dict[tuple, dict] = {}

        self._active: Optional[bool] = None

    # -- multi-SA evidence -------------------------------------------------- #

    def observe_outer_pair(self, src: Optional[str], dst: Optional[str]) -> None:
        """Track an observed outer endpoint pair independently of any SPI.

        This is what lets a snapshot describe several simultaneous SAs even when
        some of their frames carry no SPI.  Pairs are observed evidence only; no
        pair is ever derived from expected configuration.
        """
        if not src and not dst:
            return
        key = endpoint_pair(src, dst)
        entry = self._outer_pairs.get(key)
        if entry is None:
            entry = {
                "outer_src": src or None,
                "outer_dst": dst or None,
                "packet_count": 0,
                "esp_packets": 0,
                "ike_packets": 0,
                "ah_packets": 0,
                "first_seen_ns": None,
                "last_seen_ns": None,
                "spis": set(),
            }
            self._outer_pairs[key] = entry
        entry["packet_count"] += 1
        if entry["first_seen_ns"] is None:
            entry["first_seen_ns"] = self.last_packet_timestamp_ns
        self._outer_pairs[key]["last_seen_ns"] = self.last_packet_timestamp_ns

    def assign_sa_identities(self, assignments: dict) -> int:
        """Attach correlation identities to the observed SPIs.

        ``assignments`` maps the canonical hex SPI string to either

        * a ``(sa_id, sa_group_id)`` pair for a resolved SA, or
        * a ready ``(state, reason, candidates)`` triple for an uncertain one.

        Both forms exist so uncertainty reaches this snapshot: an ``AMBIGUOUS``
        or ``UNKNOWN`` SPI is recorded with the reason that produced it rather
        than being dropped for lack of an id.  Returns how many SPIs were
        labelled.  The state engine records the tokens it is given and derives
        none of them.
        """
        labelled = 0
        for spi_value, state in self.spis.items():
            token = _hexspi(spi_value)
            if token not in assignments:
                continue
            value = assignments[token]
            if len(value) == 2:
                state.assign_identity(value[0], value[1])
            else:
                state.assign_uncertain_identity(*value)
            labelled += 1
        return labelled

    def sa_snapshots(self, now_ns: Optional[int] = None) -> list[dict]:
        """Observed state grouped by SA, one entry per SPI with an identity.

        Backward-compatible by construction: this is a *new* view.  The existing
        top-level snapshot keys, including the flat ``spis`` list, are unchanged,
        so every current consumer keeps working.
        """
        if now_ns is None:
            now_ns = self.last_packet_timestamp_ns or 0
        entries: list[dict] = []
        for spi_value in sorted(self.spis):
            state = self.spis[spi_value]
            if not state._identity:
                continue
            active = (now_ns - state.last_seen_ns) <= self.active_timeout_ns
            entries.append(state.sa_snapshot(active=active))
        return entries

    def sa_group_snapshots(self) -> list[dict]:
        """One entry per distinct SA/tunnel observed, with its SPIs.

        A gateway with two simultaneous SAs yields two entries here, both of
        which may be riding the same UDP/4500 transport.
        """
        groups: dict[str, dict] = {}
        for spi_value in sorted(self.spis):
            state = self.spis[spi_value]
            if not state._identity:
                continue
            sa_id, group_id = state._identity
            entry = groups.setdefault(group_id or sa_id or "", {
                "sa_group_id": group_id,
                "sa_ids": [],
                "spis": [],
                "packet_count": 0,
                "peer": state.observed_endpoint_pairs[0][1]
                        if len(state.observed_endpoint_pairs) == 1 else None,
                "endpoint_conflict": False,
            })
            if sa_id:
                entry["sa_ids"].append(sa_id)
            entry["spis"].append(_hexspi(spi_value))
            entry["packet_count"] += state.packet_count
            entry["endpoint_conflict"] = (
                entry["endpoint_conflict"] or state.endpoint_conflict
            )
        return [groups[key] for key in sorted(groups)]

    # -- internal update helpers ------------------------------------------- #

    def _record_traffic(self, ts_ns: int) -> None:
        if self.observation_start_ns is None:
            self.observation_start_ns = ts_ns
        if self.last_packet_timestamp_ns is None:
            self.transitions.append({
                "timestamp_ns": ts_ns,
                "type": TRANSITION_TRAFFIC_OBSERVED,
                "endpoints": {"a": self.endpoint_a, "b": self.endpoint_b},
            })

    def _update_counters(self, ts_ns: int, length: int, direction: Optional[str]) -> None:
        self._record_traffic(ts_ns)
        self.last_packet_timestamp_ns = ts_ns
        self.packets_seen += 1
        self.bytes_seen += length
        if direction == A_TO_B:
            self.packets_a_to_b += 1
            self.bytes_a_to_b += length
        elif direction == B_TO_A:
            self.packets_b_to_a += 1
            self.bytes_b_to_a += length

    def _observe_spi(self, ts_ns: int, spi: int, sequence: Optional[int],
                     direction: Optional[str], src: Optional[str] = None,
                     dst: Optional[str] = None) -> SpiState:
        state = self.spis.get(spi)
        if state is None:
            state = SpiState(spi, direction, ts_ns)
            self.spis[spi] = state
            self.transitions.append({
                "timestamp_ns": ts_ns,
                "type": TRANSITION_SPI_OBSERVED,
                "spi": _hexspi(spi),
                "direction": direction,
                "known_spis": [_hexspi(s) for s in self.spis],
            })
        state.observe(ts_ns, sequence, direction)
        state.observe_endpoint(src, dst)
        return state

    # -- ingestion: packet events (exact) ---------------------------------- #

    def consume_event(self, event: PacketEvent) -> None:
        ts_ns = event.ts
        direction = _direction_for_src(event.src, self.endpoints)

        self._update_counters(ts_ns, event.length, direction)

        etype = event.type
        if etype == TYPE_ESP:
            self.esp_seen = True
            self.last_esp_timestamp_ns = ts_ns
            self.observe_outer_pair(event.src, event.dst)
            pair_entry = self._outer_pairs.get(endpoint_pair(event.src, event.dst))
            if pair_entry is not None:
                pair_entry["esp_packets"] += 1
            # SPI 0 is not "SPI zero": the parity harness emits it because the
            # v2 feature vector never reads SPI, and XDP reports it when the
            # parse failed.  Treating it as an SA would invent one.
            if event.spi is not None and int(event.spi) > 0:
                self._observe_spi(ts_ns, event.spi, event.seq, direction,
                                  event.src, event.dst)
            else:
                # ESP with no SPI still proves ESP traffic on this gateway; the
                # per-SPI list stays untouched rather than gaining a fake SPI.
                self.spi_less_esp_packets += 1
        elif etype == TYPE_AH:
            self.ah_seen = True
            self.last_ah_timestamp_ns = ts_ns
            self.observe_outer_pair(event.src, event.dst)
            pair_entry = self._outer_pairs.get(endpoint_pair(event.src, event.dst))
            if pair_entry is not None:
                pair_entry["ah_packets"] += 1
        elif etype == TYPE_IKE_NAT_T:
            self.ike_nat_t_seen = True
            self.last_ike_nat_t_timestamp_ns = ts_ns
            self.observe_outer_pair(event.src, event.dst)
            pair_entry = self._outer_pairs.get(endpoint_pair(event.src, event.dst))
            if pair_entry is not None:
                pair_entry["ike_packets"] += 1
        elif etype == TYPE_IKE:
            self.ike_seen = True
            self.last_ike_timestamp_ns = ts_ns
            self.observe_outer_pair(event.src, event.dst)
            pair_entry = self._outer_pairs.get(endpoint_pair(event.src, event.dst))
            if pair_entry is not None:
                pair_entry["ike_packets"] += 1

    # -- ingestion: 100 ms windows (aggregate only) ------------------------ #

    def consume_window(self, window: dict) -> None:
        ts_ns = _int_field(window, "window_end_ns",
                           _int_field(window, "window_start_ns", 0))
        start_ns = _int_field(window, "window_start_ns", ts_ns)
        total_packets = _int_field(window, "total_packets", 0)
        total_bytes = _int_field(window, "total_bytes", 0)

        if total_packets <= 0:
            return

        self._record_traffic(start_ns)
        if self.last_packet_timestamp_ns is None or ts_ns > self.last_packet_timestamp_ns:
            self.last_packet_timestamp_ns = ts_ns

        self.packets_seen += total_packets
        self.bytes_seen += total_bytes
        self.packets_a_to_b += _int_field(window, "packets_a_to_b", 0)
        self.packets_b_to_a += _int_field(window, "packets_b_to_a", 0)
        self.bytes_a_to_b += _int_field(window, "bytes_a_to_b", 0)
        self.bytes_b_to_a += _int_field(window, "bytes_b_to_a", 0)

        if _int_field(window, "esp_packets", 0) > 0:
            self.esp_seen = True
            self.last_esp_timestamp_ns = ts_ns
        if _int_field(window, "ah_packets", 0) > 0:
            self.ah_seen = True
            self.last_ah_timestamp_ns = ts_ns
        if _int_field(window, "ike_packets", 0) > 0:
            self.ike_seen = True
            self.last_ike_timestamp_ns = ts_ns
        if _int_field(window, "ike_nat_t_packets", 0) > 0:
            self.ike_nat_t_seen = True
            self.last_ike_nat_t_timestamp_ns = ts_ns

        # NOTE: per-SPI state is intentionally NOT derived from the window's
        # unique_esp_spi_count; that aggregate cannot reconstruct SPI values,
        # per-SPI counts or sequences.  Feed the event stream for exact SPI
        # state, or leave the SPI list empty/unassigned for window-only input.

    def consume_event_dict(self, record: dict) -> None:
        self.consume_event(PacketEvent.from_dict(record))

    # -- output ------------------------------------------------------------ #

    def is_active(self, now_ns: Optional[int] = None) -> bool:
        if self.last_packet_timestamp_ns is None:
            return False
        if now_ns is None:
            now_ns = self.last_packet_timestamp_ns
        return (now_ns - self.last_packet_timestamp_ns) <= self.active_timeout_ns

    def snapshot(self, now_ns: Optional[int] = None) -> dict:
        if now_ns is None:
            if self.last_packet_timestamp_ns is not None:
                now_ns = self.last_packet_timestamp_ns
            elif self.observation_start_ns is not None:
                now_ns = self.observation_start_ns
            else:
                now_ns = 0

        active = self.is_active(now_ns)

        # Record ACTIVE/INACTIVE as an observed transition (never an alert).
        if self.last_packet_timestamp_ns is not None and active != self._active:
            self.transitions.append({
                "timestamp_ns": now_ns,
                "type": TRANSITION_ACTIVE if active else TRANSITION_INACTIVE,
            })
            self._active = active

        spis = [
            self.spis[spi].snapshot(now_ns, self.active_timeout_ns)
            for spi in sorted(self.spis)
        ]

        record = {
            "timestamp_ns": now_ns,
            "endpoints": {"a": self.endpoint_a, "b": self.endpoint_b},
            "tunnel_seen": self.observation_start_ns is not None,
            "active": active,
            "observation_start_ns": self.observation_start_ns,
            "last_packet_timestamp_ns": self.last_packet_timestamp_ns,
            "active_timeout_ms": self.active_timeout_ms,
            "packets_seen": self.packets_seen,
            "bytes_seen": self.bytes_seen,
            "packets_a_to_b": self.packets_a_to_b,
            "packets_b_to_a": self.packets_b_to_a,
            "bytes_a_to_b": self.bytes_a_to_b,
            "bytes_b_to_a": self.bytes_b_to_a,
            "ike_seen": self.ike_seen,
            "ike_nat_t_seen": self.ike_nat_t_seen,
            "esp_seen": self.esp_seen,
            "ah_seen": self.ah_seen,
            "observed_ike_activity": self.ike_seen or self.ike_nat_t_seen,
            "last_ike_timestamp_ns": self.last_ike_timestamp_ns,
            "last_ike_nat_t_timestamp_ns": self.last_ike_nat_t_timestamp_ns,
            "last_esp_timestamp_ns": self.last_esp_timestamp_ns,
            "last_ah_timestamp_ns": self.last_ah_timestamp_ns,
            "spis": spis,
            "transitions": list(self.transitions),
            # -- multi-SA views (additive; every key above is unchanged) -----
            "sa_snapshots": self.sa_snapshots(now_ns),
            "sa_groups": self.sa_group_snapshots(),
            "spi_less_esp_packets": self.spi_less_esp_packets,
            "outer_endpoint_pairs": sorted(
                key for key in self._outer_pairs if any(key)
            ),
        }
        return record


def _int_field(record: dict, key: str, default: int = 0) -> int:
    value = record.get(key, default)
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value, 0)
        except ValueError:
            return default
    return default


# --------------------------------------------------------------------------- #
# CLI (thin shell; the state model above is transport independent)
# --------------------------------------------------------------------------- #

def _iter_jsonl_dicts(lines: Iterable[str]):
    for line in lines:
        text = line.strip()
        if not text or text.startswith("#"):
            continue
        try:
            record = json.loads(text)
        except json.JSONDecodeError:
            continue
        if isinstance(record, dict):
            yield record


def main(argv: Optional[list] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Build observed IPsec state from events and/or windows.")
    parser.add_argument("--events", default=None,
                        help="JSONL packet events ('-' = stdin)")
    parser.add_argument("--windows", default=None,
                        help="JSONL 100 ms window records")
    parser.add_argument("--output", default="-",
                        help="JSONL state snapshots ('-' = stdout)")
    parser.add_argument("--emit-every", type=int, default=0,
                        help="also emit a snapshot every N events (0 = final only)")
    parser.add_argument("--active-timeout-ms", type=int,
                        default=STATE_ACTIVE_TIMEOUT_MS)
    parser.add_argument("--endpoints", default=None,
                        help="JSON object mapping outer source IP -> A_TO_B/B_TO_A")
    args = parser.parse_args(argv)

    endpoints = json.loads(args.endpoints) if args.endpoints else None
    builder = IPsecStateBuilder(endpoints=endpoints,
                                active_timeout_ms=args.active_timeout_ms)
    out = sys.stdout if args.output == "-" else open(args.output, "w")
    emitted = 0

    def emit(now_ns=None):
        nonlocal emitted
        out.write(json.dumps(builder.snapshot(now_ns=now_ns),
                             separators=(",", ":")) + "\n")
        out.flush()
        emitted += 1

    try:
        if args.events is not None:
            in_stream = sys.stdin if args.events == "-" else open(args.events)
            try:
                n = 0
                for record in _iter_jsonl_dicts(in_stream):
                    builder.consume_event_dict(record)
                    n += 1
                    if args.emit_every and n % args.emit_every == 0:
                        emit()
            finally:
                if args.events != "-":
                    in_stream.close()

        if args.windows is not None:
            with open(args.windows) as win_stream:
                for record in _iter_jsonl_dicts(win_stream):
                    builder.consume_window(record)

        emit()
    finally:
        if args.output != "-":
            out.close()

    print("ipsec-state-builder: snapshots_emitted=%d packets_seen=%d spis=%d"
          % (emitted, builder.packets_seen, len(builder.spis)), file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
