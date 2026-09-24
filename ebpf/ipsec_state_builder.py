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


class SpiState:
    """Observed state for a single ESP SPI."""

    __slots__ = (
        "spi", "direction", "first_seen_ns", "last_seen_ns", "packet_count",
        "first_sequence", "last_sequence", "highest_sequence",
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

    def observe(self, ts_ns: int, sequence: Optional[int], direction: Optional[str]) -> None:
        self.last_seen_ns = ts_ns
        self.packet_count += 1
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

        self._active: Optional[bool] = None

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
                     direction: Optional[str]) -> SpiState:
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
            if event.spi is not None:
                self._observe_spi(ts_ns, event.spi, event.seq, direction)
        elif etype == TYPE_AH:
            self.ah_seen = True
            self.last_ah_timestamp_ns = ts_ns
        elif etype == TYPE_IKE_NAT_T:
            self.ike_nat_t_seen = True
            self.last_ike_nat_t_timestamp_ns = ts_ns
        elif etype == TYPE_IKE:
            self.ike_seen = True
            self.last_ike_timestamp_ns = ts_ns

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
