"""100 ms userspace window aggregation for XDP IPsec packet events.

Responsibilities
----------------
This module is deliberately *only* aggregation.  It consumes lightweight
per-packet observations (the ``xdp_monitor_event`` records emitted by the XDP
program through the BPF ring buffer) and folds them into fixed-size time
windows.  It performs no detection, no ML inference, no risk scoring, no
expected-vs-observed correlation, no audit integration and no mitigation.
Packet observation/classification stays in XDP/eBPF.

It is written as a standalone, dependency-free component so the same window
processor can later be fed by two sources:

* LIVE   : XDP -> ring buffer -> common event -> this aggregator
* OFFLINE: PCAP -> existing parser -> common event -> this aggregator

Only the event-accepting core (:class:`WindowAggregator`) is transport
specific-free; the JSONL reader/writer is a thin CLI shell around it.

Input event schema
------------------
A canonical event is a JSON object per packet (JSONL)::

    {"ts": 10959125374087, "type": "ESP", "src": "192.168.100.1",
     "dst": "192.168.100.2", "proto": 50, "len": 154,
     "spi": 3311570186, "seq": 4}

``ts`` is the *kernel* timestamp from ``bpf_ktime_get_ns()`` (nanoseconds,
monotonic).  It is never replaced by userspace print/processing time.  ``type``
is one of ``IKE``, ``IKE-NAT-T``, ``ESP``, ``AH``, ``OTHER`` (numeric counter
values 1..5 are also accepted).  ``spi``/``seq`` are present for ESP/AH;
``sport``/``dport`` for IKE/IKE-NAT-T.  The aliases ``timestamp``/``length`` are
accepted for offline-parser friendliness.

Window boundaries
-----------------
Boundaries are deterministic and anchored to the timestamp origin::

    window_index = ts // window_ns
    window_start = window_index * window_ns
    window_end   = window_start + window_ns

so window *N* is ``[N*window_ns, (N+1)*window_ns)``.  Every packet falls in
exactly one window.  The window size is a single configurable parameter
(``WINDOW_SIZE_MS``, default 100 ms) -- it is not hard-coded at use sites.

Ordering
--------
Ring-buffer delivery is normally ordered, but minor reordering is tolerated:
up to ``WINDOW_LOOKBACK`` completed windows are held open, so a late packet
for a very recent window still lands in its own window.  A packet older than
the last emitted window cannot be re-aggregated; it is counted in
``events_dropped_late`` rather than silently mis-binned.

Empty windows
-------------
Window records are emitted for gaps too (``total_packets = 0`` and zeroed
packet-dependent fields) so later analysis can detect silence.  Emission is
bounded: windows are only flushed as the timestamp frontier advances, plus a
final flush at end-of-stream, so an idle stream produces nothing.

ESP sequence handling
---------------------
``first_esp_sequence``/``last_esp_sequence`` are the sequence numbers of the
first/last ESP packets (in arrival order) within the window.
``esp_sequence_delta`` is ``(last - first) mod 2**32`` so a single 32-bit
wraparound yields a small positive delta instead of a huge negative jump.  With
no ESP packets all three (and ``unique_esp_spi_count``) are 0.

Direction
---------
``a_to_b`` means the outer source is the gw-a WAN address; ``b_to_a`` means the
outer source is the gw-b WAN address.  The address->direction mapping is a
single configurable parameter (:data:`DEFAULT_ENDPOINTS`), never scattered
through the code.  Packets whose source is neither endpoint are still counted
in the totals and per-type counts but are not attributed to a direction.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field
from typing import Callable, Iterable, Iterator, Optional

# --------------------------------------------------------------------------- #
# Configuration (single source of truth -- change here / via CLI flag)
# --------------------------------------------------------------------------- #

#: Default aggregation window size in milliseconds.
WINDOW_SIZE_MS = 100

#: Number of most-recent completed windows kept open to absorb minor
#: out-of-order delivery before a window is flushed.
WINDOW_LOOKBACK = 2

#: Outer WAN endpoint -> direction label.  Configurable, not scattered.
A_TO_B = "A_TO_B"
B_TO_A = "B_TO_A"
DEFAULT_ENDPOINTS = {
    "192.168.100.1": A_TO_B,   # gw-a WAN
    "192.168.100.2": B_TO_A,   # gw-b WAN
}

#: Canonical event classification labels.
TYPE_IKE = "IKE"
TYPE_IKE_NAT_T = "IKE-NAT-T"
TYPE_ESP = "ESP"
TYPE_AH = "AH"
TYPE_OTHER = "OTHER"

_TYPE_BY_COUNTER = {
    1: TYPE_IKE,
    2: TYPE_IKE_NAT_T,
    3: TYPE_ESP,
    4: TYPE_AH,
    5: TYPE_OTHER,
}
_TYPE_ALIASES = {
    "IKE_NAT_T": TYPE_IKE_NAT_T,
    "IKE-NATT": TYPE_IKE_NAT_T,
    "IKENATT": TYPE_IKE_NAT_T,
    "IKE-NAT-T": TYPE_IKE_NAT_T,
}

_ESP_SEQ_MODULUS = 1 << 32


def normalize_event_type(value) -> str:
    """Coerce a wire/loader type value to a canonical label.

    Unknown values degrade to ``OTHER`` so a packet is never dropped just
    because a future classifier adds a class this aggregator does not know.
    """
    if isinstance(value, int):
        return _TYPE_BY_COUNTER.get(value, TYPE_OTHER)
    if isinstance(value, str):
        key = value.strip().upper()
        if key in _TYPE_ALIASES:
            return _TYPE_ALIASES[key]
        if key in (TYPE_IKE, TYPE_ESP, TYPE_AH, TYPE_OTHER):
            return key
    return TYPE_OTHER


def _as_int(value, default: int = 0) -> int:
    """Parse an int that may arrive as int, decimal string or hex string."""
    if value is None:
        return default
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return default
        try:
            return int(text, 0)
        except ValueError:
            return default
    return default


@dataclass(frozen=True)
class PacketEvent:
    """A single observed packet, normalized from the source event stream."""

    ts: int
    type: str
    src: str = ""
    dst: str = ""
    proto: int = 0
    length: int = 0
    sport: int = 0
    dport: int = 0
    spi: Optional[int] = None
    seq: Optional[int] = None

    @classmethod
    def from_dict(cls, record: dict) -> "PacketEvent":
        return cls(
            ts=_as_int(record.get("ts", record.get("timestamp"))),
            type=normalize_event_type(record.get("type")),
            src=str(record.get("src", record.get("source_ip", ""))),
            dst=str(record.get("dst", record.get("destination_ip", ""))),
            proto=_as_int(record.get("proto", record.get("ip_protocol"))),
            length=_as_int(record.get("len", record.get("length",
                                                       record.get("frame_length")))),
            sport=_as_int(record.get("sport", record.get("source_port"))),
            dport=_as_int(record.get("dport", record.get("destination_port"))),
            spi=_as_int(record["spi"]) if record.get("spi") is not None else None,
            seq=_as_int(record["seq"]) if record.get("seq") is not None else None,
        )


class WindowState:
    """Mutable accumulator for one fixed-size window."""

    __slots__ = (
        "index", "start_ns", "end_ns", "duration_ms",
        "total_packets", "ike_packets", "ike_nat_t_packets", "esp_packets",
        "ah_packets", "other_packets",
        "total_bytes", "_size_sum", "min_packet_size", "max_packet_size",
        "packets_a_to_b", "packets_b_to_a", "bytes_a_to_b", "bytes_b_to_a",
        "_spis", "first_esp_sequence", "last_esp_sequence",
    )

    def __init__(self, index: int, window_ns: int, duration_ms: int):
        self.index = index
        self.start_ns = index * window_ns
        self.end_ns = self.start_ns + window_ns
        self.duration_ms = duration_ms

        self.total_packets = 0
        self.ike_packets = 0
        self.ike_nat_t_packets = 0
        self.esp_packets = 0
        self.ah_packets = 0
        self.other_packets = 0

        self.total_bytes = 0
        self._size_sum = 0
        self.min_packet_size = None
        self.max_packet_size = None

        self.packets_a_to_b = 0
        self.packets_b_to_a = 0
        self.bytes_a_to_b = 0
        self.bytes_b_to_a = 0

        self._spis = set()
        self.first_esp_sequence = None
        self.last_esp_sequence = None

    def add(self, event: PacketEvent, endpoints: dict) -> None:
        """Fold one packet into this window. Called exactly once per event."""
        length = event.length
        self.total_packets += 1
        self.total_bytes += length

        if self.min_packet_size is None or length < self.min_packet_size:
            self.min_packet_size = length
        if self.max_packet_size is None or length > self.max_packet_size:
            self.max_packet_size = length
        # track sum separately to avoid floating point accumulation error
        self._size_sum += length

        etype = event.type
        if etype == TYPE_ESP:
            self.esp_packets += 1
        elif etype == TYPE_IKE_NAT_T:
            self.ike_nat_t_packets += 1
        elif etype == TYPE_IKE:
            self.ike_packets += 1
        elif etype == TYPE_AH:
            self.ah_packets += 1
        else:
            self.other_packets += 1

        direction = endpoints.get(event.src)
        if direction == A_TO_B:
            self.packets_a_to_b += 1
            self.bytes_a_to_b += length
        elif direction == B_TO_A:
            self.packets_b_to_a += 1
            self.bytes_b_to_a += length

        if etype == TYPE_ESP:
            if event.spi is not None:
                self._spis.add(event.spi)
            seq = event.seq if event.seq is not None else 0
            if self.first_esp_sequence is None:
                self.first_esp_sequence = seq
            self.last_esp_sequence = seq

    def to_dict(self) -> dict:
        """Materialize the window feature record (one JSON object)."""
        duration_s = self.duration_ms / 1000.0
        count = self.total_packets

        average_size = round(self._size_sum / count, 1) if count else 0.0

        if self.first_esp_sequence is None:
            unique_spis = 0
            first_seq = 0
            last_seq = 0
            seq_delta = 0
        else:
            unique_spis = len(self._spis)
            first_seq = self.first_esp_sequence
            last_seq = self.last_esp_sequence
            seq_delta = (last_seq - first_seq) % _ESP_SEQ_MODULUS

        return {
            "window_start_ns": self.start_ns,
            "window_end_ns": self.end_ns,
            "window_duration_ms": self.duration_ms,
            "total_packets": count,
            "ike_packets": self.ike_packets,
            "ike_nat_t_packets": self.ike_nat_t_packets,
            "esp_packets": self.esp_packets,
            "ah_packets": self.ah_packets,
            "other_packets": self.other_packets,
            "total_bytes": self.total_bytes,
            "min_packet_size": self.min_packet_size or 0,
            "max_packet_size": self.max_packet_size or 0,
            "average_packet_size": average_size,
            "packets_a_to_b": self.packets_a_to_b,
            "packets_b_to_a": self.packets_b_to_a,
            "bytes_a_to_b": self.bytes_a_to_b,
            "bytes_b_to_a": self.bytes_b_to_a,
            "unique_esp_spi_count": unique_spis,
            "first_esp_sequence": first_seq,
            "last_esp_sequence": last_seq,
            "esp_sequence_delta": seq_delta,
            "packets_per_second": round(count / duration_s, 1) if duration_s else 0.0,
            "bytes_per_second": round(self.total_bytes / duration_s, 1) if duration_s else 0.0,
        }


class WindowAggregator:
    """Fold a stream of :class:`PacketEvent` into fixed-size windows.

    Emitted records are handed to ``emit`` as dicts.  The class is transport
    agnostic: feed it from the live ring-buffer reader or from the offline
    parser, then call :meth:`finalize`.
    """

    def __init__(
        self,
        window_ms: int = WINDOW_SIZE_MS,
        endpoints: Optional[dict] = None,
        emit: Optional[Callable[[dict], None]] = None,
        lookback: int = WINDOW_LOOKBACK,
    ):
        if window_ms <= 0:
            raise ValueError("window_ms must be positive")
        self.window_ms = window_ms
        self.window_ns = window_ms * 1_000_000
        self.endpoints = dict(endpoints or DEFAULT_ENDPOINTS)
        self.lookback = max(0, lookback)
        self._emit = emit or (lambda record: None)

        self._open: dict[int, WindowState] = {}
        self._max_index: Optional[int] = None
        self._flushed_through: Optional[int] = None

        self.events_consumed = 0
        self.windows_emitted = 0
        self.events_dropped_late = 0

    # -- ingestion --------------------------------------------------------- #

    def accept(self, event: PacketEvent) -> None:
        self.events_consumed += 1
        index = event.ts // self.window_ns

        if self._flushed_through is not None and index <= self._flushed_through:
            # Older than the newest emitted window: cannot re-open it.
            self.events_dropped_late += 1
            return

        state = self._open.get(index)
        if state is None:
            state = WindowState(index, self.window_ns, self.window_ms)
            self._open[index] = state

        state.add(event, self.endpoints)

        if self._max_index is None or index > self._max_index:
            self._max_index = index

        self._flush_through(index - self.lookback)

    def accept_dict(self, record: dict) -> None:
        self.accept(PacketEvent.from_dict(record))

    def finalize(self) -> None:
        """Flush every still-open window (bounded end-of-stream behavior)."""
        if self._max_index is not None:
            self._flush_through(self._max_index)

    # -- flushing ---------------------------------------------------------- #

    def _flush_through(self, target: int) -> None:
        if target < 0 or self._max_index is None:
            return
        if self._flushed_through is not None and target <= self._flushed_through:
            return

        if self._flushed_through is None:
            if not self._open:
                return
            lower = min(self._open)
        else:
            lower = self._flushed_through + 1

        if target < lower:
            return

        for index in range(lower, target + 1):
            state = self._open.pop(index, None)
            if state is None:
                state = WindowState(index, self.window_ns, self.window_ms)
            self._emit(state.to_dict())
            self.windows_emitted += 1

        self._flushed_through = target


def aggregate(
    events: Iterable[PacketEvent],
    window_ms: int = WINDOW_SIZE_MS,
    endpoints: Optional[dict] = None,
    lookback: int = WINDOW_LOOKBACK,
) -> list:
    """Pure helper: aggregate an iterable of events into a list of records."""
    records = []
    agg = WindowAggregator(window_ms=window_ms, endpoints=endpoints,
                           emit=records.append, lookback=lookback)
    for event in events:
        agg.accept(event)
    agg.finalize()
    return records


def iter_jsonl_events(lines: Iterable[str]) -> Iterator[PacketEvent]:
    """Yield events from JSONL lines, skipping blanks/comments/malformed."""
    for line in lines:
        text = line.strip()
        if not text or text.startswith("#"):
            continue
        try:
            record = json.loads(text)
        except json.JSONDecodeError:
            continue
        if isinstance(record, dict):
            yield PacketEvent.from_dict(record)


def _default_emit(stream):
    def emit(record: dict) -> None:
        stream.write(json.dumps(record, separators=(",", ":")) + "\n")
        stream.flush()
    return emit


def main(argv: Optional[list] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Aggregate XDP packet events into fixed windows (JSONL)."
    )
    parser.add_argument("--window-ms", type=int, default=WINDOW_SIZE_MS,
                        help="window size in milliseconds (default: %(default)s)")
    parser.add_argument("--input", default="-",
                        help="JSONL event input file ('-' = stdin)")
    parser.add_argument("--output", default="-",
                        help="JSONL window output file ('-' = stdout)")
    parser.add_argument("--lookback", type=int, default=WINDOW_LOOKBACK,
                        help="completed windows kept open for reordering")
    parser.add_argument("--endpoints", default=None,
                        help="JSON object mapping outer source IP -> direction")
    args = parser.parse_args(argv)

    endpoints = json.loads(args.endpoints) if args.endpoints else None

    in_stream = sys.stdin if args.input == "-" else open(args.input, "r")
    out_stream = sys.stdout if args.output == "-" else open(args.output, "w")

    agg = WindowAggregator(
        window_ms=args.window_ms,
        endpoints=endpoints,
        emit=_default_emit(out_stream),
        lookback=args.lookback,
    )

    try:
        for event in iter_jsonl_events(in_stream):
            agg.accept(event)
        agg.finalize()
    finally:
        if args.input != "-":
            in_stream.close()
        if args.output != "-":
            out_stream.close()
        print(
            "window-aggregator: events_consumed=%d windows_emitted=%d "
            "events_dropped_late=%d window_ms=%d"
            % (agg.events_consumed, agg.windows_emitted,
               agg.events_dropped_late, agg.window_ms),
            file=sys.stderr,
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
