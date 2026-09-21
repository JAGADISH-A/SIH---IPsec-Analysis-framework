"""100 ms windowing engine (deterministic) + epoch emission policy.

Windows are aligned to the timestamp origin exactly like the authoritative
aggregator::

    window_index = ts // window_ns
    window_start = index * window_ns
    window_end   = window_start + window_ns

Contract:

* every event falls into EXACTLY one window (index by its own timestamp in ns);
* minor out-of-order delivery is absorbed by a configurable lookback: a late
  packet for a window not yet flushed still lands in its OWN window;
* a packet older than the last flushed window is counted as ``late`` (never
  silently mis-binned, never fabricated);
* empty windows MAY be emitted (``emit_empty=True``) so downstream can detect
  silence — an empty record is real observation ("no traffic"), not invention;
* nothing here computes features/ML/risk; it is aggregation only.

Epoch / periodic emission (``EmissionPolicy``) supports:

    emit every N windows
    emit every N ms
    flush on shutdown
    flush on experiment completion

All behaviour is explicit configuration.
"""

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

CLASS_ESP = "ESP"
CLASS_IKE = "IKE"
CLASS_IKE_NAT_T = "IKE-NAT-T"
CLASS_AH = "AH"
CLASS_OTHER = "OTHER"

WINDOW_SIZE_MS_DEFAULT = 100
WINDOW_LOOKBACK_DEFAULT = 2

_SPI_MOD = 1 << 32


def _as_int(value: Any, default: int = 0) -> int:
    if value is None or isinstance(value, bool):
        return default
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value, 0)
        except ValueError:
            return default
    return default


@dataclass(frozen=True)
class WindowRecord:
    """One immutable 100 ms window record (aggregation only)."""

    window_index: int
    window_start_ns: int
    window_end_ns: int
    empty: bool
    total_packets: int
    esp_packets: int
    ike_packets: int
    ike_nat_t_packets: int
    ah_packets: int
    other_packets: int
    unique_esp_spi_count: int = 0
    first_esp_sequence: Optional[int] = None
    last_esp_sequence: Optional[int] = None
    esp_sequence_delta: Optional[int] = None
    bytes_seen: int = 0
    bytes_a_to_b: int = 0
    bytes_b_to_a: int = 0
    packets_a_to_b: int = 0
    packets_b_to_a: int = 0
    events: Tuple[Dict[str, Any], ...] = field(default_factory=tuple)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "window_index": self.window_index,
            "window_start_ns": self.window_start_ns,
            "window_end_ns": self.window_end_ns,
            "empty": self.empty,
            "total_packets": self.total_packets,
            "esp_packets": self.esp_packets,
            "ike_packets": self.ike_packets,
            "ike_nat_t_packets": self.ike_nat_t_packets,
            "ah_packets": self.ah_packets,
            "other_packets": self.other_packets,
            "unique_esp_spi_count": self.unique_esp_spi_count,
            "first_esp_sequence": self.first_esp_sequence,
            "last_esp_sequence": self.last_esp_sequence,
            "esp_sequence_delta": self.esp_sequence_delta,
            "bytes_seen": self.bytes_seen,
            "bytes_a_to_b": self.bytes_a_to_b,
            "bytes_b_to_a": self.bytes_b_to_a,
            "packets_a_to_b": self.packets_a_to_b,
            "packets_b_to_a": self.packets_b_to_a,
            "events": [dict(e) for e in self.events],
        }


@dataclass(frozen=True)
class EmissionPolicy:
    """Explicit epoch / periodic emission configuration."""

    emit_every_windows: int = 1
    emit_every_ms: Optional[int] = None
    flush_on_shutdown: bool = True
    flush_on_experiment_completion: bool = True
    emit_empty: bool = True

    def __post_init__(self) -> None:
        if self.emit_every_windows < 1:
            raise ValueError("emit_every_windows must be >= 1")


class _WindowAccumulator:
    """Mutable accumulator for one window (internal)."""

    __slots__ = (
        "index", "start_ns", "end_ns", "events", "total", "esp", "ike",
        "ike_nat_t", "ah", "other", "bytes", "bytes_a_to_b", "bytes_b_to_a",
        "packets_a_to_b", "packets_b_to_a", "first_seq", "last_seq", "spis",
    )

    def __init__(self, index: int, start_ns: int, end_ns: int) -> None:
        self.index = index
        self.start_ns = start_ns
        self.end_ns = end_ns
        self.events: List[Dict[str, Any]] = []
        self.total = 0
        self.esp = 0
        self.ike = 0
        self.ike_nat_t = 0
        self.ah = 0
        self.other = 0
        self.bytes = 0
        self.bytes_a_to_b = 0
        self.bytes_b_to_a = 0
        self.packets_a_to_b = 0
        self.packets_b_to_a = 0
        self.first_seq: Optional[int] = None
        self.last_seq: Optional[int] = None
        self.spis: set = set()

    def is_empty(self) -> bool:
        return self.total == 0

    def snapshot(self) -> WindowRecord:
        first, last = self.first_seq, self.last_seq
        delta = None
        if first is not None and last is not None:
            delta = (last - first) % _SPI_MOD
        return WindowRecord(
            window_index=self.index,
            window_start_ns=self.start_ns,
            window_end_ns=self.end_ns,
            empty=self.total == 0,
            total_packets=self.total,
            esp_packets=self.esp,
            ike_packets=self.ike,
            ike_nat_t_packets=self.ike_nat_t,
            ah_packets=self.ah,
            other_packets=self.other,
            unique_esp_spi_count=len(self.spis),
            first_esp_sequence=first,
            last_esp_sequence=last,
            esp_sequence_delta=delta,
            bytes_seen=self.bytes,
            bytes_a_to_b=self.bytes_a_to_b,
            bytes_b_to_a=self.bytes_b_to_a,
            packets_a_to_b=self.packets_a_to_b,
            packets_b_to_a=self.packets_b_to_a,
            events=tuple(self.events),
        )


class WindowEngine:
    """Deterministic event -> window binning with late/duplicate handling.

    Frontier semantics:

        frontier          the highest window index seen so far
        completed         indices < frontier (no new data expected there)
        open              completed windows back to ``frontier - lookback``
                          stay open so a slightly-out-of-order packet still
                          lands in its OWN window
        flushed           indices < frontier - lookback (immutable, emitted)
        late              an event older than the flooded frontier is counted
                          (``late_events``) and dropped -- never mis-binned
    """

    def __init__(
        self,
        window_ms: int = WINDOW_SIZE_MS_DEFAULT,
        lookback: int = WINDOW_LOOKBACK_DEFAULT,
        policy: Optional[EmissionPolicy] = None,
    ) -> None:
        if window_ms <= 0:
            raise ValueError("window_ms must be positive")
        if lookback < 0:
            raise ValueError("lookback must be >= 0")
        self.window_ns = window_ms * 1_000_000
        self.lookback = lookback
        self.policy = policy or EmissionPolicy()
        self._open: Dict[int, _WindowAccumulator] = {}
        self._frontier: Optional[int] = None
        self._last_flushed: Optional[int] = None
        self.late_events = 0
        self.windows_emitted = 0
        self.pending_flush: List[WindowRecord] = []

    # -- ingestion ---------------------------------------------------------

    @staticmethod
    def _index_of(ts_ns: int, window_ns: int) -> int:
        return ts_ns // window_ns

    def accept(
        self,
        *,
        ts_ns: int,
        event_type: str,
        src: Optional[str] = None,
        dst: Optional[str] = None,
        proto: int = 0,
        length: int = 0,
        spi: Optional[int] = None,
        seq: Optional[int] = None,
        sport: int = 0,
        dport: int = 0,
        direction: Optional[str] = None,
    ) -> bool:
        """Fold one packet into its window; True when accepted (not late)."""
        if not isinstance(ts_ns, int) or ts_ns < 0:
            raise ValueError("ts_ns must be a non-negative integer")
        index = self._index_of(ts_ns, self.window_ns)

        if self._frontier is not None and index < self._frontier - self.lookback:
            self.late_events += 1
            return False

        if self._frontier is None or index > self._frontier:
            self._advance_frontier(index)

        acc = self._open.get(index)
        if acc is None:
            acc = _WindowAccumulator(
                index, index * self.window_ns, (index + 1) * self.window_ns
            )
            self._open[index] = acc

        event = {
            "ts_ns": ts_ns,
            "type": event_type,
            "src": src or "",
            "dst": dst or "",
            "proto": proto,
            "length": length,
            "spi": spi,
            "seq": seq,
            "sport": sport,
            "dport": dport,
            "direction": direction,
        }
        self._fold(acc, event, direction)
        return True

    def _advance_frontier(self, new_index: int) -> None:
        self._frontier = new_index
        flush_below = new_index - self.lookback
        to_flush = sorted(i for i in self._open if i < flush_below)
        for index in to_flush:
            self._emit(self._open.pop(index))

    def _emit(self, acc: _WindowAccumulator) -> None:
        rec = acc.snapshot()
        if not rec.empty or self.policy.emit_empty:
            self.pending_flush.append(rec)
            self.windows_emitted += 1
        self._last_flushed = acc.index

    def _fold(self, acc: _WindowAccumulator, event: dict, direction: Optional[str]) -> None:
        etype = event["type"]
        acc.events.append(event)
        acc.total += 1
        acc.bytes += event["length"]
        if etype == CLASS_ESP:
            acc.esp += 1
            spi = event.get("spi")
            seq = event.get("seq")
            if spi is not None:
                acc.spis.add(spi)
            if seq is not None:
                seq = _as_int(seq)
                if acc.first_seq is None:
                    acc.first_seq = seq
                acc.last_seq = seq
        elif etype == CLASS_IKE:
            acc.ike += 1
        elif etype == CLASS_IKE_NAT_T:
            acc.ike_nat_t += 1
        elif etype == CLASS_AH:
            acc.ah += 1
        else:
            acc.other += 1

        if direction == "A_TO_B":
            acc.packets_a_to_b += 1
            acc.bytes_a_to_b += event["length"]
        elif direction == "B_TO_A":
            acc.packets_b_to_a += 1
            acc.bytes_b_to_a += event["length"]
        else:
            src = event.get("src")
            if src == "A":
                acc.packets_a_to_b += 1
                acc.bytes_a_to_b += event["length"]
            elif src == "B":
                acc.packets_b_to_a += 1
                acc.bytes_b_to_a += event["length"]

    # -- flush -------------------------------------------------------------

    def flush(self) -> List[WindowRecord]:
        """Emit every open window (index-ordered), then clear the engine.

        ``flush()`` covers shutdown / experiment-completion; gaps between
        flushed windows are emitted as EMPTY records when ``emit_empty`` is
        configured (silence is observed, never invented).
        """
        # Emit any gap between the frontier and the last flushed index as empty.
        if self._frontier is not None and self.policy.emit_empty:
            if self._last_flushed is not None:
                start = self._last_flushed + 1
            elif self._open:
                start = min(self._open)
            else:
                start = None
            if start is not None:
                for index in range(start, self._frontier):
                    if index not in self._open:
                        empty = _WindowAccumulator(
                            index, index * self.window_ns, (index + 1) * self.window_ns
                        )
                        self._open[index] = empty
        for index in sorted(self._open):
            self._emit(self._open[index])
        self._open.clear()
        out = self.pending_flush
        self.pending_flush = []
        return out

    def to_dict(self) -> Dict[str, Any]:
        return {
            "window_ms": self.window_ns // 1_000_000,
            "lookback": self.lookback,
            "frontier": self._frontier,
            "open_windows": sorted(self._open),
            "late_events": self.late_events,
            "windows_emitted": self.windows_emitted,
        }