"""Live feature extraction bridge: XDP event stream -> v2 feature record.

This module is the "live" side of the passive-observation pipeline.  The
WAN-side mirror emits per-packet events (``ebpf/xdp_monitor.c``), the 100 ms
window aggregator (``ebpf/xdp_window_aggregator.py``) groups them for
monitoring/state purposes, and :class:`LiveFeatureExtractor` turns the same
event stream into ML-ready records that match the training pipeline exactly:

    XDP event JSONL -> ebpf/xdp_window_aggregator.PacketEvent
                    -> LiveFeatureExtractor
                    -> {"feature_schema_version":"v2",
                        "window_start_ns":..., "window_end_ns":...,
                        "features":{<59 columns>}}

Single source of computation
----------------------------
The 59-column math is not re-implemented here.  :func:`controller.features.summarize_capture`
is the *only* implementation of the feature computation; the offline extractor
(``controller.features.extract_features``) and this module both call it.  That
makes offline/live parity structural rather than a matter of trusting two
copies of the same statistics.  The 59 column names and their types are
imported from ``controller.dataset_artifacts`` (``FEATURE_COLUMNS`` /
``INT_FEATURES``); they are never duplicated in this file.

L2 -> L3 conversion
-------------------
XDP emits ``len`` = the captured L2 frame length; the training features are
all derived from the outer-IP total length (``ip_total``, L3).  On the WAN-side
Ethernet mirror ``incl_len = ip_total + 14`` for every ESP/IKE frame (pinned by
``controller/test_features.py``), so the live extractor converts
``l3_length = event.len - ETHERNET_HEADER_BYTES`` before folding the frame in.

Which events are features built from?
-------------------------------------
The 59-feature record describes ESP data frames plus a separate IKE block
(UDP 500 / UDP 4500), exactly as the offline PCAP readers do.  ESP and
IKE/IKE-NAT-T events are consumed; AH and OTHER events do not contribute to
any of the 59 columns (the offline readers never parse AH and the --v2--
feature vector contains no AH statistics).  Direction is anchored to the
capture-point address (outer src == capture_ip => outbound, outer dst ==
capture_ip => inbound), the same rule the offline extractor uses.

SPI / sequence / state
----------------------
No feature in the v2 vector depends on ESP SPI, sequence numbers or inferred
IPsec state.  Direction comes from the outer source/destination address, never
from SPI mapping, so the live extractor needs no SPI/seq input and no state
builder.  (``ebpf/ipsec_state_builder.py`` remains the auditor's observed-state
layer and consumes the same or window-only input independently.)

Record shape (one JSONL object per line)
----------------------------------------
* ``feature_schema_version`` -- the imported constant (currently "v2").
* ``window_start_ns`` / ``window_end_ns`` -- the aligned 100 ms window span
  covering all consumed events (0/0 when no events were seen).
* ``features`` -- exactly the 59 columns, labels/metadata stay outside.

Empty observations produce an all-zero feature record (schema-complete) so a
consumer can distinguish "no traffic observed" from a malformed record.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import sys
from typing import Iterable, Iterator, Optional

from ebpf.xdp_window_aggregator import (
    TYPE_ESP,
    TYPE_IKE,
    TYPE_IKE_NAT_T,
    WINDOW_SIZE_MS,
    PacketEvent,
    iter_jsonl_events,
)
from controller import features as features_mod
from controller.dataset_artifacts import (
    FEATURE_SCHEMA_VERSION,
    assert_feature_keys,
)

#: Size columns are L3 (outer-IP total length).  The live sensor reports the
#: L2 captured frame length; on the WAN-side Ethernet mirror the L2->L3 gap is
#: a constant 14-byte Ethernet header.
ETHERNET_HEADER_BYTES = 14

#: Keys of the live record that live outside "features" (provenance/geometry).
LIVE_METADATA_KEYS = ("feature_schema_version", "window_start_ns", "window_end_ns")

IKE_NAT_T_PORT = 4500


def _pack_ip(text: str) -> bytes:
    """Pack an IPv4/IPv6 string to the 4/16-byte form read via ``read_pcap``."""
    try:
        return ipaddress.ip_address(text or "").packed
    except ValueError:
        return b"\x00" * 4


def iterate_capture_as_live_events(path) -> Iterator[dict]:
    """Reconstruct XDP-compatible event dicts from a PCAP (parity harness).

    For each ESP frame parsed by ``controller.features.read_pcap`` and each IKE
    datagram parsed by ``read_pcap_ike`` this yields the event dict that the
    live XDP sensor would have emitted for the same frame: ``type`` is ``ESP``
    or ``IKE``/``IKE-NAT-T`` (UDP 500 vs 4500), ``len`` is the *L2* frame
    length (``incl_len``), and ``ts`` is the pcap timestamp expressed in
    integer nanoseconds.  Feeding these to :class:`LiveFeatureExtractor` must
    reproduce the offline ``extract_features`` record (modulo sub-rounding
    timestamp quantization); this is asserted by
    ``controller/test_live_features.py``.
    """
    for timestamp, incl_len, _ip_total, src, dst in features_mod.read_pcap(path):
        yield {
            "ts": round(timestamp * 1_000_000_000),
            "type": TYPE_ESP,
            "src": str(ipaddress.ip_address(src)),
            "dst": str(ipaddress.ip_address(dst)),
            "proto": 50,
            "len": incl_len,
            "spi": 0,
            "seq": 0,
        }
    for timestamp, incl_len, _ip_total, src, dst, port, _ver, _exch \
            in features_mod.read_pcap_ike(path):
        yield {
            "ts": round(timestamp * 1_000_000_000),
            "type": TYPE_IKE_NAT_T if port == IKE_NAT_T_PORT else TYPE_IKE,
            "src": str(ipaddress.ip_address(src)),
            "dst": str(ipaddress.ip_address(dst)),
            "proto": 17,
            "len": incl_len,
            "sport": port,
            "dport": port,
        }


class LiveFeatureExtractor:
    """Accumulate an XDP event stream and emit exact-v2 feature records.

    The extractor is transport agnostic: feed it event dicts (``accept_dict``)
    or :class:`PacketEvent` objects (``accept``) from the live ring-buffer
    reader OR from recorded JSONL, then call :meth:`snapshot` to materialize
    the current record.  :meth:`reset` starts a new observation epoch.
    """

    def __init__(
        self,
        capture_ip: Optional[str] = None,
        burst_window: float = features_mod.DEFAULT_BURST_WINDOW_S,
        nominal_duration: Optional[float] = None,
        window_ms: int = WINDOW_SIZE_MS,
    ):
        if window_ms <= 0:
            raise ValueError("window_ms must be positive")
        self.capture_ip = capture_ip
        self.burst_window = burst_window
        self.nominal_duration = nominal_duration
        self.window_ns = window_ms * 1_000_000
        self.reset()

    # -- lifecycle --------------------------------------------------------- #

    def reset(self) -> None:
        """Start a new observation epoch (all counters and frame lists clear)."""
        self.events_consumed = 0
        self.features_consumed = 0
        self._esp = []               # [(ts_s, incl_len, l3_len, src, dst), ...]
        self._ike_sizes: list = []   # L3 ip_total sizes of IKE datagrams
        self._first_ts_ns: Optional[int] = None
        self._last_ts_ns: Optional[int] = None

    # -- ingestion --------------------------------------------------------- #

    def accept(self, event: PacketEvent) -> None:
        """Fold one observed packet into the current epoch's feature record."""
        self.events_consumed += 1
        etype = event.type
        if etype == TYPE_ESP:
            l3 = event.length - ETHERNET_HEADER_BYTES
            ts_s = event.ts / 1_000_000_000.0
            self._esp.append((ts_s, event.length, l3,
                              _pack_ip(event.src), _pack_ip(event.dst)))
            self.features_consumed += 1
        elif etype in (TYPE_IKE, TYPE_IKE_NAT_T):
            self._ike_sizes.append(event.length - ETHERNET_HEADER_BYTES)
            self.features_consumed += 1
        else:
            # AH / OTHER never contribute to the v2 feature vector.
            return

        if self._first_ts_ns is None:
            self._first_ts_ns = event.ts
        self._last_ts_ns = event.ts

    def accept_dict(self, record: dict) -> None:
        self.accept(PacketEvent.from_dict(record))

    # -- output ------------------------------------------------------------ #

    @property
    def window_start_ns(self) -> int:
        """Aligned start of the first 100 ms window containing an event."""
        if self._first_ts_ns is None:
            return 0
        return (self._first_ts_ns // self.window_ns) * self.window_ns

    @property
    def window_end_ns(self) -> int:
        """Aligned end of the last 100 ms window containing an event."""
        if self._last_ts_ns is None:
            return 0
        return ((self._last_ts_ns // self.window_ns) + 1) * self.window_ns

    def features(self) -> dict:
        """The current 59-feature dict (shared computation with training)."""
        return features_mod.summarize_capture(
            self._esp,
            ike_sizes=self._ike_sizes,
            burst_window=self.burst_window,
            capture_ip=self.capture_ip,
            nominal_duration=self.nominal_duration,
        )

    def snapshot(self) -> dict:
        """Materialize one live record: version + window span + 59 features."""
        features = self.features()
        assert_feature_keys(features)
        return {
            "feature_schema_version": FEATURE_SCHEMA_VERSION,
            "window_start_ns": self.window_start_ns,
            "window_end_ns": self.window_end_ns,
            "features": features,
        }


def extract_record(records: Iterable[dict], capture_ip=None,
                   burst_window=features_mod.DEFAULT_BURST_WINDOW_S,
                   nominal_duration=None) -> dict:
    """Convenience: feed event dicts into a fresh extractor and snapshot."""
    extractor = LiveFeatureExtractor(
        capture_ip=capture_ip,
        burst_window=burst_window,
        nominal_duration=nominal_duration,
    )
    for record in records:
        extractor.accept_dict(record)
    return extractor.snapshot()


def main(argv: Optional[list] = None) -> int:
    """Thin CLI: read event JSONL, emit feature-record JSONL.

    ``--emit-every N`` emits (and resets) a record every N consumed events,
    modelling a per-epoch live loop; the final snapshot is always emitted.
    """
    parser = argparse.ArgumentParser(
        description="Live XDP events -> exact-v2 feature records (JSONL).")
    parser.add_argument("--events", default="-",
                        help="JSONL event input file ('-' = stdin)")
    parser.add_argument("--output", default="-",
                        help="JSONL feature-record output file ('-' = stdout)")
    parser.add_argument("--capture-ip", default=None,
                        help="capture-point WAN address (direction anchor)")
    parser.add_argument("--nominal-duration", type=float, default=None,
                        help="reuse offline densest-window logic (seconds)")
    parser.add_argument("--burst-window", type=float,
                        default=features_mod.DEFAULT_BURST_WINDOW_S,
                        help="legacy single-window burst gate (seconds)")
    parser.add_argument("--window-ms", type=int, default=WINDOW_SIZE_MS,
                        help="window size for start/end boundaries (ms)")
    parser.add_argument("--emit-every", type=int, default=0,
                        help="also emit+reset a record every N events")
    args = parser.parse_args(argv)

    extractor = LiveFeatureExtractor(
        capture_ip=args.capture_ip,
        burst_window=args.burst_window,
        nominal_duration=args.nominal_duration,
        window_ms=args.window_ms,
    )

    in_stream = sys.stdin if args.events == "-" else open(args.events, "r")
    out_stream = sys.stdout if args.output == "-" else open(args.output, "w")
    emitted = 0

    def emit() -> None:
        nonlocal emitted
        out_stream.write(json.dumps(extractor.snapshot(),
                                    separators=(",", ":")) + "\n")
        out_stream.flush()
        emitted += 1

    try:
        for event in iter_jsonl_events(in_stream):
            extractor.accept(event)
            if args.emit_every and extractor.events_consumed % args.emit_every == 0:
                emit()
                extractor.reset()
        emit()
    finally:
        if args.events != "-":
            in_stream.close()
        if args.output != "-":
            out_stream.close()
        print(
            "live-features: events_consumed=%d features_consumed=%d "
            "records_emitted=%d feature_schema_version=%s"
            % (extractor.events_consumed, extractor.features_consumed,
               emitted, FEATURE_SCHEMA_VERSION),
            file=sys.stderr,
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())