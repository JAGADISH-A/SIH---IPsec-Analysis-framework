"""Read-only capture feed (Phase 10, capture / live-traffic view).

A thin, read-only projection of the *existing* XDP/eBPF packet journal that the
gateway monitor writes (``ebpf/xdp_monitor`` JSONL, the ``xdp_monitor_event``
shape). Every raw event is normalized through the same ``XdpEventAdapter`` the
streaming layer already uses, so a captured packet reaches the /api/v1 surface
in exactly the canonical stream contract:

    timestamp / interface / protocol / source / destination /
    SPI / sequence / packet_length / source_port / destination_port /
    classification / direction / sensor_type

Policy (carried verbatim from the frontend contract):

- **read-only** - this module never writes to the capture journal; the endpoint
  only tails it at a byte offset supplied by the client.
- **no new capture** - it reuses the journal produced by ``xdp_monitor``; it
  does not build another capture or aggregation path.
- **no packet-parsing in the frontend** - ``protocol_label`` and the IPsec
  classification are computed here from the normalized packet, never in the UI.
- **no fabricated packets** - with no traffic the feed reports an explicit
  waiting state (``present: false`` + ``reason``) rather than synthesizing rows.
- **current live traffic only** - every envelope carries ``current``: whether
  the journal is being *actively appended to right now* (mtime within the live
  freshness window), alongside ``last_write_age_ms`` / ``newest_observed_at_ms``
  so a client can tell "currently observed" from "a recorded artifact that
  happens to still be on disk". A journal that stopped being written is
  recorded history, never current traffic; the frontend must not present its
  rows as live. ``status()`` reports the same verdict.
- **experiment boundary** - when experiment gating is enabled
  (``ANALYTICS_CAPTURE_EXPERIMENT_GATED=1``, the real testbed deployment), the
  feed serves ONLY journal lines at/after the current controller experiment's
  ``observation_start_bytes`` boundary, so old runs / dataset / replay rows can
  never appear in the LIVE table. With no active experiment on THIS journal, or
  after the experiment ended, the feed serves zero rows and ``current: false``.
  No boundary is applied to the legacy / demo / replay feed paths.
- **risk only from the assessment store** - per-packet ``risk`` is a verbatim
  projection of the existing deterministic ``AssessmentStore`` headers joined by
  observed SPI. When no assessment observed the SPI, ``risk.present`` is
  ``false``. Nothing is inferred from the packet itself.
"""

import hashlib
import json
import os
import time
from typing import Any, Dict, List, Optional, Sequence

from ..streaming.live_adapter import (
    AH,
    CLASSIFICATION_AH,
    CLASSIFICATION_ESP,
    CLASSIFICATION_ESP_IN_UDP,
    CLASSIFICATION_IKE,
    CLASSIFICATION_OTHER,
    CLASSIFICATION_UNKNOWN,
    ESP,
    IKE,
    IKE_PORT,
    IP_PROTO_UDP,
    NAT_T_PORT,
    XdpEventAdapter,
)

__all__ = [
    "CAPTURE_SCHEMA",
    "DEFAULT_CAPTURE_FEED_PATH",
    "DEFAULT_LIVE_FRESHNESS_MS",
    "DESCRIPTION",
    "ENV_LIVE_FRESHNESS_MS",
    "STATE_WAITING",
    "CaptureFeedService",
    "build_risk_index",
    "protocol_label",
    "risk_for_spi",
]

CAPTURE_SCHEMA = "packet"
DESCRIPTION = (
    "Passive capture of the gateway traffic path (xdp_monitor). Read-only: the "
    "server only tails the packet journal the sensor writes."
)

#: The recorded live-tap artifact that ships with the repo. A gateway monitor
#: writing to the same path turns this page into a genuinely live view.
DEFAULT_CAPTURE_FEED_PATH = "results/observed-state/live_events_full.jsonl"

#: Environment variable override for the live-freshness window.
ENV_LIVE_FRESHNESS_MS = "ANALYTICS_API_CAPTURE_FRESHNESS_MS"

#: A journal is ``current`` only while it is being appended to. Once its
#: modification time is older than this window it is recorded history — still
#: readable through the feed, but never to be presented as current live traffic.
DEFAULT_LIVE_FRESHNESS_MS = 8000

SEVERITY_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")

#: IP protocol numbers without a dedicated IPsec label, rendered as their
#: IANA names so the UI does not have to translate protocol numbers itself.
_PROTO_NAMES = {
    1: "ICMP",
    2: "IGMP",
    6: "TCP",
    17: "UDP",
    41: "IPv6",
    47: "GRE",
    50: ESP,
    51: AH,
    89: "OSPF",
    112: "VRRP",
}

#: Well-known UDP/TCP service ports shown in the Info column when present.
_PORT_NAMES = {
    53: "DNS",
    123: "NTP",
    IKE_PORT: IKE,
    NAT_T_PORT: "NAT-T",
    179: "BGP",
    520: "RIP",
}


def protocol_label(packet: Dict[str, Any]) -> str:
    """Wireshark-style Protocol column label for a normalized packet.

    IPsec geometry is already classified by the streaming adapter (ESP / AH /
    IKE / ESP-in-UDP). This function turns that classification plus the port
    pair into the label a capture analyst expects, without re-parsing anything.
    """
    proto = int(packet.get("protocol", 0) or 0)
    classification = str(packet.get("classification", "") or "")
    sport = int(packet.get("source_port", 0) or 0)
    dport = int(packet.get("destination_port", 0) or 0)

    if classification == CLASSIFICATION_ESP:
        return ESP
    if classification == CLASSIFICATION_AH:
        return AH
    if classification in (CLASSIFICATION_IKE, CLASSIFICATION_ESP_IN_UDP):
        return classification
    if proto in (IP_PROTO_UDP, 6):  # UDP / TCP
        if NAT_T_PORT in (sport, dport) and classification == CLASSIFICATION_UNKNOWN:
            return "UDP"
        if 53 in (sport, dport):
            return "DNS"
        if proto == IP_PROTO_UDP:
            return "UDP"
        return "TCP"
    if proto in _PROTO_NAMES:
        return _PROTO_NAMES[proto]
    if classification == CLASSIFICATION_OTHER:
        return CLASSIFICATION_OTHER
    return CLASSIFICATION_UNKNOWN


def packet_info(packet: Dict[str, Any]) -> str:
    """Wireshark-style Info column for a normalized packet (display formatting)."""
    label = protocol_label(packet)
    spi = packet.get("spi")
    seq = int(packet.get("sequence", 0) or 0)
    sport = int(packet.get("source_port", 0) or 0)
    dport = int(packet.get("destination_port", 0) or 0)

    if label in (ESP, CLASSIFICATION_ESP_IN_UDP):
        base = f"SPI 0x{spi:08x}" if spi is not None else "SPI —"
        return f"{base}, seq {seq}" if seq else base
    if label == AH:
        base = f"SPI 0x{spi:08x}" if spi is not None else "SPI —"
        return base
    if label in (CLASSIFICATION_IKE, "IKE-NAT-T"):
        return "IKE negotiation"
    if sport or dport:
        vers = " → " if sport and dport else ""
        return f"{sport}{vers}{dport}"
    return label


def _severity_rank(severity: Optional[str]) -> int:
    return SEVERITY_ORDER.index(severity) if severity in SEVERITY_ORDER else len(SEVERITY_ORDER)


def build_risk_index(store) -> Dict[int, List[Dict[str, Any]]]:
    """SPI -> assessment risk projection, copied verbatim from the store.

    Only observed SPI values participate: a packet whose SPI the store never
    observed is simply not in the index and renders ``risk.present: false``.
    """
    index: Dict[int, List[Dict[str, Any]]] = {}
    header_by_id: Dict[str, Dict[str, Any]] = {}
    for header in getattr(store, "headers", []) or []:
        aid = header.get("assessment_id")
        if aid:
            header_by_id[aid] = header

    for assessment_id, bundle in (getattr(store, "bundles", {}) or {}).items():
        observed = bundle.get("observed") or {}
        header = header_by_id.get(assessment_id) or {}
        # A packet matching an observed SPI inherits the assessment's risk only
        # when the assessment actually observed the SPI.
        for spi_view in observed.get("spis", []) or []:
            spi = spi_view.get("spi")
            if spi in (None, ""):
                continue
            try:
                spi = int(str(spi), 0)
            except (TypeError, ValueError):
                continue
            index.setdefault(spi, []).append(
                {
                    "assessment_id": assessment_id,
                    "severity": header.get("severity"),
                    "risk_score": header.get("risk_score"),
                    "finding_count": header.get("finding_count"),
                }
            )
    return index


def risk_for_spi(
    spi: Optional[int],
    risk_index: Optional[Dict[int, List[Dict[str, Any]]]] = None,
) -> Dict[str, Any]:
    """Per-packet risk: a verbatim projection of assessment store results."""
    if spi is None or not risk_index:
        return {"present": False}
    matches = risk_index.get(spi)
    if not matches:
        return {"present": False}
    ranked = sorted(
        matches,
        key=lambda m: (
            _severity_rank(m.get("severity")),
            -(m.get("risk_score") if isinstance(m.get("risk_score"), (int, float)) else -1),
        ),
    )
    return {
        "present": True,
        "highest_severity": ranked[0].get("severity"),
        "highest_risk_score": ranked[0].get("risk_score"),
        "assessments": ranked,
    }


STATE_WAITING = "waiting"
STATE_AVAILABLE = "available"

#: Boundary gate verdicts (see ``CaptureFeedService._boundary_gate``).
GATE_LEGACY = "legacy"
GATE_ACTIVE = "active"
GATE_CLOSED = "closed"


class CaptureFeedService:
    """Read-only tail of the xdp_monitor JSONL journal.

    The cursor is a byte offset into the journal, returned verbatim with every
    response so a client can resume exactly where it left off. Growing the file
    (the gateway monitor appending live packets) is the source of new rows.
    """

    def __init__(
        self,
        path: str,
        *,
        adapter: Optional[XdpEventAdapter] = None,
        risk_index: Optional[Dict[int, List[Dict[str, Any]]]] = None,
        freshness_window_ms: Optional[int] = None,
        boundary_provider: Optional[Any] = None,
        experiment_gated: Optional[bool] = None,
    ) -> None:
        self.path = os.path.abspath(path)
        self.adapter = adapter or XdpEventAdapter(source="capture_feed")
        self.risk_index = risk_index or {}
        if not freshness_window_ms:
            try:
                freshness_window_ms = int(
                    os.environ.get(ENV_LIVE_FRESHNESS_MS, "") or DEFAULT_LIVE_FRESHNESS_MS
                )
            except ValueError:
                freshness_window_ms = DEFAULT_LIVE_FRESHNESS_MS
        self.freshness_window_ms = max(1000, int(freshness_window_ms))
        # Experiment boundary gate (see ``_boundary_gate``). ``boundary_provider``
        # is the current-run annex's ``boundary()``; when ``experiment_gated`` is
        # on (the default), the feed serves ONLY journal lines at/after the
        # current experiment's observation-start offset, and serves zero rows
        # while no experiment is active. ``ANALYTICS_CAPTURE_EXPERIMENT_GATED=0``
        # opts the feed back into legacy recorded-demo replay;
        # ``start-live-analytics.sh`` is the real live deployment.
        self.boundary_provider: Optional[Any] = boundary_provider
        # Gated by default: a live server must never replay recorded history as
        # current traffic. Legacy replay requires an explicit opt-out
        # (``ANALYTICS_CAPTURE_EXPERIMENT_GATED=0``) used by the recorded-demo
        # fixtures, never the default.
        if experiment_gated is None:
            experiment_gated = os.environ.get("ANALYTICS_CAPTURE_EXPERIMENT_GATED", "1") == "1"
        self.experiment_gated: bool = bool(experiment_gated)

    # -- internals ---------------------------------------------------------

    @property
    def present(self) -> bool:
        return os.path.isfile(self.path)

    def _now_ms(self) -> int:
        return int(time.time() * 1000)

    def _file_size(self) -> int:
        try:
            return os.path.getsize(self.path)
        except OSError:
            return 0

    def _mtime_ms(self) -> Optional[int]:
        if not self.present:
            return None
        try:
            return int(os.path.getmtime(self.path) * 1000)
        except OSError:
            return None

    def _last_event_time_ms(self) -> Optional[int]:
        """Best-effort wall-clock time of the journal's newest complete line.

        Only newline-terminated lines count (a torn tail being written by the
        sensor is never read as an event). This is informational: the *current*
        verdict itself comes from journal write activity (mtime), not from the
        adapter's clock mapping.
        """
        if not self.present:
            return None
        try:
            with open(self.path, "rb") as fh:
                fh.seek(0, os.SEEK_END)
                size = fh.tell()
                if size == 0:
                    return None
                back = min(size, 1 << 16)
                fh.seek(size - back)
                chunk = fh.read().decode("utf-8", errors="replace")
        except OSError:
            return None
        if not chunk.endswith("\n"):
            chunk = chunk.rsplit("\n", 1)[0]
        lines = [line.strip() for line in chunk.split("\n") if line.strip()]
        if not lines:
            return None
        try:
            payload = json.loads(lines[-1])
        except (ValueError, TypeError):
            return None
        if not isinstance(payload, dict):
            return None
        if not self.present:
            return None
        try:
            timestamp = int(self.adapter.normalize(payload).get("timestamp", 0) or 0)
        except Exception:
            return None
        return timestamp // 1_000_000 if timestamp else None

    def _currentness(self) -> Dict[str, Any]:
        """The envelope's liveness verdict, computed server-side from write
        activity. A journal is ``current`` only while it is actively being
        appended to; a static recorded artifact is never current."""
        mtime = self._mtime_ms()
        now = self._now_ms()
        age = (now - mtime) if mtime is not None else None
        current = bool(
            self.present
            and self._file_size() > 0
            and age is not None
            and age <= self.freshness_window_ms
        )
        return {
            "current": current,
            "freshness_window_ms": self.freshness_window_ms,
            "last_write_age_ms": age,
            "journal_mtime_ms": mtime,
            "server_time_ms": now,
            "newest_observed_at_ms": self._last_event_time_ms(),
        }

    def _line_count(self) -> int:
        """Number of completed lines in the journal (cheap first pass)."""
        try:
            with open(self.path, "rb") as fh:
                return fh.read().count(b"\n")
        except OSError:
            return 0

    def _unavailable_payload(self, reason: str) -> Dict[str, Any]:
        return {
            "api": "capture-events-v1",
            "schema": CAPTURE_SCHEMA,
            "state": STATE_WAITING,
            "read_only": True,
            "present": False,
            "reason": reason,
            "source": os.path.basename(self.path),
            "frame": DESCRIPTION,
            "cursor": 0,
            "start_cursor": 0,
            "size": 0,
            "total": 0,
            "count": 0,
            "limit": 0,
            "has_more": False,
            "events": [],
            **self._currentness(),
        }

    def _boundary_gate(self) -> tuple:
        """Verdict of the experiment-boundary gate for the live feed.

        Returns ``(GATE_*, start_bytes)``. ``GATE_LEGACY`` (no gate / gating
        disabled) leaves the historical tailing behavior untouched; ``GATE_ACTIVE``
        serves only journal lines at/after ``start_bytes``; ``GATE_CLOSED`` serves
        zero rows and marks the envelope ``current: false`` because either no
        experiment is active on THIS journal, the experiment already ended, or the
        gate could not be resolved. Closing (never leaking) is the safe default on
        any failure.
        """
        if not self.experiment_gated or self.boundary_provider is None:
            return GATE_LEGACY, 0
        try:
            info = self.boundary_provider()
        except Exception:
            return GATE_CLOSED, 0
        if not isinstance(info, dict):
            return GATE_CLOSED, 0
        try:
            journal_path = os.path.abspath(str(info.get("journal_path") or ""))
        except (AttributeError, TypeError):
            journal_path = ""
        if journal_path != self.path:
            return GATE_CLOSED, 0
        if info.get("ended"):
            return GATE_CLOSED, 0
        try:
            start = int(info.get("start_bytes") or 0)
        except (TypeError, ValueError):
            start = 0
        return GATE_ACTIVE, max(0, start)

    def _gated_empty_payload(self, reason: str) -> Dict[str, Any]:
        """Envelope for a present-but-closed live view (zero rows, not current)."""
        currentness = self._currentness()
        currentness["current"] = False
        return {
            "api": "capture-events-v1",
            "schema": CAPTURE_SCHEMA,
            "state": STATE_AVAILABLE,
            "read_only": True,
            "present": True,
            "reason": reason,
            "source": os.path.basename(self.path),
            "frame": DESCRIPTION,
            "cursor": 0,
            "start_cursor": 0,
            "size": self._file_size(),
            "total": 0,
            "count": 0,
            "limit": 200,
            "has_more": False,
            "events": [],
            **currentness,
        }

    def status(self) -> Dict[str, Any]:
        if not self.present:
            return {
                "present": False,
                "source": os.path.basename(self.path),
                "reason": (
                    f"no capture journal at {os.path.basename(self.path)}; "
                    "waiting for the gateway monitor to write"
                ),
                **self._currentness(),
            }
        gate, _ = self._boundary_gate()
        if gate == GATE_CLOSED:
            currentness = self._currentness()
            currentness["current"] = False
            return {
                "present": True,
                "source": os.path.basename(self.path),
                "reason": "live feed closed: no active testbed experiment on this journal",
                "size": self._file_size(),
                "events": 0,
                **currentness,
            }
        return {
            "present": True,
            "source": os.path.basename(self.path),
            "size": self._file_size(),
            "events": self._line_count(),
            **self._currentness(),
        }

    def poll(self, cursor: int = 0, limit: int = 200) -> Dict[str, Any]:
        """Tail the journal from ``cursor`` bytes, returning up to ``limit`` rows.

        Returns the full envelope with a byte ``cursor`` for the next poll. Only
        complete (newline-terminated) lines are parsed, so a torn final line
        being written by the sensor is never surfaced.
        """
        if not self.present:
            return self._unavailable_payload(
                f"no capture journal at {os.path.basename(self.path)}; "
                "waiting for the gateway monitor to write"
            )

        gate, gate_start = self._boundary_gate()
        if gate == GATE_CLOSED:
            return self._gated_empty_payload(
                "live feed closed: no active testbed experiment on this journal"
            )

        size = self._file_size()
        start = max(0, int(cursor or 0))
        if gate == GATE_ACTIVE and gate_start:
            # Serve ONLY lines written by this experiment's monitor run. The
            # journal may still hold pre-experiment history at earlier offsets;
            # those bytes are never surfaced.
            start = max(start, gate_start)
        if start > size:
            if gate == GATE_ACTIVE and gate_start:
                # Journal rotated/truncated mid-run: never fall back to the head
                # (that could resurrect pre-experiment rows). Clamp to the gate.
                start = gate_start if gate_start <= size else size
            else:
                # Journal was rotated or truncated: resume from the top.
                start = 0
        limit = max(1, min(int(limit or 200), 2000))

        if size == 0:
            # The monitor has opened/truncated the journal but not written a
            # complete packet yet. "Present but empty" is a waiting state, never
            # a bare empty table that could read as "the link is quiet".
            return self._unavailable_payload(
                f"capture journal {os.path.basename(self.path)} is empty; "
                "waiting for the gateway monitor to write"
            )

        if start >= size:
            return {
                "api": "capture-events-v1",
                "schema": CAPTURE_SCHEMA,
                "state": STATE_AVAILABLE,
                "read_only": True,
                "present": True,
                "reason": None,
                "source": os.path.basename(self.path),
                "frame": DESCRIPTION,
                "cursor": int(start),
                "start_cursor": int(start),
                "size": size,
                "total": self._line_count(),
                "count": 0,
                "limit": limit,
                "has_more": False,
                "events": [],
                **self._currentness(),
            }

        try:
            with open(self.path, "rb") as fh:
                fh.seek(start)
                raw = fh.read()
        except OSError:
            return self._unavailable_payload("capture journal read failed; will retry")

        # The final segment is always the torn tail being written by the
        # sensor, so it is never surfaced. The first segment is complete only
        # when the byte *before* the cursor is a newline (or we start at 0).
        boundary = start == 0
        if not boundary and start > 0:
            try:
                with open(self.path, "rb") as fh:
                    fh.seek(start - 1)
                    boundary = fh.read(1) == b"\n"
            except OSError:
                boundary = False

        text = raw.decode("utf-8", errors="replace")
        segments = text.split("\n")
        complete: List[str] = []
        byte_offset = start
        if segments and segments[0]:
            if boundary:
                complete = segments[:-1]
            else:
                # Drop the partial head (the cursor is mid-line).
                byte_offset += len(segments[0].encode("utf-8")) + 1
                complete = segments[1:-1]
        else:
            complete = segments[:-1]

        events: List[Dict[str, Any]] = []
        next_cursor = int(byte_offset)
        for line_text in complete:
            if len(events) >= limit:
                break
            line_text = line_text.strip()
            if not line_text:
                next_cursor += len(line_text.encode("utf-8")) + 1
                continue
            offset = next_cursor
            next_cursor += len(line_text.encode("utf-8")) + 1
            try:
                payload = json.loads(line_text)
            except (ValueError, TypeError):
                continue
            if not isinstance(payload, dict):
                continue
            packet = self.adapter.normalize(payload)
            events.append(self._view(packet, line_text, offset))

        has_more = next_cursor < size or len(events) >= limit
        return {
            "api": "capture-events-v1",
            "schema": CAPTURE_SCHEMA,
            "state": STATE_AVAILABLE,
            "read_only": True,
            "present": True,
            "reason": None,
            "source": os.path.basename(self.path),
            "frame": DESCRIPTION,
            "cursor": int(next_cursor),
            "start_cursor": int(start),
            "size": size,
            "total": self._line_count(),
            "count": len(events),
            "limit": limit,
            "has_more": bool(has_more),
            "events": events,
            **self._currentness(),
        }

    def _view(self, packet: Dict[str, Any], line_text: str, offset: int) -> Dict[str, Any]:
        """One captured packet row, wrapped with its feed identity + risk."""
        digest = hashlib.sha256(str(offset).encode("utf-8") + b":" + line_text.encode("utf-8"))
        return {
            "id": digest.hexdigest(),
            "source": os.path.basename(self.path),
            "offset": offset,
            "timestamp_ns": int(packet.get("timestamp", 0) or 0),
            "schema": CAPTURE_SCHEMA,
            "packet": packet,
            "protocol_label": protocol_label(packet),
            "info": packet_info(packet),
            "spi": packet.get("spi"),
            "direction": packet.get("direction"),
            "risk": risk_for_spi(packet.get("spi"), self.risk_index),
        }