"""XDP/eBPF live event adapter (Phase 10).

Consumes the existing XDP/eBPF JSON event stream (the ``xdp_monitor_event``
shape documented in ``D:\\sihipsec\\ebpf\\xdp_monitor_common.h`` + the
normalized ``PacketEvent`` in ``D:\\sihipsec\\ebpf\\xdp_window_aggregator.py``)
and normalizes each packet into the canonical streaming contract.

Preserved fields:

    timestamp / interface / protocol / source / destination /
    SPI / direction / packet length / IKE-ESP-AH classification

The adapter NEVER infers cryptographic algorithms from packet sizes and NEVER
infers security posture from traffic statistics.

UDP/4500 (NAT-T seam)
---------------------
Not every UDP/4500 packet is IKE. An explicit classification state is
introduced:

    IKE          negotiated IKE over UDP 500, or IKE-Over-NAT-T (UDP 4500)
                 supported by sensor evidence
    ESP_IN_UDP   ESP encapsulated in UDP/4500 (NAT-T data) supported by
                 sensor evidence
    UNKNOWN      UDP/4500 with insufficient evidence (never fabricated)

Raw sensor labels are honoured as evidence, never re-invented by heuristics.
"""

import ipaddress
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Optional, Tuple

from ..models import CorrelationIdentity
from .models import (
    EVENT_TYPE_IKE,
    EVENT_TYPE_PACKET,
    StreamEvent,
)

CLASS_IKE = "IKE"
CLASS_IKE_NAT_T = "IKE-NAT-T"
CLASS_ESP = "ESP"
CLASS_AH = "AH"
CLASS_OTHER = "OTHER"
# ESP carried inside UDP/4500 (RFC 3948 NAT-T data plane).  The sensor emits
# this only when the UDP payload really is an ESP header, so it carries a real
# SPI/sequence; IKE over NAT-T is reported separately as CLASS_IKE_NAT_T.
CLASS_ESP_NAT_T = "ESP-NAT-T"

CLASSIFICATION_IKE = IKE = "IKE"
CLASSIFICATION_ESP_IN_UDP = ESP_IN_UDP = "ESP_IN_UDP"
CLASSIFICATION_ESP = ESP = "ESP"
CLASSIFICATION_AH = AH = "AH"
CLASSIFICATION_OTHER = "OTHER"
CLASSIFICATION_UNKNOWN = UNKNOWN = "UNKNOWN"

CLASSIFICATIONS = (
    CLASSIFICATION_IKE,
    CLASSIFICATION_ESP_IN_UDP,
    CLASSIFICATION_ESP,
    CLASSIFICATION_AH,
    CLASSIFICATION_OTHER,
    CLASSIFICATION_UNKNOWN,
)

IP_PROTO_ESP = 50
IP_PROTO_AH = 51
IP_PROTO_UDP = 17
IKE_PORT = 500
NAT_T_PORT = 4500

_RAW_TYPE_TO_CLASS = {
    CLASS_IKE: CLASSIFICATION_IKE,
    CLASS_IKE_NAT_T: CLASSIFICATION_IKE,
    CLASS_ESP_NAT_T: CLASSIFICATION_ESP_IN_UDP,
    CLASS_ESP: CLASSIFICATION_ESP,
    CLASS_AH: CLASSIFICATION_AH,
    CLASS_OTHER: CLASSIFICATION_OTHER,
}


def _packed(text: Any) -> str:
    if not text:
        return "0.0.0.0"
    try:
        return str(ipaddress.ip_address(str(text)))
    except ValueError:
        return ""


@dataclass(frozen=True)
class NatTClassification:
    """Explicit UDP/4500 classification (the NAT-T seam)."""

    classification: str
    reason: str
    nat_t: bool = False

    def __post_init__(self) -> None:
        if self.classification not in CLASSIFICATIONS:
            raise ValueError(
                f"classification must be one of {CLASSIFICATIONS}, got "
                f"{self.classification!r}"
            )

    def to_dict(self) -> dict:
        return {
            "classification": self.classification,
            "reason": self.reason,
            "nat_t": self.nat_t,
        }


def classify_udp_4500(sensor_type: Optional[str], sport: int, dport: int) -> NatTClassification:
    """Classify a UDP/4500 datagram without fabricating evidence."""
    if sport not in (IKE_PORT, NAT_T_PORT) and dport not in (IKE_PORT, NAT_T_PORT):
        return NatTClassification(
            CLASSIFICATION_UNKNOWN,
            reason="neither UDP port is 500/4500; classification unsupported",
        )
    if 500 in (sport, dport):
        return NatTClassification(
            CLASSIFICATION_IKE,
            reason="UDP/500 indicates IKE negotiation",
            nat_t=False,
        )
    sensor = (sensor_type or "").strip().upper()
    if sensor == CLASS_ESP_NAT_T:
        # The sensor only emits this label when the UDP payload really is an
        # ESP header, so the SPI/sequence in the event are genuine.
        return NatTClassification(
            CLASSIFICATION_ESP_IN_UDP,
            reason="sensor parsed a real ESP header inside UDP/4500 "
            "(RFC 3948 NAT-T data plane)",
            nat_t=True,
        )
    if sensor == CLASS_IKE_NAT_T or sensor == CLASS_IKE:
        return NatTClassification(
            CLASSIFICATION_IKE,
            reason="sensor labels the datagram as IKE over NAT-T",
            nat_t=True,
        )
    if sensor == CLASS_ESP:
        return NatTClassification(
            CLASSIFICATION_ESP_IN_UDP,
            reason="sensor labels the datagram as ESP-in-UDP (NAT-T data)",
            nat_t=True,
        )
    return NatTClassification(
        CLASSIFICATION_UNKNOWN,
        reason="UDP/4500 with insufficient evidence; not labelled as IKE or "
        "ESP-in-UDP (never fabricated)",
        nat_t=True,
    )


@dataclass
class XdpEventAdapter:
    """Normalizes raw XDP/eBPF packet dicts into canonical stream events.

    ``realtime_offset_ns`` converts the sensor's CLOCK_MONOTONIC ``ts`` (ns
    since boot, from ``bpf_ktime_get_ns()``) into a realtime epoch so the
    canonical ``PacketEvent.timestamp`` is always a wall-clock nanosecond
    timestamp — never an uptime that a client could mistake for wall time. The
    offset is sampled once at construction: it is linear in monotonic time, so
    it maps every event of a journal written on this host, including ones
    captured slightly after the sample. Tests may pass an explicit offset to
    keep the mapping deterministic.
    """

    capture_ip: Optional[str] = None
    endpoints: Dict[str, str] = field(default_factory=dict)
    source: str = "live_xdp"
    realtime_offset_ns: Optional[int] = None

    def __post_init__(self) -> None:
        if self.realtime_offset_ns is None:
            # CLOCK_MONOTONIC in the sensor container is the host's monotonic
            # clock (no time namespace), so the offset is the same map the
            # analytics server can compute for itself.
            self.realtime_offset_ns = time.time_ns() - time.clock_gettime_ns(
                time.CLOCK_MONOTONIC
            )

    # -- classification ----------------------------------------------------

    def classify(self, raw: Dict[str, Any]) -> str:
        proto = int(raw.get("proto", raw.get("ip_protocol", 0)) or 0)
        sensor_type = str(raw.get("type", "") or "").strip().upper()
        sport = int(raw.get("sport", raw.get("source_port", 0)) or 0)
        dport = int(raw.get("dport", raw.get("destination_port", 0)) or 0)

        mapped = _RAW_TYPE_TO_CLASS.get(sensor_type)
        if proto == IP_PROTO_UDP:
            if 4500 in (sport, dport):
                return classify_udp_4500(sensor_type, sport, dport).classification
            if 500 in (sport, dport):
                return CLASSIFICATION_IKE
            if mapped in (CLASSIFICATION_IKE, CLASSIFICATION_ESP_IN_UDP):
                return mapped
            return CLASSIFICATION_UNKNOWN
        if proto == IP_PROTO_ESP:
            return CLASSIFICATION_ESP
        if proto == IP_PROTO_AH:
            return CLASSIFICATION_AH
        return mapped

    # -- normalization -----------------------------------------------------

    def direction(self, raw: Dict[str, Any]) -> Optional[str]:
        src = _packed(raw.get("src", raw.get("source_ip")))
        if not src:
            return None
        if self.capture_ip and src == self.capture_ip:
            return "outbound"
        if self.capture_ip and _packed(raw.get("dst", raw.get("destination_ip"))) == self.capture_ip:
            return "inbound"
        for label, addr in self.endpoints.items():
            if src == addr:
                return "A_TO_B" if label in ("a", "A") else "B_TO_A"
        if raw.get("direction"):
            return str(raw["direction"])
        return None

    @staticmethod
    def spi_of(raw: Dict[str, Any]) -> Optional[int]:
        spi = raw.get("spi")
        if spi in (None, "", 0):
            return None
        if isinstance(spi, int):
            return spi
        try:
            return int(str(spi), 0)
        except (TypeError, ValueError):
            return None

    def _wall_clock(self, ts: int) -> int:
        if ts <= 0:
            return 0
        return ts + (self.realtime_offset_ns or 0)

    def normalize(self, raw: Dict[str, Any]) -> Dict[str, Any]:
        """Canonical packet payload (timestamp + identity + type + geometry)."""
        ts = int(raw.get("ts", raw.get("timestamp", raw.get("ts_ns", 0))) or 0)
        if isinstance(ts, float):
            ts = int(ts)
        ts = self._wall_clock(ts)
        classification = self.classify(raw)
        return {
            "timestamp": ts,
            "interface": str(raw.get("interface", "")),
            "protocol": int(raw.get("proto", raw.get("ip_protocol", 0)) or 0),
            "source": _packed(raw.get("src", raw.get("source_ip"))),
            "destination": _packed(raw.get("dst", raw.get("destination_ip"))),
            "spi": self.spi_of(raw),
            "sequence": int(raw.get("seq", raw.get("sequence", 0)) or 0),
            "packet_length": int(raw.get("len", raw.get("length")) or 0),
            "source_port": int(raw.get("sport", raw.get("source_port", 0)) or 0),
            "destination_port": int(raw.get("dport", raw.get("destination_port", 0)) or 0),
            "classification": classification,
            "direction": self.direction(raw),
            "sensor_type": classification,
        }

    # -- stream events -----------------------------------------------------

    def to_stream_event(
        self,
        raw: Dict[str, Any],
        identity: CorrelationIdentity,
        *,
        created_at: Optional[int] = None,
    ) -> StreamEvent:
        payload = self.normalize(raw)
        classification = payload["classification"]
        event_type = (
            EVENT_TYPE_IKE if classification in (CLASSIFICATION_IKE,)
            else EVENT_TYPE_PACKET
        )
        return StreamEvent.from_identity(
            identity,
            event_type,
            payload=payload,
            source=self.source,
            created_at=created_at,
        )