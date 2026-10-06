"""Area 4 -- metadata exposure.

Lists what a passive observer of this capture *actually* gets to see, with
each dimension carrying its own state and the reason for that state. The
product answers three questions and keeps them separate:

* ``observable_metadata`` -- which metadata dimensions this sensor can see,
  each with ``observable``, ``value``, ``state``, ``source`` and ``reason``;
* ``findings`` -- observation-level statements about exposure (``EXPOSED``,
  ``NOT_EXPOSED``, ``NOT_OBSERVABLE``) with their evidence. These are NOT risk
  findings: the risk engine owns severity, score and finding id, and no value
  in this module is ever scored;
* ``risk_level`` -- one value chosen by a documented, deterministic ladder,
  never by a threshold that only the current data happens to cross.

What this observation path records is exactly what the state builder emits:
outer endpoints, protocol presence, SPI values, per-SPI direction labels,
byte/packet counters and timestamps. Payload bytes, transport ports, IKE
header fields (version, cookies, identities) and (in tunnel mode) inner
addresses are never decoded, so they are reported as not observable rather
than as safe.
"""

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from ..models import ObservedState
from .states import (
    STATE_NOT_APPLICABLE,
    STATE_NOT_AVAILABLE,
    STATE_OBSERVED,
    STATE_UNKNOWN,
    validate_state,
)

#: Exposure markers used by ``findings``. Deliberately not severities: this
#: product never assigns a severity or a score.
EXPOSURE_EXPOSED = "EXPOSED"
EXPOSURE_NOT_EXPOSED = "NOT_EXPOSED"
EXPOSURE_NOT_OBSERVABLE = "NOT_OBSERVABLE"
EXPOSURES = (EXPOSURE_EXPOSED, EXPOSURE_NOT_EXPOSED, EXPOSURE_NOT_OBSERVABLE)

#: ``risk_level`` ladder, evaluated in order. The first match wins, which makes
#: the value reproducible from the dimension list alone.
RISK_LEVEL_HIGH = "HIGH"
RISK_LEVEL_MEDIUM = "MEDIUM"
RISK_LEVEL_LOW = "LOW"
RISK_LEVEL_NONE = "NONE"

OUTER_ENDPOINTS = "outer_endpoints"
PROTOCOL_NUMBERS = "protocol_numbers"
IKE_ESP_METADATA = "ike_esp_metadata"
SECURITY_PARAMETER_INDEX = "security_parameter_index"
PACKET_DIRECTION = "packet_direction"
TRAFFIC_VOLUME = "traffic_volume"
TIMING = "timing_and_volume"
PACKET_SIZES = "packet_sizes"
TRANSPORT_PORTS = "transport_ports"
INNER_ADDRESSES = "inner_addresses"
PAYLOAD_CONTENT = "payload_content"

#: Every dimension this product classifies, in report order. The observation
#: path records what it records: nothing here is inferred, and a dimension no
#: sensor recorded stays NOT_AVAILABLE rather than becoming NOT_APPLICABLE.
_METADATA_DIMENSIONS: Tuple[str, ...] = (
    OUTER_ENDPOINTS,
    PROTOCOL_NUMBERS,
    IKE_ESP_METADATA,
    SECURITY_PARAMETER_INDEX,
    PACKET_DIRECTION,
    TRAFFIC_VOLUME,
    TIMING,
    PACKET_SIZES,
    TRANSPORT_PORTS,
    INNER_ADDRESSES,
    PAYLOAD_CONTENT,
)

@dataclass(frozen=True)
class MetadataDimension:
    """One metadata dimension and what this sensor can say about it."""

    dimension: str
    observable: bool
    value: Any
    state: str
    source: str
    reason: str
    exposure: str = EXPOSURE_NOT_OBSERVABLE

    def __post_init__(self) -> None:
        validate_state(self.state)
        if self.exposure not in EXPOSURES:
            raise ValueError(f"unknown exposure marker: {self.exposure!r}")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "dimension": self.dimension,
            "observable": self.observable,
            "value": self.value,
            "state": self.state,
            "source": self.source,
            "reason": self.reason,
            "exposure": self.exposure,
        }


@dataclass(frozen=True)
class MetadataExposure:
    """The complete metadata-exposure product for one assessment."""

    state: str
    reason: str
    source: str
    risk_level: str
    observable_metadata: tuple = ()
    findings: tuple = ()
    evidence: tuple = ()
    limitations: tuple = ()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "state": self.state,
            "reason": self.reason,
            "source": self.source,
            "risk_level": self.risk_level,
            "risk_ladder": _ladder_document(),
            "observable_metadata": [d.to_dict() for d in self.observable_metadata],
            "findings": [dict(f) for f in self.findings],
            "evidence": [dict(e) for e in self.evidence],
            "limitations": list(self.limitations),
        }


def _ladder_document() -> List[Dict[str, str]]:
    """The ``risk_level`` ladder, published beside the value it produced."""
    return [
        {
            "risk_level": RISK_LEVEL_HIGH,
            "condition": "payload content is observable by this sensor",
            "meaning": (
                "captured bytes include application content, so metadata "
                "exposure is not the limiting concern"
            ),
        },
        {
            "risk_level": RISK_LEVEL_MEDIUM,
            "condition": (
                "payload content is not observable, but outer addresses, "
                "timing and volume are"
            ),
            "meaning": (
                "an on-path observer can map topology and traffic behaviour "
                "(who talks, when, how much) while content stays out of reach"
            ),
        },
        {
            "risk_level": RISK_LEVEL_LOW,
            "condition": (
                "only coarse metadata is observable (protocol presence and "
                "volume) without addresses or timing"
            ),
            "meaning": "little beyond 'this pair exchanges IPsec traffic'",
        },
        {
            "risk_level": RISK_LEVEL_NONE,
            "condition": "no metadata dimension is observable",
            "meaning": "nothing was recorded for this assessment",
        },
    ]


def _has_addresses(observed: ObservedState) -> bool:
    endpoints = getattr(observed, "endpoints", None)
    if endpoints:
        return bool(endpoints.get("a")) and bool(endpoints.get("b"))
    return any(
        bool(getattr(spi, "outer_a", None)) and bool(getattr(spi, "outer_b", None))
        for spi in observed.spis
    )


def _has_timing(observed: ObservedState) -> bool:
    if getattr(observed, "observation_start_ns", None):
        return True
    if getattr(observed, "last_esp_timestamp_ns", None):
        return True
    return any(getattr(spi, "first_seen_ns", None) for spi in observed.spis)


def _has_volume(observed: ObservedState) -> bool:
    return bool(getattr(observed, "bytes_seen", 0)) or bool(
        getattr(observed, "packets_seen", 0)
    )


def _risk_level(dimensions: List[MetadataDimension]) -> Tuple[str, str]:
    by_name = {d.dimension: d for d in dimensions}
    if by_name[PAYLOAD_CONTENT].observable:
        return (
            RISK_LEVEL_HIGH,
            "The ladder reports HIGH because payload content is observable, "
            "which outranks every metadata-only exposure.",
        )
    if _addresses_and_timing(by_name):
        return (
            RISK_LEVEL_MEDIUM,
            "The ladder reports MEDIUM: payload content is not observable, but "
            "outer addresses, timing and volume are, so topology and traffic "
            "behaviour are exposed to an on-path observer.",
        )
    if any(by_name[name].observable for name in (PROTOCOL_NUMBERS, TRAFFIC_VOLUME)):
        return (
            RISK_LEVEL_LOW,
            "The ladder reports LOW: only coarse metadata (protocol presence "
            "and volume) is observable, with no addresses or timing recorded.",
        )
    return (
        RISK_LEVEL_NONE,
        "The ladder reports NONE because no metadata dimension is observable "
        "for this assessment.",
    )


def _addresses_and_timing(by_name: Dict[str, MetadataDimension]) -> bool:
    return (
        by_name[OUTER_ENDPOINTS].observable
        and by_name[TIMING].observable
        and by_name[TRAFFIC_VOLUME].observable
    )


def _dimension(
    name: str,
    *,
    observable: bool,
    value: Any,
    state: str,
    source: str,
    reason: str,
    exposure: str = EXPOSURE_NOT_OBSERVABLE,
) -> MetadataDimension:
    return MetadataDimension(
        dimension=name,
        observable=observable,
        value=value,
        state=state,
        source=source,
        reason=reason,
        exposure=exposure,
    )


def analyze_metadata_exposure(
    observed: Optional[ObservedState] = None,
    *,
    source: str = "observed-state snapshot",
) -> MetadataExposure:
    """Classify every metadata dimension for one assessment."""
    observed_present = observed is not None and (
        observed.timestamp_ns != 0 or bool(observed.spis)
    )
    dimensions: List[MetadataDimension] = []
    evidence: List[Dict[str, Any]] = []

    if not observed_present:
        reason = (
            "No ipsec_state_builder snapshot was supplied for this assessment, "
            "so no metadata dimension could be classified from an observation."
        )
        for name in _METADATA_DIMENSIONS:
            dimensions.append(
                _dimension(
                    name,
                    observable=False,
                    value=None,
                    state=STATE_NOT_AVAILABLE,
                    source=source,
                    reason=reason,
                )
            )
        return MetadataExposure(
            state=STATE_NOT_AVAILABLE,
            reason=reason,
            source=source,
            risk_level=RISK_LEVEL_NONE,
            observable_metadata=tuple(dimensions),
            findings=(),
            evidence=(),
            limitations=(
                "No observation means no exposure assessment; this is an "
                "evidence gap, not an absence of exposure.",
            ),
        )

    endpoints = dict(observed.endpoints) if observed.endpoints else {}
    addresses = _has_addresses(observed)
    dimensions.append(
        _dimension(
            OUTER_ENDPOINTS,
            observable=addresses,
            value=endpoints or None,
            state=STATE_OBSERVED if addresses else STATE_NOT_AVAILABLE,
            source=f"{source} (endpoints / spis[].outer_*)",
            reason=(
                "The outer source and destination addresses are written into "
                "every state line the sensor emits, so an on-path observer "
                "recovers the tunnel endpoints directly."
                if addresses
                else "This snapshot recorded no outer endpoint pair."
            ),
            exposure=EXPOSURE_EXPOSED if addresses else EXPOSURE_NOT_OBSERVABLE,
        )
    )

    protocols = {
        "esp": bool(observed.esp_seen),
        "ah": bool(observed.ah_seen),
        "ike": bool(observed.ike_seen),
        "ike_nat_t": bool(getattr(observed, "ike_nat_t_seen", False)),
    }
    recorded_protocols = observed.esp_seen or observed.ah_seen or observed.ike_seen
    dimensions.append(
        _dimension(
            PROTOCOL_NUMBERS,
            observable=True,
            value=protocols,
            state=STATE_OBSERVED,
            source=f"{source} (esp_seen / ah_seen / ike_seen / ike_nat_t_seen)",
            reason=(
                "Protocol presence is a recorded fact of the snapshot: the IP "
                "protocol number and the UDP 500/4500 ports are cleartext in "
                "every packet header."
            ),
            exposure=EXPOSURE_EXPOSED,
        )
    )
    if recorded_protocols:
        evidence.append(
            {
                "dimension": PROTOCOL_NUMBERS,
                "observed": protocols,
                "source": source,
            }
        )

    any_protocol = bool(
        observed.esp_seen or observed.ah_seen or observed.ike_seen
    )
    dimensions.append(
        _dimension(
            IKE_ESP_METADATA,
            observable=any_protocol,
            value=(
                {
                    "protocol_presence": dict(protocols),
                    "ike_version": None,
                    "ike_initiator_cookie": None,
                    "ike_responder_cookie": None,
                    "ike_identity": None,
                    "negotiated_cipher": None,
                }
                if any_protocol
                else None
            ),
            state=STATE_OBSERVED if any_protocol else STATE_NOT_AVAILABLE,
            source=(
                f"{source} (esp_seen / ah_seen / ike_seen / ike_nat_t_seen; "
                "IKE and ESP header fields are never decoded)"
            ),
            reason=(
                "Which of ESP, AH and IKE ran is cleartext in the packet "
                "headers this sensor reads, so presence is observable. The "
                "IKE version, cookies, identities and the negotiated cipher "
                "live in handshake or payload bytes that are never decoded "
                "here, so those fields are recorded as null rather than "
                "guessed."
                if any_protocol
                else "This snapshot recorded no ESP, AH or IKE packet, so "
                     "neither protocol presence nor any IKE/ESP header field "
                     "is available from it."
            ),
            exposure=(
                EXPOSURE_EXPOSED if any_protocol else EXPOSURE_NOT_OBSERVABLE
            ),
        )
    )

    spi_values = [spi.spi for spi in observed.spis]
    dimensions.append(
        _dimension(
            SECURITY_PARAMETER_INDEX,
            observable=bool(spi_values),
            value=spi_values or None,
            state=STATE_OBSERVED if spi_values else STATE_NOT_AVAILABLE,
            source=f"{source} (spis[].spi)",
            reason=(
                "The 32-bit SPI travels in cleartext with every ESP packet and "
                "indexes the security association, so it is a stable, "
                "observer-visible handle on the SA."
                if spi_values
                else "This snapshot recorded no SPI."
            ),
            exposure=EXPOSURE_EXPOSED if spi_values else EXPOSURE_NOT_OBSERVABLE,
        )
    )

    directions = [
        spi.direction for spi in observed.spis
        if getattr(spi, "direction", None)
    ]
    has_direction = bool(directions)
    dimensions.append(
        _dimension(
            PACKET_DIRECTION,
            observable=has_direction,
            value=(
                {
                    "directions": sorted(set(directions)),
                    "per_spi": [
                        {"spi": spi.spi, "direction": spi.direction}
                        for spi in observed.spis
                        if getattr(spi, "direction", None)
                    ],
                }
                if has_direction
                else None
            ),
            state=STATE_OBSERVED if has_direction else STATE_NOT_AVAILABLE,
            source=f"{source} (spis[].direction)",
            reason=(
                "The direction label is recorded per SPI by the state builder "
                "(A_TO_B or B_TO_A), so who sends and who replies is readable "
                "from the capture's own record."
                if has_direction
                else "This snapshot recorded no per-SPI direction label, so "
                     "the direction of travel is not available from it."
            ),
            exposure=(
                EXPOSURE_EXPOSED if has_direction else EXPOSURE_NOT_OBSERVABLE
            ),
        )
    )

    volume = {
        "bytes_seen": getattr(observed, "bytes_seen", None),
        "packets_seen": getattr(observed, "packets_seen", None),
        "bytes_a_to_b": getattr(observed, "bytes_a_to_b", None),
        "bytes_b_to_a": getattr(observed, "bytes_b_to_a", None),
    }
    has_volume = _has_volume(observed)
    dimensions.append(
        _dimension(
            TRAFFIC_VOLUME,
            observable=has_volume,
            value=volume if has_volume else None,
            state=STATE_OBSERVED if has_volume else STATE_NOT_AVAILABLE,
            source=f"{source} (bytes_seen / packets_seen / per-direction counters)",
            reason=(
                "Volume counters are recorded per snapshot and the IP total "
                "length field is cleartext, so how much traffic flows is "
                "recoverable without any decryption."
            ),
            exposure=EXPOSURE_EXPOSED if has_volume else EXPOSURE_NOT_OBSERVABLE,
        )
    )

    has_timing = _has_timing(observed)
    timing = {
        "observation_start_ns": getattr(observed, "observation_start_ns", None),
        "last_packet_timestamp_ns": getattr(
            observed, "last_packet_timestamp_ns", None
        ),
        "first_seen_ns": [spi.first_seen_ns for spi in observed.spis],
        "last_seen_ns": [spi.last_seen_ns for spi in observed.spis],
    }
    dimensions.append(
        _dimension(
            TIMING,
            observable=has_timing,
            value=timing if has_timing else None,
            state=STATE_OBSERVED if has_timing else STATE_NOT_AVAILABLE,
            source=f"{source} (observation window / spis[].first_seen_ns)",
            reason=(
                "Packet timestamps are recorded per SPI and per snapshot, so "
                "when traffic runs, how bursty it is and when it stops are all "
                "observable from the wire."
            ),
            exposure=EXPOSURE_EXPOSED if has_timing else EXPOSURE_NOT_OBSERVABLE,
        )
    )

    has_sizes = has_volume
    dimensions.append(
        _dimension(
            PACKET_SIZES,
            observable=has_sizes,
            value=(
                {
                    "packets_seen": observed.packets_seen,
                    "bytes_seen": getattr(observed, "bytes_seen", None),
                }
                if has_sizes
                else None
            ),
            state=STATE_OBSERVED if has_sizes else STATE_NOT_AVAILABLE,
            source=f"{source} (byte and packet counters)",
            reason=(
                "Packet sizes are visible in the IP header and are aggregated "
                "into the snapshot's byte and packet counters, so size "
                "distributions are observable."
            ),
            exposure=EXPOSURE_EXPOSED if has_sizes else EXPOSURE_NOT_OBSERVABLE,
        )
    )

    dimensions.append(
        _dimension(
            TRANSPORT_PORTS,
            observable=False,
            value=None,
            state=STATE_NOT_AVAILABLE,
            source="not recorded by the observation path",
            reason=(
                "Transport ports are cleartext on the wire in transport mode "
                "and inside the ESP payload in tunnel mode, but the state "
                "builder records counters and SA state only: it never writes "
                "a port field. The capability exists on the wire; this "
                "backend records no value, so the state is NOT_AVAILABLE "
                "rather than NOT_APPLICABLE."
            ),
        )
    )

    dimensions.append(
        _dimension(
            INNER_ADDRESSES,
            observable=False,
            value=None,
            state=STATE_NOT_APPLICABLE,
            source="not decoded by the observation path",
            reason=(
                "Inner (tunnel-mode) addresses sit inside the ESP payload. "
                "This sensor never decrypts and never writes an inner endpoint "
                "field, so inner addressing is not observable. Note that "
                "tunnel_seen does NOT establish tunnel mode: the state builder "
                "records it as 'any traffic was observed'."
            ),
        )
    )

    dimensions.append(
        _dimension(
            PAYLOAD_CONTENT,
            observable=False,
            value=None,
            state=STATE_NOT_APPLICABLE,
            source="payload inspection was never performed",
            reason=(
                "Payload content is reported as not observable, not as safe: "
                "the observation path records counters, headers and SA state "
                "and never decodes ESP payload bytes, and the negotiated "
                "cipher itself is reported UNKNOWN by the crypto-evidence "
                "product. No payload inspection was performed, so no "
                "payload-based conclusion of any kind is available."
            ),
        )
    )

    by_name = {d.dimension: d for d in dimensions}
    findings: List[Dict[str, Any]] = []

    def add_finding(name: str, finding: str, exposure: str, why: str) -> None:
        dimension = by_name[name]
        findings.append(
            {
                "dimension": name,
                "finding": finding,
                "exposure": exposure,
                "reason": why,
                "evidence": [
                    {
                        "dimension": name,
                        "value": dimension.value,
                        "state": dimension.state,
                        "source": dimension.source,
                    }
                ],
                "scoring": (
                    "observation-level metadata finding; it carries no "
                    "severity and is not scored. The risk engine is the only "
                    "scorer in this backend."
                ),
            }
        )

    if by_name[OUTER_ENDPOINTS].observable:
        add_finding(
            OUTER_ENDPOINTS,
            "Outer tunnel endpoints are visible to any on-path observer.",
            EXPOSURE_EXPOSED,
            by_name[OUTER_ENDPOINTS].reason,
        )
    if by_name[SECURITY_PARAMETER_INDEX].observable:
        add_finding(
            SECURITY_PARAMETER_INDEX,
            "SPI values travel in cleartext and identify each security "
            "association.",
            EXPOSURE_EXPOSED,
            by_name[SECURITY_PARAMETER_INDEX].reason,
        )
    if by_name[TIMING].observable and by_name[TRAFFIC_VOLUME].observable:
        add_finding(
            TIMING,
            "Traffic timing and volume are observable, which enables traffic "
            "analysis without decryption.",
            EXPOSURE_EXPOSED,
            by_name[TIMING].reason,
        )
    add_finding(
        PAYLOAD_CONTENT,
        "Payload content was not inspected and is reported as not observable.",
        EXPOSURE_NOT_OBSERVABLE,
        by_name[PAYLOAD_CONTENT].reason,
    )
    add_finding(
        TRANSPORT_PORTS,
        "Transport ports were not recorded by this sensor.",
        EXPOSURE_NOT_OBSERVABLE,
        by_name[TRANSPORT_PORTS].reason,
    )

    risk_level, ladder_reason = _risk_level(dimensions)
    observable_count = sum(1 for d in dimensions if d.observable)
    return MetadataExposure(
        state=STATE_OBSERVED if observable_count else STATE_NOT_AVAILABLE,
        reason=(
            f"{observable_count} of {len(dimensions)} metadata dimensions are "
            f"observable from this capture; risk_level is {risk_level}. "
            + ladder_reason
        ),
        source=source,
        risk_level=risk_level,
        observable_metadata=tuple(dimensions),
        findings=tuple(findings),
        evidence=tuple(evidence),
        limitations=(
            "An observable dimension is a capability of the capture, not a "
            "claim that anyone collected it.",
            "Not observable never means safe: payload content is reported as "
            "NOT_APPLICABLE because no inspection was performed.",
            "These findings are observation-level statements about exposure. "
            "They carry no severity and no score; severity, score and finding "
            "identity belong to the risk engine alone.",
        ),
    )
