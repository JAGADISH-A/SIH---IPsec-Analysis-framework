"""Observed IPsec state model.

This model mirrors the actual ``IPsecStateBuilder.snapshot()`` discovered in
Phase 1 (``D:\\sihipsec\\ebpf\\ipsec_state_builder.py``). It represents what
the state engine can actually observe.

CRYPTO IS NOT INFERRED. Phase 1 established that the state builder:

    * does not infer encryption
    * does not infer integrity
    * does not infer IKE SA establishment
    * does not parse IKE exchange types

Therefore these models have NO crypto fields and MUST NOT pretend such values
are available from the state builder. ``unknown``/``absent`` is expressed by
the field simply being absent (or ``None`` where timestamps/counters may not
apply).
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from ._base import JsonModel

# Documented transition names emitted by the state builder.
TRANSITION_NO_TRAFFIC = "NO_TRAFFIC"
TRANSITION_IPSEC_TRAFFIC_OBSERVED = "IPSEC_TRAFFIC_OBSERVED"
TRANSITION_SPI_OBSERVED = "SPI_OBSERVED"
TRANSITION_ACTIVE = "ACTIVE"
TRANSITION_INACTIVE = "INACTIVE"
DOCUMENTED_TRANSITIONS = (
    TRANSITION_NO_TRAFFIC,
    TRANSITION_IPSEC_TRAFFIC_OBSERVED,
    TRANSITION_SPI_OBSERVED,
    TRANSITION_ACTIVE,
    TRANSITION_INACTIVE,
)

SPI_DIRECTION_A_TO_B = "A_TO_B"
SPI_DIRECTION_B_TO_A = "B_TO_A"
SPI_DIRECTIONS = (SPI_DIRECTION_A_TO_B, SPI_DIRECTION_B_TO_A)

#: The two IPsec encapsulation modes, as ``ObservedState.mode`` carries them.
MODE_TUNNEL = "tunnel"
MODE_TRANSPORT = "transport"
OBSERVED_MODES = (MODE_TUNNEL, MODE_TRANSPORT)

#: A deployed SA report (strongSwan ``swanctl --list-sas``) states the
#: encapsulation mode in upper case -- ``INSTALLED, TRANSPORT``.  These aliases
#: map such a report onto the canonical lower-case observed-state form.
_AUTHORITATIVE_MODE_ALIASES = {
    "TUNNEL": MODE_TUNNEL,
    "TRANSPORT": MODE_TRANSPORT,
    "TUNNEL-MODE": MODE_TUNNEL,
    "TRANSPORT-MODE": MODE_TRANSPORT,
}


def normalize_authoritative_mode(value: Any) -> Optional[str]:
    """Canonicalize a deployed SA's encapsulation mode, or ``None``.

    Accepts what strongSwan reports (``"TRANSPORT"``/``"TUNNEL"``, optionally
    ``-mode`` suffixed, in any case) and the already-canonical lower-case form.
    Anything else -- ``None``, empty strings, unrelated words, non-strings --
    returns ``None`` so the comparison layer treats the variable as
    UNOBSERVED instead of guessing.

    Mode is authoritative only when it comes from the real security
    association.  It is never derivable from the wire: tunnel and transport
    mode place identical protocol-50 ESP on the wire.
    """
    if not isinstance(value, str):
        return None
    return _AUTHORITATIVE_MODE_ALIASES.get(value.strip().upper())


@dataclass(frozen=True)
class SpiObservation(JsonModel):
    """Per-SPI observation from the state builder.

    ``spi`` is preserved exactly as the state engine keyed it (integer, or a
    canonical string form such as ``"0xcda30093"``).
    """

    spi: Any
    direction: Optional[str] = None
    active: bool = False
    first_seen_ns: int = 0
    last_seen_ns: int = 0
    packet_count: int = 0
    first_sequence: Optional[int] = None
    last_sequence: Optional[int] = None
    highest_sequence: Optional[int] = None
    sequence_delta: Optional[int] = None

    def __post_init__(self) -> None:
        if self.spi is None:
            raise ValueError("spi must not be None")
        if self.direction is not None and self.direction not in SPI_DIRECTIONS:
            raise ValueError(
                f"spi.direction must be one of {SPI_DIRECTIONS} or None, "
                f"got {self.direction!r}"
            )
        if not isinstance(self.first_seen_ns, int) or isinstance(
            self.first_seen_ns, bool
        ):
            raise ValueError("first_seen_ns must be an integer")
        if not isinstance(self.last_seen_ns, int) or isinstance(self.last_seen_ns, bool):
            raise ValueError("last_seen_ns must be an integer")
        if self.first_seen_ns < 0 or self.last_seen_ns < 0:
            raise ValueError("SPI timestamps must be >= 0")
        if self.last_seen_ns < self.first_seen_ns:
            raise ValueError(
                f"last_seen_ns ({self.last_seen_ns}) must be >= "
                f"first_seen_ns ({self.first_seen_ns})"
            )
        for n, name in (
            (self.packet_count, "packet_count"),
            (self.first_sequence, "first_sequence"),
            (self.last_sequence, "last_sequence"),
            (self.highest_sequence, "highest_sequence"),
            (self.sequence_delta, "sequence_delta"),
        ):
            if n is not None and (not isinstance(n, int) or isinstance(n, bool)):
                raise ValueError(f"{name} must be an integer or None")
            if n is not None and n < 0:
                raise ValueError(f"{name} must be >= 0, got {n}")

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SpiObservation":
        return cls(
            spi=data["spi"],
            direction=data.get("direction"),
            active=data.get("active", False),
            first_seen_ns=data.get("first_seen_ns", 0),
            last_seen_ns=data.get("last_seen_ns", 0),
            packet_count=data.get("packet_count", 0),
            first_sequence=data.get("first_sequence"),
            last_sequence=data.get("last_sequence"),
            highest_sequence=data.get("highest_sequence"),
            sequence_delta=data.get("sequence_delta"),
        )


@dataclass(frozen=True)
class TransitionObservation(JsonModel):
    """State-engine transition record (name + monotonic timestamp).

    ``details`` preserves any per-transition payload (e.g. SPI/direction for
    ``SPI_OBSERVED``) without constraining its shape.
    """

    name: str
    timestamp_ns: int
    details: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or not self.name.strip():
            raise ValueError("transition name must be a non-empty string")
        if not isinstance(self.timestamp_ns, int) or isinstance(
            self.timestamp_ns, bool
        ):
            raise ValueError("transition timestamp_ns must be an integer")
        if self.timestamp_ns < 0:
            raise ValueError(f"transition timestamp_ns must be >= 0, got {self.timestamp_ns}")
        if not isinstance(self.details, dict):
            raise ValueError("transition details must be a dict")

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "TransitionObservation":
        # The eBPF state builder (``ebpf/ipsec_state_builder.py``) writes the
        # transition name under "type" and keeps any extra payload as sibling
        # keys; this model calls the same value "name" and collects the payload
        # into "details". Accept both spellings so a real snapshot can be read
        # without a translation layer that could quietly drop a field.
        if "name" not in data and "type" not in data:
            raise KeyError("transition requires 'name' (or the state builder's 'type')")
        details = dict(data.get("details") or {})
        for key, value in data.items():
            if key in ("name", "type", "timestamp_ns", "details"):
                continue
            details.setdefault(key, value)
        return cls(
            name=data.get("name") or data["type"],
            timestamp_ns=data["timestamp_ns"],
            details=details,
        )


@dataclass(frozen=True)
class ObservedState(JsonModel):
    """Immutable snapshot of observed IPsec state for one experiment.

    Field names match the Phase 1 ``IPsecStateBuilder.snapshot()`` contract.
    No crypto (encryption / integrity / IKE-SA) fields are modelled.
    """

    timestamp_ns: int
    endpoints: Dict[str, str] = field(default_factory=dict)  # {"a": ..., "b": ...}
    tunnel_seen: bool = False
    active: bool = False
    # Authoritative IPsec *encapsulation mode* of the deployed security
    # association ("tunnel" or "transport"), as reported by the real SA state
    # (strongSwan ``swanctl --list-sas`` -> ``TUNNEL`` / ``TRANSPORT``).
    #
    # This is deliberately NOT derivable from the wire: BOTH modes place ESP
    # (protocol 50) on the wire, so ``esp_seen``/``ah_seen`` cannot distinguish
    # them and inferring one from the other fabricates observation.  ``None``
    # means "no authoritative source supplied", which the comparison layer
    # reports as unknown -- never as a match and never as a mismatch.
    mode: Optional[str] = None
    packets_seen: int = 0
    bytes_seen: int = 0
    packets_a_to_b: int = 0
    packets_b_to_a: int = 0
    bytes_a_to_b: int = 0
    bytes_b_to_a: int = 0
    ike_seen: bool = False
    ike_nat_t_seen: bool = False
    esp_seen: bool = False
    ah_seen: bool = False
    observed_ike_activity: bool = False
    last_ike_timestamp_ns: Optional[int] = None
    last_ike_nat_t_timestamp_ns: Optional[int] = None
    last_esp_timestamp_ns: Optional[int] = None
    last_ah_timestamp_ns: Optional[int] = None
    spis: List[SpiObservation] = field(default_factory=list)
    transitions: List[TransitionObservation] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not isinstance(self.timestamp_ns, int) or isinstance(self.timestamp_ns, bool):
            raise ValueError("timestamp_ns must be an integer")
        if self.timestamp_ns < 0:
            raise ValueError(f"timestamp_ns must be >= 0, got {self.timestamp_ns}")

        counters = (
            ("packets_seen", self.packets_seen),
            ("bytes_seen", self.bytes_seen),
            ("packets_a_to_b", self.packets_a_to_b),
            ("packets_b_to_a", self.packets_b_to_a),
            ("bytes_a_to_b", self.bytes_a_to_b),
            ("bytes_b_to_a", self.bytes_b_to_a),
        )
        for name, value in counters:
            if not isinstance(value, int) or isinstance(value, bool):
                raise ValueError(f"{name} must be an integer")
            if value < 0:
                raise ValueError(f"{name} must be >= 0, got {value}")

        if not isinstance(self.endpoints, dict):
            raise ValueError("endpoints must be a dict")

        if self.mode is not None and self.mode not in ("tunnel", "transport"):
            raise ValueError(
                f"mode must be 'tunnel', 'transport' or None, got {self.mode!r}"
            )

        for label in ("last_ike_timestamp_ns", "last_ike_nat_t_timestamp_ns",
                      "last_esp_timestamp_ns", "last_ah_timestamp_ns"):
            value = getattr(self, label)
            if value is not None and (
                not isinstance(value, int) or isinstance(value, bool)
            ):
                raise ValueError(f"{label} must be an integer or None")
            if value is not None and value < 0:
                raise ValueError(f"{label} must be >= 0, got {value}")
            if value is not None and value > self.timestamp_ns:
                raise ValueError(
                    f"{label} ({value}) must not exceed snapshot timestamp_ns "
                    f"({self.timestamp_ns})"
                )

        for spi in self.spis:
            if not isinstance(spi, SpiObservation):
                raise ValueError("spis must contain SpiObservation objects")
        for t in self.transitions:
            if not isinstance(t, TransitionObservation):
                raise ValueError("transitions must contain TransitionObservation objects")

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ObservedState":
        return cls(
            timestamp_ns=data["timestamp_ns"],
            endpoints=data.get("endpoints") or {},
            tunnel_seen=data.get("tunnel_seen", False),
            active=data.get("active", False),
            mode=data.get("mode"),
            packets_seen=data.get("packets_seen", 0),
            bytes_seen=data.get("bytes_seen", 0),
            packets_a_to_b=data.get("packets_a_to_b", 0),
            packets_b_to_a=data.get("packets_b_to_a", 0),
            bytes_a_to_b=data.get("bytes_a_to_b", 0),
            bytes_b_to_a=data.get("bytes_b_to_a", 0),
            ike_seen=data.get("ike_seen", False),
            ike_nat_t_seen=data.get("ike_nat_t_seen", False),
            esp_seen=data.get("esp_seen", False),
            ah_seen=data.get("ah_seen", False),
            observed_ike_activity=data.get("observed_ike_activity", False),
            last_ike_timestamp_ns=data.get("last_ike_timestamp_ns"),
            last_ike_nat_t_timestamp_ns=data.get("last_ike_nat_t_timestamp_ns"),
            last_esp_timestamp_ns=data.get("last_esp_timestamp_ns"),
            last_ah_timestamp_ns=data.get("last_ah_timestamp_ns"),
            spis=[SpiObservation.from_dict(s) for s in data.get("spis") or []],
            transitions=[
                TransitionObservation.from_dict(t)
                for t in data.get("transitions") or []
            ],
        )