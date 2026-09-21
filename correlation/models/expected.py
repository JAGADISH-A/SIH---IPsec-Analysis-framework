"""Expected testbed state model.

Preserves the exact canonical testbed variable names discovered during Phase 1
(DOT-NOTATION-CANONICAL, serialized as a nested structure because Python field
names cannot contain dots):

    mode            address_family
    ike.version     ike.encryption     ike.integrity      ike.dh_group
    esp.encryption  esp.integrity      esp.dh_group       esp.pfs
    traffic.profile traffic.duration   traffic.port
    capture_filter

Allowed values documented below were discovered from ``D:\\sihipsec``
(``configs/gw-a/swanctl/conf.d/ipsec.conf``, ``dataset_planner`` variables,
Phase 1 report /tv tables). ``configuration_id`` and ``security_posture`` are
DERIVED metadata (Phase 1: ``posture_of_config`` is the authority; posture is
NOT re-computed here — only its resulting value is represented).
"""

from dataclasses import dataclass
from typing import Any, Dict, Optional

from ._base import JsonModel
from .observability import OBSERVABILITY, Observability

CANONICAL_VARIABLES = (
    "mode",
    "address_family",
    "ike.version",
    "ike.encryption",
    "ike.integrity",
    "ike.dh_group",
    "esp.encryption",
    "esp.integrity",
    "esp.dh_group",
    "esp.pfs",
    "traffic.profile",
    "traffic.duration",
    "traffic.port",
    "capture_filter",
)

# Documented allowed values (Phase 1 discovery; repository stays authoritative).
ALLOWED_MODES = ("tunnel", "transport")
ALLOWED_ADDRESS_FAMILIES = ("ipv4", "ipv6")
ALLOWED_IKE_VERSIONS = (1, 2)
ALLOWED_IKE_ENCRYPTION = ("aes128", "aes256")
ALLOWED_IKE_INTEGRITY = ("sha256", "sha384", "sha512")
ALLOWED_IKE_DH_GROUPS = ("modp2048", "modp3072", "modp4096")
ALLOWED_ESP_ENCRYPTION = ("aes128gcm16", "aes256gcm16", "aes128cbc", "aes256cbc")
ALLOWED_ESP_INTEGRITY = (None, "sha256", "sha384", "sha512")
ALLOWED_ESP_DH_GROUPS = ("modp2048", "modp3072", "modp4096")
ALLOWED_TRAFFIC_PROFILES = ("video", "voip", "messaging", "email", "web", "icmp")
TRAFFIC_DURATION_RANGE = (10, 120)
TRAFFIC_PORT_RANGE = (1, 65535)


def _require_in(value: Any, allowed, name: str) -> None:
    if value not in allowed:
        raise ValueError(
            f"{name} must be one of {allowed}, got {value!r}"
        )


def _bool_field(value: Any, name: str) -> bool:
    if not isinstance(value, bool):
        raise ValueError(f"{name} must be a bool, got {value!r}")
    return value


@dataclass(frozen=True)
class IkeExpected(JsonModel):
    """Canonical ``ike.*`` expected variables."""

    version: int
    encryption: str
    integrity: str
    dh_group: str

    def __post_init__(self) -> None:
        if not isinstance(self.version, int) or isinstance(self.version, bool):
            raise ValueError("ike.version must be an integer")
        _require_in(self.version, ALLOWED_IKE_VERSIONS, "ike.version")
        _require_in(self.encryption, ALLOWED_IKE_ENCRYPTION, "ike.encryption")
        _require_in(self.integrity, ALLOWED_IKE_INTEGRITY, "ike.integrity")
        _require_in(self.dh_group, ALLOWED_IKE_DH_GROUPS, "ike.dh_group")

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "IkeExpected":
        return cls(
            version=data["version"],
            encryption=data["encryption"],
            integrity=data["integrity"],
            dh_group=data["dh_group"],
        )


@dataclass(frozen=True)
class EspExpected(JsonModel):
    """Canonical ``esp.*`` expected variables."""

    encryption: str
    integrity: Optional[str]
    dh_group: str
    pfs: bool

    def __post_init__(self) -> None:
        _require_in(self.encryption, ALLOWED_ESP_ENCRYPTION, "esp.encryption")
        _require_in(self.integrity, ALLOWED_ESP_INTEGRITY, "esp.integrity")
        _require_in(self.dh_group, ALLOWED_ESP_DH_GROUPS, "esp.dh_group")
        _bool_field(self.pfs, "esp.pfs")

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "EspExpected":
        return cls(
            encryption=data["encryption"],
            integrity=data.get("integrity"),
            dh_group=data["dh_group"],
            pfs=data["pfs"],
        )


@dataclass(frozen=True)
class TrafficExpected(JsonModel):
    """Canonical ``traffic.*`` expected variables."""

    profile: str
    duration: int
    port: int

    def __post_init__(self) -> None:
        _require_in(self.profile, ALLOWED_TRAFFIC_PROFILES, "traffic.profile")
        if not isinstance(self.duration, int) or isinstance(self.duration, bool):
            raise ValueError("traffic.duration must be an integer")
        if not (TRAFFIC_DURATION_RANGE[0] <= self.duration <= TRAFFIC_DURATION_RANGE[1]):
            raise ValueError(
                f"traffic.duration must be in {TRAFFIC_DURATION_RANGE}, got {self.duration}"
            )
        if not isinstance(self.port, int) or isinstance(self.port, bool):
            raise ValueError("traffic.port must be an integer")
        if not (TRAFFIC_PORT_RANGE[0] <= self.port <= TRAFFIC_PORT_RANGE[1]):
            raise ValueError(
                f"traffic.port must be in {TRAFFIC_PORT_RANGE}, got {self.port}"
            )

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "TrafficExpected":
        return cls(
            profile=data["profile"],
            duration=data["duration"],
            port=data["port"],
        )


@dataclass(frozen=True)
class ExpectedState(JsonModel):
    """Expected testbed state for one experiment.

    ``configuration_id`` and ``security_posture`` are optional DERIVED
    metadata. ``security_posture`` is only represented (<None> unless supplied
    by the authority ``posture_of_config``); the posture calculation is NOT
    re-implemented here.
    """

    mode: str
    address_family: str
    ike: IkeExpected
    esp: EspExpected
    traffic: TrafficExpected
    capture_filter: str
    configuration_id: Optional[str] = None
    security_posture: Optional[str] = None

    def __post_init__(self) -> None:
        _require_in(self.mode, ALLOWED_MODES, "mode")
        _require_in(self.address_family, ALLOWED_ADDRESS_FAMILIES, "address_family")
        if not isinstance(self.capture_filter, str) or not self.capture_filter.strip():
            raise ValueError("capture_filter must be a non-empty string")
        if self.configuration_id is not None and not isinstance(
            self.configuration_id, str
        ):
            raise ValueError("configuration_id must be a string or None")
        if self.security_posture is not None:
            if not isinstance(self.security_posture, str) or not self.security_posture:
                raise ValueError("security_posture must be a non-empty string or None")

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ExpectedState":
        return cls(
            mode=data["mode"],
            address_family=data["address_family"],
            ike=IkeExpected.from_dict(data["ike"]),
            esp=EspExpected.from_dict(data["esp"]),
            traffic=TrafficExpected.from_dict(data["traffic"]),
            capture_filter=data["capture_filter"],
            configuration_id=data.get("configuration_id"),
            security_posture=data.get("security_posture"),
        )

    def derive_configuration_id(self) -> str:
        """Derive ``configuration_id`` using the documented deterministic
        grammar (``mode-address_family-esp_encryption-esp_integrity-none-esp_dh_group-pfs``).

        Convenience only; the authority remains ``dataset_planner`` in the
        SIHPsec repository. ``security_posture`` is never derived here.
        """
        integrity = self.esp.integrity or "none"
        return (
            f"{self.mode}-{self.address_family}-{self.esp.encryption}-"
            f"{integrity}-{self.esp.dh_group}-{str(self.esp.pfs).lower()}"
        )

    def observability(self) -> Dict[str, str]:
        """Return canonical-variable -> observability classification.

        Metadata only (see ``correlation/models/observability.py``); not a
        risk signal.
        """
        return dict(OBSERVABILITY)

    def observability_of(self, canonical_variable: str) -> str:
        return OBSERVABILITY[canonical_variable]

    @property
    def observability_level(self):
        return Observability