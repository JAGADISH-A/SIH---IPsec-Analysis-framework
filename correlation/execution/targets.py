"""Execution targets & allow-list (Phase 10).

Targets are STRUCTURED and validated: a network action always names a concrete
source/destination/protocol/ports. There is deliberately no "wildcard target"
shortcut: every production/testbed execution must be able to declare one
concrete target that the allow-list can check.

Allow-list semantics (deterministic, fail closed):

    * an EMPTY allow-list allows NOTHING (safe default);
    * CIDR entries are supported (IPv4 + IPv6);
    * a target is allowed only when its ``destination`` falls inside an
      allowed network (or matches an exact host) — protocol/port are policy
      attributes the settings gate may also constrain;
    * UNKNOWN address families (unparsable values) are NEVER allowed.
"""

import ipaddress
from dataclasses import dataclass, field
from typing import Any, Dict, Optional, Sequence, Union

IP_VERSION_IPV4 = "ipv4"
IP_VERSION_IPV6 = "ipv6"
IP_VERSION_UNKNOWN = "UNKNOWN"


def parse_ip_version(host: Any) -> str:
    if host is None:
        return IP_VERSION_UNKNOWN
    try:
        return IP_VERSION_IPV4 if ipaddress.ip_address(str(host)).version == 4 else IP_VERSION_IPV6
    except ValueError:
        return IP_VERSION_UNKNOWN


def _ip(value: Any):
    try:
        return ipaddress.ip_address(str(value))
    except ValueError:
        return None


@dataclass(frozen=True)
class ExecutionTarget:
    """One concrete target for a controlled network operation."""

    source: str = ""
    destination: str = ""
    protocol: int = 0
    source_port: int = 0
    destination_port: int = 0
    ip_version: str = IP_VERSION_UNKNOWN

    def __post_init__(self) -> None:
        family = parse_ip_version(self.destination)
        if family == IP_VERSION_UNKNOWN:
            raise ValueError(
                f"destination {self.destination!r} is not a parsable IP address; "
                "an explicit structured target requires a real destination"
            )
        for name, value in (
            ("source_port", self.source_port),
            ("destination_port", self.destination_port),
        ):
            if not isinstance(value, int) or isinstance(value, bool) or not (0 <= value <= 65535):
                raise ValueError(f"{name} must be an int in [0, 65535]")
        if not isinstance(self.protocol, int) or not (0 <= self.protocol <= 255):
            raise ValueError("protocol must be an int in [0, 255]")
        if self.source:
            sf = parse_ip_version(self.source)
            if sf == IP_VERSION_UNKNOWN:
                raise ValueError(
                    f"source {self.source!r} is not a parsable IP address"
                )
        version = parse_ip_version(self.destination)
        if not self.ip_version or self.ip_version == IP_VERSION_UNKNOWN:
            object.__setattr__(self, "ip_version", version)
        elif self.ip_version != version:
            raise ValueError(
                f"ip_version {self.ip_version!r} does not match destination "
                f"family {version}"
            )

    def key(self) -> str:
        return "|".join(
            (
                self.destination,
                str(self.protocol),
                str(self.destination_port),
            )
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source": self.source,
            "destination": self.destination,
            "protocol": self.protocol,
            "source_port": self.source_port,
            "destination_port": self.destination_port,
            "ip_version": self.ip_version,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ExecutionTarget":
        return cls(
            source=str(data.get("source") or ""),
            destination=str(data.get("destination") or ""),
            protocol=int(data.get("protocol") or 0),
            source_port=int(data.get("source_port") or 0),
            destination_port=int(data.get("destination_port") or 0),
            ip_version=data.get("ip_version") or IP_VERSION_UNKNOWN,
        )


@dataclass(frozen=True)
class TargetAllowlist:
    """Fail-closed allow-list of permitted destinations (CIDR or exact host)."""

    networks: Sequence[str] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        parsed = []
        for entry in self.networks:
            if not isinstance(entry, str) or not entry.strip():
                raise ValueError("allow-list entries must be non-empty strings")
            try:
                parsed.append(ipaddress.ip_network(entry.strip(), strict=False))
            except ValueError as exc:
                raise ValueError(f"invalid allow-list network {entry!r}: {exc}") from exc
        object.__setattr__(self, "_parsed", tuple(parsed))

    def allows(self, destination: str) -> bool:
        ip = _ip(destination)
        if ip is None:
            return False
        for network in getattr(self, "_parsed", ()):
            if ip in network:
                return True
        return False

    def allows_target(self, target: Union[ExecutionTarget, Dict[str, Any]]) -> bool:
        if isinstance(target, ExecutionTarget):
            return self.allows(target.destination)
        return self.allows(str(target.get("destination") or ""))

    def to_dict(self) -> Dict[str, Any]:
        return {"networks": list(self.networks)}