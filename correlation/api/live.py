"""Phase 10 — live API context (wires health, metrics, PCAP, traffic
generator) for the transport layer — PASSIVE OBSERVATION ONLY.

``Phase10Context`` is a deterministic, explicit wiring point. It is
constructed from any registry/metrics instances; every component is
replaceable for tests. It is READ-ONLY for the dashboard: no
action/approval/target inputs are accepted here.

The deployed application is PASSIVE-ONLY. This context wires only
observability surfaces (health, metrics, PCAP/evidence metadata, traffic
generator status). The Phase-10 XDP execution/enforcement machinery
(``correlation.execution``) is NOT wired here: XDP/eBPF is used for passive
observation, the sensor is non-inline and receives mirrored/tapped traffic,
and XDP enforcement actions are not part of the deployed passive application
architecture.
"""

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Optional

from ..observability import Phase10Metrics, HealthRegistry, healthy, disabled, unavailable
from .pcap import PcapRegistry, PcapService


class TrafficGeneratorMonitor:
    """Deterministic traffic-generator status feed (HTTP-only, no control)."""

    def __init__(self, status_fn: Optional[Callable[[], Dict[str, Any]]] = None) -> None:
        self._status_fn = status_fn

    def status(self) -> Dict[str, Any]:
        if self._status_fn is not None:
            return dict(self._status_fn())
        return {
            "running": None,
            "monitored": False,
            "detail": (
                "no traffic-generator feed is configured; status stays "
                "UNKNOWN (never fabricated)"
            ),
        }


def _noop_report() -> Dict[str, Any]:
    return {}


@dataclass
class Phase10Context:
    """All Phase-10 API dependencies in one explicitly-wired context."""

    metrics: Phase10Metrics = field(default_factory=Phase10Metrics)
    health: HealthRegistry = field(default_factory=HealthRegistry)
    pcap: Optional[PcapService] = None
    traffic_generator: TrafficGeneratorMonitor = field(default_factory=TrafficGeneratorMonitor)
    #: Optional read-only query layer over the analysis audit journal. When it
    #: is None the audit routes report "no journal configured" rather than
    #: inventing evidence; it is never written to from a request.
    audit_store: Optional[Any] = None

    def __post_init__(self) -> None:
        if self.pcap is None:
            self.pcap = PcapService(PcapRegistry(root=""))
        self._seed_health()

    def attach_audit_store(self, store) -> None:
        """Wire the audit query layer. Explicit, like every other dependency."""
        self.audit_store = store

    def _seed_health(self) -> None:
        if self.health._components:
            return
        self.health.set(healthy("kafka", "streaming contract wired (in-memory transport)"))
        self.health.set(
            healthy(
                "xdp_sensor",
                "passive non-inline observation of mirrored/tapped traffic "
                "(no XDP enforcement action)",
            )
        )
        self.health.set(
            unavailable("swanctl", "no swanctl adapter connection configured")
        )
        self.health.set(
            unavailable("evidence", "no evidence registry configured")
        )
        self.health.set(
            disabled("ml", "ML consumption depends on a configured model")
        )

    def summary(self) -> Dict[str, Any]:
        return {
            "passive_only": True,
            "health": self.health.overall.status,
            "metrics_points": len(self.metrics.collect_all()),
            "registered_evidence": len(self.pcap.registry._mapping),
            "pcap_downloads": self.pcap.download_count,
            "traffic_generator": self.traffic_generator.status(),
            "audit_journal_configured": self.audit_store is not None,
        }