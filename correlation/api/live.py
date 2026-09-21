"""Phase 10 — live API context (wires health, metrics, execution, PCAP,
traffic generator) for the transport layer.

``Phase10Context`` is a deterministic, explicit wiring point. It is
constructed from ``ExecutionSettings`` (env-derived) + any registry/metrics
instances; every component is replaceable for tests. It is READ-ONLY for the
dashboard: no action/approval/target inputs are accepted here.
"""

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Optional

from ..execution import ExecutionControlPlane, ExecutionSettings
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
    execution: Optional[ExecutionControlPlane] = None
    pcap: Optional[PcapService] = None
    traffic_generator: TrafficGeneratorMonitor = field(default_factory=TrafficGeneratorMonitor)

    def __post_init__(self) -> None:
        if self.execution is None:
            self.execution = ExecutionControlPlane(settings=ExecutionSettings())
        if self.pcap is None:
            self.pcap = PcapService(PcapRegistry(root=""))
        # seeded component health (standard components + phase-10 ones)
        self._seed_health()

    def _seed_health(self) -> None:
        if self.health._components:
            return
        self.health.set(healthy("kafka", "streaming contract wired (in-memory transport)"))
        self.health.set(
            disabled(
                "executor",
                "production execution stays OFF unless explicitly enabled",
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

    @classmethod
    def from_settings(
        cls, settings: ExecutionSettings, *, root: str = "", **kwargs
    ) -> "Phase10Context":
        return cls(
            execution=ExecutionControlPlane(settings=settings),
            pcap=PcapService(PcapRegistry(root=root)),
            **kwargs,
        )

    def summary(self) -> Dict[str, Any]:
        return {
            "execution_mode": self.execution.settings.effective_mode.name,
            "enable_production_execution": (
                self.execution.settings.enable_production_execution
            ),
            "health": self.health.overall.status,
            "metrics_points": len(self.metrics.collect_all()),
            "registered_evidence": len(self.pcap.registry._mapping),
            "executions_recorded": self.execution.outcome_count,
            "pcap_downloads": self.pcap.download_count,
            "traffic_generator": self.traffic_generator.status(),
        }