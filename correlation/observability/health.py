"""Production health system (Phase 10).

Health components distinguish four explicit statuses:

    healthy      the component is observable and operating
    degraded     the component works but under capacity pressure / latency
    unavailable  the component is reachable but not serving
    disabled     the component is intentionally disabled by configuration

A disabled production executor must not be reported as an error: ``disabled``
is a distinct, non-error status. Health is observational only and never
participates in security decisions.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, Optional, Sequence, Tuple

STATUS_HEALTHY = "healthy"
STATUS_DEGRADED = "degraded"
STATUS_UNAVAILABLE = "unavailable"
STATUS_DISABLED = "disabled"

STATUSES = (STATUS_HEALTHY, STATUS_DEGRADED, STATUS_UNAVAILABLE, STATUS_DISABLED)

ERROR_STATUSES = frozenset({STATUS_UNAVAILABLE})


def validate_status(value: str) -> str:
    if value not in STATUSES:
        raise ValueError(f"status must be one of {STATUSES}, got {value!r}")
    return value


@dataclass(frozen=True)
class ComponentHealth:
    """Immutable health snapshot for one subsystem."""

    component: str
    status: str
    detail: str = ""
    metrics: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.component, str) or not self.component.strip():
            raise ValueError("component must be a non-empty string")
        validate_status(self.status)
        if not isinstance(self.detail, str):
            raise ValueError("detail must be a string")

    def is_ok(self) -> bool:
        return self.status in (STATUS_HEALTHY, STATUS_DEGRADED, STATUS_DISABLED)


class HealthRegistry:
    """Rename-capable component registry (backend interface)."""

    def __init__(self, components: Sequence[ComponentHealth] | None = None) -> None:
        self._components: Dict[str, ComponentHealth] = {}
        for item in components or ():
            self.set(item)

    def set(self, health: ComponentHealth) -> ComponentHealth:
        self._components[health.component] = health
        return health

    def get(self, component: str) -> Optional[ComponentHealth]:
        return self._components.get(component)

    def all(self) -> Tuple[ComponentHealth, ...]:
        return tuple(dict(sorted(self._components.items())).values())

    @property
    def overall(self) -> ComponentHealth:
        worst_rank = (
            STATUS_HEALTHY,
            STATUS_DEGRADED,
            STATUS_DISABLED,
            STATUS_UNAVAILABLE,
        )
        rank = {name: i for i, name in enumerate(worst_rank)}
        worst = STATUS_HEALTHY
        for item in self._components.values():
            if rank[item.status] > rank[worst]:
                worst = item.status
        return ComponentHealth(
            component="overall",
            status=worst,
            detail="aggregate across registered subsystems",
        )

    def to_dict(self) -> Dict[str, Any]:
        overall = self.overall
        return {
            "status": overall.status,
            "components": {
                name: {
                    "status": item.status,
                    "detail": item.detail,
                    "metrics": dict(item.metrics),
                }
                for name, item in sorted(self._components.items())
            },
        }


def disabled(component: str, why: str) -> ComponentHealth:
    return ComponentHealth(component=component, status=STATUS_DISABLED, detail=why)


def healthy(component: str, detail: str = "", **metrics: Any) -> ComponentHealth:
    return ComponentHealth(
        component=component, status=STATUS_HEALTHY, detail=detail, metrics=metrics
    )


def unavailable(component: str, detail: str, **metrics: Any) -> ComponentHealth:
    return ComponentHealth(
        component=component, status=STATUS_UNAVAILABLE, detail=detail, metrics=metrics
    )


def degraded(component: str, detail: str, **metrics: Any) -> ComponentHealth:
    return ComponentHealth(
        component=component, status=STATUS_DEGRADED, detail=detail, metrics=metrics
    )