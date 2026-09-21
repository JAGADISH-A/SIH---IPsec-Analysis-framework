"""Phase 10 — production executors: XDP, firewall, StrongSwan.

Structured-operations ONLY. Executors translate an authorized Phase-9 action
into a typed operation descriptor (no command strings, no subprocess, no SSH):

    XdpExecutor        BLOCK_FLOW / ISOLATE_FLOW over an eBPF/XDP map
    FirewallExecutor   BLOCK_FLOW / ISOLATE_FLOW over nftables/iptables ruleset
    StrongSwanExecutor TERMINATE_SESSION / RENEGOTIATE_SESSION over swanctl

Behavior by mode (honest, never fake):

    DRY_RUN            -> status SUCCEEDED(plan), network_effect=False,
                          message WOULD_APPLY
    AUTHORIZED_TESTBED -> through the injected (default Memory) host only when
                          the target passes the allow-list; else
                          TARGET_NOT_ALLOWED
    PRODUCTION         -> only when enable_production_execution AND an
                          available host; otherwise DEPENDENCY_UNAVAILABLE

Every execution result records the operation descriptor + evergreen evidence
policy ("executions must never fabricate success").
"""

from dataclasses import dataclass, field
from typing import Any, Dict, Optional

from ..response.models import (
    ACTION_BLOCK_FLOW,
    ACTION_ISOLATE_FLOW,
    ACTION_RENEGOTIATE_SESSION,
    ACTION_TERMINATE_SESSION,
)
from .base import (
    STATUS_CANCELLED,
    STATUS_DEPENDENCY_UNAVAILABLE,
    STATUS_FAILED,
    STATUS_NOT_SUPPORTED,
    STATUS_SUCCESS,
    STATUS_TARGET_NOT_ALLOWED,
    ExecutionOutcome,
    ProductionExecutor,
    validate_execution_status,
)
from .host import HostOperations, MemoryHost, UnavailableHost
from .settings import (
    MODE_AUTHORIZED_TESTBED,
    MODE_DRY_RUN,
    MODE_PRODUCTION,
    ExecutionSettings,
)
from .targets import ExecutionTarget, TargetAllowlist


def _now(context: Dict[str, Any]) -> Optional[int]:
    value = context.get("now_ns")
    return None if value is None else int(value)


class StructuredOperationExecutor(ProductionExecutor):
    """Base for all structured-operation executors."""

    executor_type = "phase-10"
    supported_actions = ()

    def __init__(
        self,
        host: Optional[HostOperations] = None,
        settings: Optional[ExecutionSettings] = None,
        allowlist: Optional[TargetAllowlist] = None,
        source_label: str = "phase-10",
    ) -> None:
        self.host = host if host is not None else UnavailableHost()
        self.settings = settings if settings is not None else ExecutionSettings()
        self.allowlist = (
            allowlist
            if allowlist is not None
            else TargetAllowlist(networks=self.settings.allowed_testbed_targets)
        )
        self.source_label = source_label

    # -- structural validation ---------------------------------------------

    def _target(self, context: Dict[str, Any]) -> Optional[ExecutionTarget]:
        value = context.get("target")
        if isinstance(value, ExecutionTarget):
            return value
        if isinstance(value, dict):
            try:
                return ExecutionTarget.from_dict(value)
            except ValueError:
                return None
        return None

    def validate(self, request, **context: Any) -> Dict[str, Any]:
        reasons: Dict[str, Any] = {}
        if request.action not in self.supported_actions:
            reasons["unsupported_action"] = (
                f"{self.executor_type} executor does not support action "
                f"{request.action!r}"
            )
        if request.executor_type not in (self.executor_type, "phase-10"):
            reasons["executor_mismatch"] = (
                f"request executor_type {request.executor_type!r} does not "
                f"match {self.executor_type!r}"
            )
        target = self._target(context)
        if target is None:
            reasons["target"] = "a structured ExecutionTarget is required"
        return {
            "execution_id": request.execution_id,
            "action": request.action,
            "executor_type": self.executor_type,
            "validated": not reasons,
            "network_effect": False,
            "reasons": reasons,
            "target": target.to_dict() if target else None,
        }

    # -- operation descriptor ----------------------------------------------

    def operation_descriptor(self, request, **context: Any) -> Dict[str, Any]:
        target = self._target(context)
        return {
            "op": self._op_name(request.action),
            "executor": self.executor_type,
            "action": request.action,
            "target": target.to_dict() if target else None,
            "source": self.source_label,
        }

    def _op_name(self, action: str) -> str:
        return f"{self.executor_type}.{action.lower()}"

    # -- execution -----------------------------------------------------------

    def execute(self, request, **context: Any) -> ExecutionOutcome:
        mode = self.settings.effective_mode
        now = _now(context)
        target = self._target(context)
        validation = self.validate(request, **context)
        if not validation["validated"]:
            reasons = validation["reasons"]
            status = (
                STATUS_NOT_SUPPORTED
                if "unsupported_action" in reasons or "executor_mismatch" in reasons
                else STATUS_DENIED
            )
            return ExecutionOutcome(
                execution_id=request.execution_id,
                recommendation_id=request.recommendation_id,
                action=request.action,
                executor_type=self.executor_type,
                status=status,
                success=False,
                network_effect=False,
                reason=str(reasons),
                operation=self.operation_descriptor(request, **context),
                started_at=now,
                completed_at=now,
            )

        descriptor = self.operation_descriptor(request, **context)

        if mode.name == MODE_DRY_RUN:
            return ExecutionOutcome(
                execution_id=request.execution_id,
                recommendation_id=request.recommendation_id,
                action=request.action,
                executor_type=self.executor_type,
                status=STATUS_SUCCESS,
                success=True,
                network_effect=False,
                reason="WOULD_APPLY (DRY_RUN mode; no network operation performed)",
                operation=descriptor,
                started_at=now,
                completed_at=now,
                extras={"mode": MODE_DRY_RUN},
            )

        if not self.allowlist.allows_target(target):
            return ExecutionOutcome(
                execution_id=request.execution_id,
                recommendation_id=request.recommendation_id,
                action=request.action,
                executor_type=self.executor_type,
                status=STATUS_TARGET_NOT_ALLOWED,
                success=False,
                network_effect=False,
                reason=(
                    f"target {target.destination!r} is not in the allowed "
                    "testbed/production allow-list (fail-closed)"
                ),
                operation=descriptor,
                started_at=now,
                completed_at=now,
                extras={"mode": mode.name},
            )

        if not self.host.is_available():
            return ExecutionOutcome(
                execution_id=request.execution_id,
                recommendation_id=request.recommendation_id,
                action=request.action,
                executor_type=self.executor_type,
                status=STATUS_DEPENDENCY_UNAVAILABLE,
                success=False,
                network_effect=False,
                reason=(
                    "host backend unavailable; refusing to simulate success in "
                    f"{mode.name} mode"
                ),
                operation=descriptor,
                started_at=now,
                completed_at=now,
                extras={"mode": mode.name},
            )

        if mode.name == MODE_PRODUCTION and not self.settings.enable_production_execution:
            return ExecutionOutcome(
                execution_id=request.execution_id,
                recommendation_id=request.recommendation_id,
                action=request.action,
                executor_type=self.executor_type,
                status=STATUS_DENIED,
                success=False,
                network_effect=False,
                reason=(
                    "production mode requires enable_production_execution=true "
                    "(kept OFF by default)"
                ),
                operation=descriptor,
                started_at=now,
                completed_at=now,
                extras={"mode": MODE_PRODUCTION},
            )

        applied = self.host.apply(descriptor)
        success = bool(applied.get("applied"))
        return ExecutionOutcome(
            execution_id=request.execution_id,
            recommendation_id=request.recommendation_id,
            action=request.action,
            executor_type=self.executor_type,
            status=STATUS_SUCCESS if success else STATUS_FAILED,
            success=success,
            network_effect=success,
            reason=applied.get("reason") or ("applied" if success else "applied=False"),
            operation=descriptor,
            started_at=now,
            completed_at=now,
            extras={"mode": mode.name, "host_detail": applied},
        )

    def cancel(self, request, **context: Any) -> ExecutionOutcome:
        now = _now(context)
        return ExecutionOutcome(
            execution_id=request.execution_id,
            recommendation_id=request.recommendation_id,
            action=request.action,
            executor_type=self.executor_type,
            status=STATUS_CANCELLED,
            success=False,
            network_effect=False,
            reason="CANCELLED (no network reversal was performed)",
            operation=self.operation_descriptor(request, **context),
            started_at=now,
            completed_at=now,
        )


class XdpExecutor(StructuredOperationExecutor):
    executor_type = "xdp"
    supported_actions = (ACTION_BLOCK_FLOW, ACTION_ISOLATE_FLOW)


class FirewallExecutor(StructuredOperationExecutor):
    executor_type = "firewall"
    supported_actions = (ACTION_BLOCK_FLOW, ACTION_ISOLATE_FLOW)


class StrongSwanExecutor(StructuredOperationExecutor):
    executor_type = "strongswan"
    supported_actions = (ACTION_TERMINATE_SESSION, ACTION_RENEGOTIATE_SESSION)


EXECUTOR_CLASSES = {
    "xdp": XdpExecutor,
    "firewall": FirewallExecutor,
    "strongswan": StrongSwanExecutor,
}


def executor_for(type_name: str, **kwargs) -> ProductionExecutor:
    """Router: instantiate the executor named in the request."""
    cls = EXECUTOR_CLASSES.get(type_name)
    if cls is None:
        return UnsupportedExecutor(name=type_name)
    return cls(**kwargs)


class UnsupportedExecutor(ProductionExecutor):
    """Structured response when a request names an unknown executor."""

    executor_type = "unsupported"

    def __init__(self, name: str = "unsupported") -> None:
        self.name = name

    def validate(self, request, **context: Any) -> Dict[str, Any]:
        return {
            "execution_id": request.execution_id,
            "action": request.action,
            "executor_type": self.executor_type,
            "validated": False,
            "network_effect": False,
            "reasons": {"executor": f"{self.name!r} is not a supported executor"},
            "target": None,
        }

    def execute(self, request, **context: Any) -> ExecutionOutcome:
        now = _now(context)
        return ExecutionOutcome(
            execution_id=request.execution_id,
            recommendation_id=request.recommendation_id,
            action=request.action,
            executor_type=self.executor_type,
            status=STATUS_NOT_SUPPORTED,
            success=False,
            network_effect=False,
            reason=f"executor {self.name!r} is not supported",
            started_at=now,
            completed_at=now,
        )

    def cancel(self, request, **context: Any) -> ExecutionOutcome:
        now = _now(context)
        return ExecutionOutcome(
            execution_id=request.execution_id,
            recommendation_id=request.recommendation_id,
            action=request.action,
            executor_type=self.executor_type,
            status=STATUS_CANCELLED,
            success=False,
            network_effect=False,
            reason="CANCELLED (unsupported executor)",
            started_at=now,
            completed_at=now,
        )