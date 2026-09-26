"""Phase 10 — controlled production execution layer (TEST-ONLY / DEPRECATED).

.. warning::
   This package is **not deployed** and has **no production caller**. The
   application architecture is PASSIVE-ONLY: XDP/eBPF performs passive
   observation via a non-inline sensor fed by mirrored/tapped traffic, and XDP
   enforcement actions are not part of the deployed application. Nothing in
   :mod:`correlation.api`, :mod:`correlation.streaming`, :mod:`correlation.risk`
   or :mod:`correlation.response` constructs an
   :class:`~correlation.execution.gates.ExecutionControlPlane` or calls an
   executor. These modules are retained solely so the execution-semantics
   tests (``tests/test_execution_*.py``,
   ``tests/test_phase10_integration.py::TestControlledExecution``) can exercise
   gates, idempotency and outcome accounting in isolation.

Historical context — the two-layer enforcement gateway. Only APPROVED +
AUTHORIZED Phase-9 recommendations reach this layer; ML and risk score NEVER do
directly. All operations are structured descriptors (no subprocess/shell/SSH);
production is OFF until explicitly enabled, and success is never fabricated.
"""

from .base import (  # noqa: F401
    CLOSED_STATUSES,
    EXECUTION_STATUSES,
    STATUS_ALREADY_APPLIED,
    STATUS_CANCELLED,
    STATUS_DENIED,
    STATUS_DEPENDENCY_UNAVAILABLE,
    STATUS_EXPIRED,
    STATUS_FAILED,
    STATUS_NOT_SUPPORTED,
    STATUS_SUCCESS,
    STATUS_TARGET_NOT_ALLOWED,
    TERMINAL_STATUSES,
    ExecutionOutcome,
    ProductionExecutor,
    is_success,
    validate_execution_status,
)
from .executors import (  # noqa: F401
    EXECUTOR_CLASSES,
    FirewallExecutor,
    StrongSwanExecutor,
    StructuredOperationExecutor,
    UnsupportedExecutor,
    XdpExecutor,
    executor_for,
)
from .gates import ExecutionControlPlane  # noqa: F401
from .host import MemoryHost, UnavailableHost  # noqa: F401
from .idempotency import (  # noqa: F401
    IdempotencyRegistry,
    idempotency_key,
)
from .settings import (  # noqa: F401
    ENABLE_PRODUCTION_EXECUTION_DEFAULT,
    EXECUTION_MODES,
    EXECUTION_MODES_MAP,
    MODE_AUTHORIZED_TESTBED,
    MODE_DRY_RUN,
    MODE_PRODUCTION,
    ExecutionMode,
    ExecutionSettings,
)
from .targets import (  # noqa: F401
    IP_VERSION_IPV4,
    IP_VERSION_IPV6,
    IP_VERSION_UNKNOWN,
    ExecutionTarget,
    TargetAllowlist,
    parse_ip_version,
)

EXECUTION_LAYER_VERSION = "v1"

__all__ = [
    "CLOSED_STATUSES",
    "EXECUTION_LAYER_VERSION",
    "EXECUTION_MODES",
    "EXECUTION_MODES_MAP",
    "EXECUTION_STATUSES",
    "ENABLE_PRODUCTION_EXECUTION_DEFAULT",
    "STATUS_ALREADY_APPLIED",
    "STATUS_CANCELLED",
    "STATUS_DENIED",
    "STATUS_DEPENDENCY_UNAVAILABLE",
    "STATUS_EXPIRED",
    "STATUS_FAILED",
    "STATUS_NOT_SUPPORTED",
    "STATUS_SUCCESS",
    "STATUS_TARGET_NOT_ALLOWED",
    "TERMINAL_STATUSES",
    "ExecutionControlPlane",
    "ExecutionMode",
    "ExecutionOutcome",
    "ExecutionSettings",
    "ExecutionTarget",
    "FirewallExecutor",
    "IP_VERSION_IPV4",
    "IP_VERSION_IPV6",
    "IP_VERSION_UNKNOWN",
    "IdempotencyRegistry",
    "MemoryHost",
    "MODE_AUTHORIZED_TESTBED",
    "MODE_DRY_RUN",
    "MODE_PRODUCTION",
    "ProductionExecutor",
    "StrongSwanExecutor",
    "StructuredOperationExecutor",
    "TargetAllowlist",
    "UnavailableHost",
    "UnsupportedExecutor",
    "XdpExecutor",
    "executor_for",
    "idempotency_key",
    "is_success",
    "parse_ip_version",
    "validate_execution_status",
]