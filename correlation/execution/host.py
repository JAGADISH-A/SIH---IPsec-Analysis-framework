"""Host operations seam (Phase 10).

Executors NEVER invoke subprocess/shell/SSH. All real network mechanics go
through the ``HostOperations`` protocol with STRUCTURED operation dicts (no
command strings). The default production host is ``UnavailableHost``:
applying to an unavailable host yields ``DEPENDENCY_UNAVAILABLE`` — production
never reports a fake SUCCEEDED.

``MemoryHost`` is the deterministic recording implementation used by
``AUTHORIZED_TESTBED`` mode and by tests: it records each operation and marks
it applied (monotonic recorded counter) without touching a real network.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Protocol

from .base import STATUS_DEPENDENCY_UNAVAILABLE, STATUS_SUCCESS


class HostOperations(Protocol):
    """Structured apply/query surface (never command strings)."""

    def apply(self, operation: Dict[str, Any]) -> Dict[str, Any]: ...

    def is_available(self) -> bool: ...


@dataclass
class UnavailableHost:
    """Always-depends-on-missing backend: honest DEPENDENCY_UNAVAILABLE."""

    def is_available(self) -> bool:
        return False

    def apply(self, operation: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "status": STATUS_DEPENDENCY_UNAVAILABLE,
            "applied": False,
            "operation": dict(operation),
            "reason": (
                "no production host adapter is configured; refusing to simulate "
                "success"
            ),
        }

    def reason(self) -> str:
        return (
            "no production host adapter is configured (DEPENDENCY_UNAVAILABLE; "
            "refusing to simulate success)"
        )


@dataclass
class MemoryHost:
    """Deterministic recording host for the authorized testbed / tests."""

    available: bool = True
    _operations: List[Dict[str, Any]] = field(default_factory=list)

    def is_available(self) -> bool:
        return self.available

    def apply(self, operation: Dict[str, Any]) -> Dict[str, Any]:
        if not self.available:
            return {
                "status": STATUS_DEPENDENCY_UNAVAILABLE,
                "applied": False,
                "operation": dict(operation),
                "reason": "memory host marked unavailable",
            }
        self._operations.append(dict(operation))
        return {
            "status": STATUS_SUCCESS,
            "applied": True,
            "operation": dict(operation),
            "apply_order": len(self._operations),
            "reason": "recorded by deterministic MemoryHost (testbed/code-only)",
        }

    @property
    def operations(self) -> List[Dict[str, Any]]:
        return [dict(op) for op in self._operations]

    def reset(self) -> None:
        self._operations.clear()