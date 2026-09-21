"""Execution settings & modes (Phase 10).

Production safety is CONFIGURED, not hard-coded:

    MODE_DRY_RUN            default; executors describe the operation only and
                            ``network_effect`` is ALWAYS False
    MODE_AUTHORIZED_TESTBED only the configured ``allowed_testbed_targets`` may
                            receive operations (through the injected host)
    MODE_PRODUCTION         requires ``enable_production_execution`` AND an
                            explicitly supplied production host adapter; without
                            them every execution is ``DENIED`` /
                            ``DEPENDENCY_UNAVAILABLE`` -- never a fake success

All settings are explicit and environment-derived (``SIHEXEC_*``) or
injected in tests; production flags default to OFF.
"""

import os
from dataclasses import dataclass, field
from typing import Any, Dict, Optional, Sequence, Tuple

MODE_DRY_RUN = "DRY_RUN"
MODE_AUTHORIZED_TESTBED = "AUTHORIZED_TESTBED"
MODE_PRODUCTION = "PRODUCTION"

EXECUTION_MODES = (MODE_DRY_RUN, MODE_AUTHORIZED_TESTBED, MODE_PRODUCTION)

ENABLE_PRODUCTION_EXECUTION_DEFAULT = False
PRODUCTION_MODE_LABEL = "production"


@dataclass(frozen=True)
class ExecutionMode:
    name: str
    network_effect_allowed: bool
    requires_allowlist: bool

    @classmethod
    def parse(cls, value: Any) -> "ExecutionMode":
        text = str(value or MODE_DRY_RUN).strip().upper()
        if text in EXECUTION_MODES:
            return EXECUTION_MODES_MAP[text]
        raise ValueError(f"unknown execution mode {value!r}")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "network_effect_allowed": self.network_effect_allowed,
            "requires_allowlist": self.requires_allowlist,
        }


EXECUTION_MODES_MAP = {
    MODE_DRY_RUN: ExecutionMode(MODE_DRY_RUN, network_effect_allowed=False, requires_allowlist=False),
    MODE_AUTHORIZED_TESTBED: ExecutionMode(
        MODE_AUTHORIZED_TESTBED, network_effect_allowed=True, requires_allowlist=True
    ),
    MODE_PRODUCTION: ExecutionMode(
        MODE_PRODUCTION, network_effect_allowed=True, requires_allowlist=True
    ),
}


def _split_csv(value: Optional[str]) -> Tuple[str, ...]:
    if not value:
        return ()
    return tuple(part.strip() for part in value.split(",") if part.strip())


@dataclass(frozen=True)
class ExecutionSettings:
    """Explicit, deterministic execution configuration."""

    mode: str = MODE_DRY_RUN
    enable_production_execution: bool = ENABLE_PRODUCTION_EXECUTION_DEFAULT
    allowed_testbed_targets: Tuple[str, ...] = ()
    executor_whitelist: Tuple[str, ...] = ("xdp", "firewall", "strongswan")
    idempotency_window: int = 0
    expiry_policy: bool = True

    def __post_init__(self) -> None:
        if self.mode not in EXECUTION_MODES:
            raise ValueError(f"mode must be one of {EXECUTION_MODES}")
        if not isinstance(self.enable_production_execution, bool):
            raise ValueError("enable_production_execution must be a bool")
        if not isinstance(self.allowed_testbed_targets, (tuple, list)):
            raise ValueError("allowed_testbed_targets must be a tuple/list")
        if self.mode == MODE_PRODUCTION and not self.enable_production_execution:
            raise ValueError(
                "mode=production requires enable_production_execution=true "
                "(default false; production stays OFF until explicitly enabled)"
            )
        if self.mode in (MODE_AUTHORIZED_TESTBED, MODE_PRODUCTION) and not self.allowed_testbed_targets:
            raise ValueError(
                f"mode {self.mode} requires a non-empty allowed_testbed_targets "
                "allow-list (fail-closed)"
            )

    @classmethod
    def from_env(cls, environ=None) -> "ExecutionSettings":
        env = environ if environ is not None else os.environ
        return cls(
            mode=str(env.get("SIHEXEC_MODE", MODE_DRY_RUN)).strip().upper(),
            enable_production_execution=_truthy(
                env.get("SIHEXEC_ENABLE_PRODUCTION_EXECUTION", "false")
            ),
            allowed_testbed_targets=_split_csv(env.get("SIHEXEC_ALLOWED_TESTBED_TARGETS")),
            executor_whitelist=_split_csv(env.get("SIHEXEC_EXECUTOR_WHITELIST"))
            or ("xdp", "firewall", "strongswan"),
        )

    @property
    def effective_mode(self) -> ExecutionMode:
        return EXECUTION_MODES_MAP[self.mode]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "mode": self.mode,
            "effective_mode": self.effective_mode.to_dict(),
            "enable_production_execution": self.enable_production_execution,
            "allowed_testbed_targets": list(self.allowed_testbed_targets),
            "executor_whitelist": list(self.executor_whitelist),
            "expiry_policy": self.expiry_policy,
        }


def _truthy(value: Optional[str]) -> bool:
    return str(value or "").strip().lower() in ("1", "true", "yes", "on")