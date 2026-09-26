"""Phase 10 — central configuration (aggregates streaming + API + legacy execution).

One deterministic place to read every operational knob. Each sub-package keeps
its own, tighter config (``streaming.config.StreamingConfig``); this module
aggregates it plus the evidence root and API flags into a single
``ProductionConfig`` used by the live server. No secrets live here.

.. note::
   ``ProductionConfig.execution`` is **deprecated and test-only**. The deployed
   application is passive-only: no module reads this field to construct an
   execution plane, and XDP enforcement actions are not part of the deployed
   architecture. It is retained only so ``tests/test_phase10_config.py`` and the
   isolated ``correlation/execution`` semantics tests keep working.
"""

import os
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

from .execution.settings import ExecutionSettings
from .streaming.config import StreamingConfig

CONFIG_SCHEMA_VERSION = "v1"


def _env_str(source: Dict[str, Any], name: str, default: str) -> str:
    raw = source.get(name)
    return default if raw is None or raw == "" else raw


def _env_bool(source: Dict[str, Any], name: str, default: bool) -> bool:
    raw = source.get(name)
    if raw is None or raw == "":
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


@dataclass(frozen=True)
class ProductionConfig:
    """Aggregated operational configuration (dots into the sub-configs)."""

    schema_version: str = CONFIG_SCHEMA_VERSION
    streaming: StreamingConfig = field(default_factory=StreamingConfig)
    execution: ExecutionSettings = field(default_factory=ExecutionSettings)  # noqa: E501  # deprecated: test-only, never read by the app
    evidence_root: str = ""
    api_host: str = "127.0.0.1"
    api_port: int = 8000
    traffic_generator_monitored: bool = False

    @classmethod
    def from_env(cls, env: Optional[dict] = None) -> "ProductionConfig":
        source = dict(os.environ if env is None else env)
        streaming = StreamingConfig.from_env(source)
        execution = ExecutionSettings.from_env(source)
        return cls(
            streaming=streaming,
            execution=execution,
            evidence_root=_env_str(
                source, "SIHEVIDENCE_ROOT", os.path.join(os.getcwd(), "evidence")
            ),
            api_host=_env_str(source, "SIHAPI_HOST", "127.0.0.1"),
            api_port=int(source.get("SIHAPI_PORT", "8000") or "8000"),
            traffic_generator_monitored=_env_bool(
                source, "SIH_TRAFFIC_GENERATOR_MONITORED", False
            ),
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "streaming": self.streaming.to_dict(),
            "execution": self.execution.to_dict(),
            "evidence_root": self.evidence_root,
            "api_host": self.api_host,
            "api_port": self.api_port,
            "traffic_generator_monitored": self.traffic_generator_monitored,
        }