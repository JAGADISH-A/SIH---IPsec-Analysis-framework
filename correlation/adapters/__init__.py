"""Expected-state adapters (Phase 3).

Read-only extraction of the REAL expected testbed state from the SIH project
artifacts (``plan.json``, campaign JSON, run metadata, explicit configuration)
into the Phase 2 ``ExpectedState`` model. The adapters contain NO correlation,
mismatch, risk, ML, anomaly or scoring logic.
"""

from .expected_state import (  # noqa: F401
    EXPECTED_STATE_SOURCE_ORDER,
    SOURCE_DEFAULTS,
    ExpectedStateAdapter,
    ExpectedStateMaterializationError,
    MaterializedExpectedState,
    MissingExpectedVariableError,
    SourceProvenance,
)

__all__ = [
    "EXPECTED_STATE_SOURCE_ORDER",
    "SOURCE_DEFAULTS",
    "ExpectedStateAdapter",
    "ExpectedStateMaterializationError",
    "MaterializedExpectedState",
    "MissingExpectedVariableError",
    "SourceProvenance",
]