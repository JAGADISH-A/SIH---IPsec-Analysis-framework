"""Correlation identity model.

Implements the identity spine discovered during Phase 1:

    dataset_run_id -> sequence -> experiment_id -> attempt_number -> window

The recommended primary correlation identity is
``(run_id, sequence, experiment_id, window_start_ns)`` with
``attempt_number`` / ``window_index`` retained as additional identity
information. State/SPI-level records may omit window information entirely.

No arbitrary UUIDs are introduced; they are not part of the identity.
"""

from dataclasses import dataclass
from typing import Any, Dict, Optional

from ._base import JsonModel


def _non_negative_int(value: Any, name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError(f"{name} must be an integer")
    if value < 0:
        raise ValueError(f"{name} must be >= 0, got {value}")
    return value


def _strict_int(value: Any, name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError(f"{name} must be an integer")
    return value


@dataclass(frozen=True)
class CorrelationIdentity(JsonModel):
    """Immutable correlation identity.

    Window fields are optional together: a state-level record (single SPI /
    trial-level) may legitimately have no window information. When window
    boundaries are present they must be logically valid
    (``window_end_ns >= window_start_ns``).
    """

    dataset_run_id: str
    sequence: int
    experiment_id: str
    attempt_number: int
    window_index: Optional[int] = None
    window_start_ns: Optional[int] = None
    window_end_ns: Optional[int] = None

    def __post_init__(self) -> None:
        if not isinstance(self.dataset_run_id, str) or not self.dataset_run_id.strip():
            raise ValueError("dataset_run_id must be a non-empty string")
        if not isinstance(self.experiment_id, str) or not self.experiment_id.strip():
            raise ValueError("experiment_id must be a non-empty string")

        seq = _strict_int(self.sequence, "sequence")
        if seq < 1:
            raise ValueError(f"sequence must be >= 1, got {self.sequence}")
        attempt = _strict_int(self.attempt_number, "attempt_number")
        if attempt < 1:
            raise ValueError(f"attempt_number must be >= 1, got {self.attempt_number}")

        if self.window_index is not None:
            _non_negative_int(self.window_index, "window_index")

        if self.window_end_ns is not None and self.window_start_ns is None:
            raise ValueError("window_end_ns requires window_start_ns")

        if self.window_start_ns is not None:
            start = _non_negative_int(self.window_start_ns, "window_start_ns")
            if self.window_end_ns is not None:
                end = _non_negative_int(self.window_end_ns, "window_end_ns")
                if end < start:
                    raise ValueError(
                        f"window_end_ns ({end}) must be >= window_start_ns ({start})"
                    )

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CorrelationIdentity":
        return cls(
            dataset_run_id=data["dataset_run_id"],
            sequence=data["sequence"],
            experiment_id=data["experiment_id"],
            attempt_number=data["attempt_number"],
            window_index=data.get("window_index"),
            window_start_ns=data.get("window_start_ns"),
            window_end_ns=data.get("window_end_ns"),
        )

    def is_window_level(self) -> bool:
        """True when this identity carries window information."""
        return (
            self.window_start_ns is not None
            and self.window_end_ns is not None
            and self.window_index is not None
        )

    def is_state_level(self) -> bool:
        """True for state/SPI-level identities lacking window information."""
        return self.window_start_ns is None and self.window_end_ns is None