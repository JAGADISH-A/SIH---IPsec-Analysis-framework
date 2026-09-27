"""Live feature window model.

Represents a single live v2 feature record produced by the SIHPsec live
pipeline (``controller/live_features.py``):

    {
      "feature_schema_version": "v2",
      "window_start_ns": ...,
      "window_end_ns": ...,
      "features": { ... 59 features ... }
    }

The authoritative 59-feature schema lives in the SIHPsec repository
(``D:\\sihipsec\\controller\\dataset_artifacts.py`` + ``SCHEMA``).
This model DELIBERATELY does NOT re-list the 59 feature names to avoid schema
drift; ``features`` is carried verbatim as a dictionary and validated only as a
dictionary here. ``assert_feature_keys()`` is NOT re-implemented.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, Optional

from ._base import JsonModel

FEATURE_SCHEMA_VERSION_V2 = "v2"


@dataclass(frozen=True)
class LiveFeatureWindow(JsonModel):
    """One immutable live v2 feature window.

    ``sa_identity`` is the passive SA/tunnel this window's traffic was
    attributed to (see :mod:`correlation.models.sa_identity`).  It is optional
    and defaults to ``None``: a window recorded before SA identity existed, or
    produced by the single-SA path, still loads unchanged.  When present it is
    an *observation*, never a configuration value.
    """

    feature_schema_version: str = FEATURE_SCHEMA_VERSION_V2
    window_start_ns: int = 0
    window_end_ns: int = 0
    features: Dict[str, Any] = field(default_factory=dict)
    sa_identity: Optional[Dict[str, Any]] = None

    def __post_init__(self) -> None:
        if self.feature_schema_version != FEATURE_SCHEMA_VERSION_V2:
            raise ValueError(
                f"feature_schema_version must be {FEATURE_SCHEMA_VERSION_V2!r}, "
                f"got {self.feature_schema_version!r}"
            )
        if not isinstance(self.window_start_ns, int) or isinstance(
            self.window_start_ns, bool
        ):
            raise ValueError("window_start_ns must be an integer")
        if not isinstance(self.window_end_ns, int) or isinstance(
            self.window_end_ns, bool
        ):
            raise ValueError("window_end_ns must be an integer")
        if self.window_start_ns < 0:
            raise ValueError(
                f"window_start_ns must be >= 0, got {self.window_start_ns}"
            )
        if self.window_end_ns < self.window_start_ns:
            raise ValueError(
                f"window_end_ns ({self.window_end_ns}) must be >= "
                f"window_start_ns ({self.window_start_ns})"
            )
        if not isinstance(self.features, dict):
            raise ValueError("features must be a dictionary")
        if self.sa_identity is not None and not isinstance(self.sa_identity, dict):
            raise ValueError("sa_identity must be a dictionary or None")

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "LiveFeatureWindow":
        return cls(
            feature_schema_version=data.get(
                "feature_schema_version", FEATURE_SCHEMA_VERSION_V2
            ),
            window_start_ns=data.get("window_start_ns", 0),
            window_end_ns=data.get("window_end_ns", 0),
            features=data.get("features") or {},
            sa_identity=data.get("sa_identity"),
        )