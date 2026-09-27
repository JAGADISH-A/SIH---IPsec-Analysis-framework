"""ML result contract placeholder.

The ML model is developed by another team member (separately from this
workspace). Phase 2 therefore creates ONLY the interface.

The field names below are a PROPOSED contract. Do not assume the ML teammate
will use these exact names; all model-specific outputs are extensible through
``extras`` so the contract can be adapted WITHOUT changing the core
identity/expected/observed models. No model is trained or executed here.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, Optional

from ._base import JsonModel


@dataclass(frozen=True)
class MLResult(JsonModel):
    """Placeholder result produced by a future ML/classifier engine.

    All fields are optional because the ML layer does not exist yet; an
    ``MLResult`` may therefore be entirely minimal. Represent the ABSENCE of
    ML output with ``None`` at the ``CorrelationInput`` level (preferred), or
    an empty ``MLResult()``.
    """

    model_version: Optional[str] = None
    traffic_class: Optional[str] = None
    classification_confidence: Optional[float] = None
    anomaly: Optional[bool] = None
    anomaly_score: Optional[float] = None
    extras: Dict[str, Any] = field(default_factory=dict)
    #: Passive SA/tunnel this result was produced for (see
    #: :mod:`correlation.models.sa_identity`).  Optional and ``None`` on the
    #: single-SA path, so a pre-SA artifact loads and re-serializes unchanged.
    #: The RF is *never* authoritative over the network, SA-scoped or not --
    #: the value only records which observed SA the prediction describes.
    sa_group_id: Optional[str] = None
    sa_id: Optional[str] = None

    def __post_init__(self) -> None:
        if self.model_version is not None and not isinstance(self.model_version, str):
            raise ValueError("model_version must be a string or None")
        if self.traffic_class is not None and not isinstance(self.traffic_class, str):
            raise ValueError("traffic_class must be a string or None")
        if self.classification_confidence is not None:
            if not isinstance(self.classification_confidence, (int, float)) or isinstance(
                self.classification_confidence, bool
            ):
                raise ValueError("classification_confidence must be a float or None")
            if not (0.0 <= float(self.classification_confidence) <= 1.0):
                raise ValueError(
                    "classification_confidence must be within [0, 1], got "
                    f"{self.classification_confidence}"
                )
        if self.anomaly is not None and not isinstance(self.anomaly, bool):
            raise ValueError("anomaly must be a bool or None")
        if self.anomaly_score is not None:
            if not isinstance(self.anomaly_score, (int, float)) or isinstance(
                self.anomaly_score, bool
            ):
                raise ValueError("anomaly_score must be a float or None")
            if float(self.anomaly_score) < 0.0:
                raise ValueError(
                    f"anomaly_score must be >= 0, got {self.anomaly_score}"
                )
        if not isinstance(self.extras, dict):
            raise ValueError("extras must be a dict")
        for name in ("sa_group_id", "sa_id"):
            value = getattr(self, name)
            if value is not None and (not isinstance(value, str) or not value.strip()):
                raise ValueError(f"{name} must be a non-empty string or None")

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "MLResult":
        return cls(
            model_version=data.get("model_version"),
            traffic_class=data.get("traffic_class"),
            classification_confidence=data.get("classification_confidence"),
            anomaly=data.get("anomaly"),
            anomaly_score=data.get("anomaly_score"),
            extras=data.get("extras") or {},
            sa_group_id=data.get("sa_group_id"),
            sa_id=data.get("sa_id"),
        )