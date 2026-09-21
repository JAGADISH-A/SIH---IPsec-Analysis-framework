"""Model metadata container (Phase 5).

``ModelMetadata`` records provenance for a trained model artifact. Fields are
only populated when the training process actually observed them — nothing is
invented. In this workspace every model produced by ``training.py`` records
the full set; a model that does not carry a field keeps it ``None``.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, Optional, Sequence, Tuple

from .errors import ModelMetadataError
from .feature_contract import FEATURE_SCHEMA_VERSION, canonical_feature_names

MODEL_TYPE_CENTROID = "nearest_centroid"

SUPPORTED_MODEL_TYPES = (MODEL_TYPE_CENTROID,)


@dataclass(frozen=True)
class ModelMetadata:
    """Provenance shared by every deterministic model artifact.

    ``feature_names`` MUST equal the canonical 59-feature order (explicit
    ordering validation at load time). ``class_labels`` is the ordered list of
    labels the model was trained on.
    """

    model_version: str
    model_type: str
    feature_schema_version: str = FEATURE_SCHEMA_VERSION
    training_dataset: Optional[str] = None
    training_timestamp: Optional[str] = None
    class_labels: Tuple[str, ...] = ()
    feature_names: Tuple[str, ...] = ()
    extras: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.model_version, str) or not self.model_version.strip():
            raise ModelMetadataError("model_version must be a non-empty string")
        if self.model_type not in SUPPORTED_MODEL_TYPES:
            raise ModelMetadataError(
                f"unsupported model_type {self.model_type!r}; "
                f"supported: {SUPPORTED_MODEL_TYPES}"
            )
        if self.feature_schema_version != FEATURE_SCHEMA_VERSION:
            raise ModelMetadataError(
                f"feature_schema_version must be {FEATURE_SCHEMA_VERSION!r}, "
                f"got {self.feature_schema_version!r}"
            )
        names = tuple(self.feature_names or ())
        canonical = canonical_feature_names()
        if names != canonical:
            raise ModelMetadataError(
                "model feature ordering must match the canonical 59-feature "
                "order exactly"
            )
        if not self.class_labels:
            raise ModelMetadataError("class_labels must be non-empty")
        if len(set(self.class_labels)) != len(self.class_labels):
            raise ModelMetadataError("class_labels must be unique")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "model_version": self.model_version,
            "model_type": self.model_type,
            "feature_schema_version": self.feature_schema_version,
            "training_dataset": self.training_dataset,
            "training_timestamp": self.training_timestamp,
            "class_labels": list(self.class_labels),
            "feature_names": list(self.feature_names),
            "extras": dict(self.extras),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ModelMetadata":
        return cls(
            model_version=data["model_version"],
            model_type=data["model_type"],
            feature_schema_version=data.get(
                "feature_schema_version", FEATURE_SCHEMA_VERSION
            ),
            training_dataset=data.get("training_dataset"),
            training_timestamp=data.get("training_timestamp"),
            class_labels=tuple(data.get("class_labels") or ()),
            feature_names=tuple(data.get("feature_names") or ()),
            extras=dict(data.get("extras") or {}),
        )

    @classmethod
    def from_values(
        cls,
        *,
        model_version: str,
        model_type: str = MODEL_TYPE_CENTROID,
        training_dataset: Optional[str] = None,
        training_timestamp: Optional[str] = None,
        class_labels: Sequence[str],
    ) -> "ModelMetadata":
        return cls(
            model_version=model_version,
            model_type=model_type,
            training_dataset=training_dataset,
            training_timestamp=training_timestamp,
            class_labels=tuple(class_labels),
            feature_names=canonical_feature_names(),
        )


def class_label_mapping(model_labels: Sequence[str]) -> Dict[str, str]:
    """Explicit mapping from model labels to canonical ``traffic.profile``.

    The authoritative SIHPsec traffic catalogue AND the Phase-3 expected
    profiles share the same six labels; when a model uses that vocabulary the
    mapping is the documented identity mapping. Any label the model reports
    that is NOT in the canonical six stays unmapped (caller must reject it).
    """
    from ..models import ALLOWED_TRAFFIC_PROFILES

    return {label: label for label in model_labels if label in ALLOWED_TRAFFIC_PROFILES}