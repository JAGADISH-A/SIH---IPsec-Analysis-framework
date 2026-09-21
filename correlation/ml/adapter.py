"""Model adapter boundary (Phase 5).

The adapter is the ONE place that turns a model's raw output into correlation
domain vocabulary:

* raw classification label         -> canonical ``traffic.profile``
* optional probability vector      -> ``classification_confidence`` (only when
  the model genuinely provides one; a deterministic similarity is NOT passed
  off as a calibrated probability)
* optional anomaly capability      -> anomaly flag + score; ABSENCE stays
  ``None`` (the seam), never a fabricated verdict
* raw label outside the canonical 6 -> ``canonical_profile = None`` with an
  explanatory ``extras`` note (never silently mapped)

The adapter is model-agnostic: anything exposing ``metadata`` + ``predict``
(+ optional confidence/anomaly) works, so an externally supplied trained
model substitutes directly for the deterministic demo model.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, Optional, Protocol, Sequence, Tuple

from ..models import ALLOWED_TRAFFIC_PROFILES, LiveFeatureWindow
from .errors import MLInferenceError
from .feature_contract import feature_vector
from .model_metadata import ModelMetadata, class_label_mapping


class MLModelInterface(Protocol):
    """Minimal model surface the adapter consumes.

    ``predict`` returns the model's own label vocabulary. The optional
    members are feature-detected via ``supports_probability`` /
    ``supports_anomaly`` so a bare classifier still works.
    """

    metadata: ModelMetadata

    def predict(self, vector: Sequence[float]) -> str: ...

    def supports_probability(self) -> bool: ...

    def predict_proba(self, vector: Sequence[float]) -> Dict[str, float]: ...

    def supports_anomaly(self) -> bool: ...

    def score_anomaly(self, vector: Sequence[float]) -> float: ...


@dataclass(frozen=True)
class ClassificationResult:
    """Adapter-normalized classification output."""

    label: str
    canonical_profile: Optional[str]
    classification_confidence: Optional[float]
    mapping: Dict[str, str]
    extras: Dict[str, Any] = field(default_factory=dict)


class ModelAdapter:
    """Normalizes a raw model into correlation-domain vocabulary."""

    def __init__(self, model: MLModelInterface) -> None:
        if model is None:
            raise MLInferenceError("adapter requires a model (use None upstream "
                                   "when no model is available)")
        self.model = model
        self.metadata = model.metadata
        self.label_map = class_label_mapping(self.metadata.class_labels)

    # -- classification -----------------------------------------------------
    def classify(self, window: LiveFeatureWindow) -> ClassificationResult:
        vector = feature_vector(window)
        label = self.model.predict(vector)
        if not isinstance(label, str) or not label:
            raise MLInferenceError(
                f"model predict returned invalid label {label!r}"
            )
        canonical = self.label_map.get(label)
        confidence: Optional[float] = None
        if self.model.supports_probability():
            probs = self.model.predict_proba(vector)
            if not isinstance(probs, dict) or not probs:
                raise MLInferenceError(
                    "model predict_proba must return a non-empty dict"
                )
            confidence = float(probs.get(label, 0.0))
            if not (0.0 <= confidence <= 1.0):
                raise MLInferenceError(
                    f"classification_confidence must be in [0, 1], got {confidence}"
                )
        extras: Dict[str, Any] = {
            "source": "ml",
            "model_version": self.metadata.model_version,
            "model_label": label,
            "label_mapping": dict(self.label_map),
            "mapped_to_canonical_profile": canonical is not None,
        }
        if canonical is None:
            extras["unmapped_label"] = (
                f"model label {label!r} is not a canonical traffic profile; "
                "ML result carries no traffic_class"
            )
        return ClassificationResult(
            label=label,
            canonical_profile=canonical,
            classification_confidence=confidence,
            mapping=dict(self.label_map),
            extras=extras,
        )

    # -- anomaly (seam; absent unless the model really supports it) ---------
    def evaluate_anomaly(
        self, window: LiveFeatureWindow
    ) -> Tuple[Optional[bool], Optional[float]]:
        if not self.model.supports_anomaly():
            return None, None
        vector = feature_vector(window)
        try:
            score = float(self.model.score_anomaly(vector))
        except Exception as exc:
            raise MLInferenceError(f"anomaly scoring failed: {exc}") from exc
        threshold = getattr(self.model, "anomaly_threshold", None)
        if score < 0:
            raise MLInferenceError("anomaly score must be >= 0")
        return (score >= threshold, score) if threshold is not None else (None, score)

    def supports_anomaly(self) -> bool:
        return self.model.supports_anomaly()