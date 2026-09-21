"""ML inference orchestration (Phase 5).

``run_ml_inference(window, model)`` runs one feature window through the model
adapter and produces a ``correlation.models.MLResult``:

    model_version             provenance (never None for a real model)
    traffic_class             canonical traffic profile, or None if the raw
                              label is unmappable
    classification_confidence in [0,1] only when the model provides
                              probabilities; otherwise None (no invented
                              confidence/no thresholds)
    anomaly / anomaly_score   present ONLY when the model has the capability;
                              otherwise None (the seam, explicitly reported)
    extras                    provenance-rich, source-labeled ("ml")

Determinism: same window + same model artifact -> identical MLResult.
The ML layer NEVER fabricates verdicts for absent capabilities and never
performs risk semantics.
"""

from typing import Optional

from ..models import LiveFeatureWindow, MLResult
from .adapter import ModelAdapter
from .errors import ModelUnavailableError
from .feature_contract import FEATURE_SCHEMA_VERSION


class MLInferencePipeline:
    """Runs windows through a model via its adapter."""

    def __init__(self, model, adapter: Optional[ModelAdapter] = None) -> None:
        if model is None:
            raise ModelUnavailableError(
                "no trained model available; inference was requested without "
                "a model (the integration layer must pass ml_result=None instead)"
            )
        self.model = model
        self.adapter = adapter or ModelAdapter(model)

    def run(self, window: LiveFeatureWindow) -> MLResult:
        classification = self.adapter.classify(window)
        anomaly, anomaly_score = self.adapter.evaluate_anomaly(window)
        metadata = self.adapter.metadata
        extras = {
            "source": "ml",
            "model_type": metadata.model_type,
            "feature_schema_version": FEATURE_SCHEMA_VERSION,
            "model_version": metadata.model_version,
            "model_label": classification.label,
            "label_mapping": dict(classification.mapping),
            "probability_supported": self.adapter.model.supports_probability(),
            "anomaly_supported": bool(anomaly is not None or anomaly_score is not None),
            "anomaly_threshold": getattr(self.adapter.model, "anomaly_threshold", None),
        }
        extras.update(classification.extras)
        if not extras["anomaly_supported"]:
            extras["anomaly_seam"] = (
                "no anomaly capability in the model; anomaly/anomaly_score are "
                "intentionally None and must be treated as unavailable"
            )
        return MLResult(
            model_version=metadata.model_version,
            traffic_class=classification.canonical_profile,
            classification_confidence=classification.classification_confidence,
            anomaly=anomaly,
            anomaly_score=anomaly_score,
            extras=extras,
        )


def run_ml_inference(window: LiveFeatureWindow, model) -> MLResult:
    """Convenience: one-shot ML inference on a live feature window."""
    return MLInferencePipeline(model).run(window)