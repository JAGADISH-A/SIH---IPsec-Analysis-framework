"""Integration of ML results into the correlation pipeline (Phase 5).

``correlate_with_ml`` wires the FEATURES -> ML -> MLResult -> CORRELATION
flow WITHOUT modifying the Phase 4 comparison engine's behavior:

* the engine is called with ``ml_result`` (metadata ``ml_evaluated`` stays
  accurate: True iff an MLResult was actually provided),
* expected-vs-ML outcomes (``correlation.comparison.ml_comparison``) are
  attached under ``CorrelationResult.metadata["ml"]`` ONLY,
* ``matches`` / ``mismatches`` / ``unknowns`` / ``not_applicable`` and the
  overall status are NEVER touched by ML output,
* absence of a model is represented as ``ml_result=None`` (ML result null in
  the output), never as a fabricated verdict.

The ML attachment is deterministic and serializable with the result.
"""

from typing import Any, Dict, Mapping, Optional, Sequence, Union

from ..adapters import MaterializedExpectedState
from ..comparison.engine import ComparisonEngine
from ..comparison.ml_comparison import ml_comparisons
from ..models import (
    CorrelationIdentity,
    CorrelationResult,
    ExpectedState,
    LiveFeatureWindow,
    MLResult,
    ObservedState,
)
from .adapter import ModelAdapter
from .inference import MLInferencePipeline

ML_METADATA_KEY = "ml"


class MLCorrelationMissingModelError(ValueError):
    """Raised when a window is supplied but there is no model to run it."""


def _expected_traffic_profile(
    expected: Union[ExpectedState, MaterializedExpectedState],
) -> Optional[str]:
    if isinstance(expected, MaterializedExpectedState):
        return expected.expected.traffic.profile
    return expected.traffic.profile


def run_ml_for_window(
    window: LiveFeatureWindow, model
) -> MLResult:
    """Infer one window through the pipeline (model required)."""
    if model is None:
        raise MLCorrelationMissingModelError(
            "a window was provided but no model is available; pass model=None "
            "AND ml_result=None to record the ML result as absent"
        )
    return MLInferencePipeline(model, ModelAdapter(model)).run(window)


def correlate_with_ml(
    engine: ComparisonEngine,
    expected: Union[ExpectedState, MaterializedExpectedState],
    observed: ObservedState,
    *,
    identity: Optional[CorrelationIdentity] = None,
    observed_identity: CorrelationIdentity,
    model=None,
    window: Optional[LiveFeatureWindow] = None,
    ml_result: Optional[MLResult] = None,
    evidence_refs: Sequence = (),
    clock_alignment=None,
    observed_values: Optional[Mapping] = None,
) -> CorrelationResult:
    """Run the Phase 4 engine and attach deterministic ML outcomes.

    ``model`` + ``window`` run live inference; a precomputed ``ml_result``
    may be supplied instead. If neither is present the ML result is recorded
    as ABSENT (null) and ``ml_evaluated`` stays False.
    """
    if model is not None and window is None:
        raise MLCorrelationMissingModelError(
            "a model was provided without a feature window; pass the window "
            "or supply a precomputed ml_result"
        )
    if window is not None and ml_result is None and model is None:
        raise MLCorrelationMissingModelError(
            "a window was provided without a model or a precomputed ml_result; "
            "pass model=<trained model> or ml_result=<MLResult>"
        )
    final_ml_result = ml_result
    if window is not None and ml_result is None:
        final_ml_result = run_ml_for_window(window, model)

    result = engine.compare(
        expected,
        observed,
        identity=identity,
        observed_identity=observed_identity,
        ml_result=final_ml_result,
        evidence_refs=evidence_refs,
        clock_alignment=clock_alignment,
        observed_values=observed_values,
    )
    attach_ml_metadata(result, expected=expected, ml_result=final_ml_result)
    return result


def attach_ml_metadata(
    result: CorrelationResult,
    *,
    expected: Union[ExpectedState, MaterializedExpectedState],
    ml_result: Optional[MLResult],
) -> CorrelationResult:
    """Attach ML outcomes to ``result.metadata[ML_METADATA_KEY]``.

    Pure metadata: protocol comparison lists and the overall status are never
    modified (the engine's own lists are left untouched).
    """
    expected_profile = _expected_traffic_profile(expected)
    attach: Dict[str, Any] = {
        "ml_result": None if ml_result is None else _ml_result_to_dict(ml_result),
        "model_available": ml_result is not None,
        "ml_evaluated": result.metadata.get("ml_evaluated", ml_result is not None),
        "comparisons": ml_comparisons(expected_profile, ml_result),
        "disclaimer": (
            "ML outputs are inference only: never authoritative protocol "
            "observations and never risk/security conclusions."
        ),
    }
    result.metadata[ML_METADATA_KEY] = attach
    return result


def _ml_result_to_dict(ml_result: MLResult) -> Dict[str, Any]:
    return {
        "model_version": ml_result.model_version,
        "traffic_class": ml_result.traffic_class,
        "classification_confidence": ml_result.classification_confidence,
        "anomaly": ml_result.anomaly,
        "anomaly_score": ml_result.anomaly_score,
        "extras": dict(ml_result.extras),
    }