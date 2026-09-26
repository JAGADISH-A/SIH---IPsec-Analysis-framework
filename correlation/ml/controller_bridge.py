"""Correlation boundary bridge for the controller Random Forest (Phase 10+).

Connects the REAL trained RF inference (``controller/ml_inference.py`` +
``results/ml/model_traffic_rf_v1.joblib``) to the EXISTING correlation ML
boundary WITHOUT creating a second classifier, a second correlation engine, or
touching any proven Phase 5 component:

    live v2 features (LiveFeatureWindow)
        -> controller.ml_inference.predict()   (strict 57-feature validation,
                                                 real RF artifact)
        -> controller result dict
        -> :func:`controller_result_to_ml_result`   (the ONLY redesigned seam)
        -> correlation.models.MLResult
        -> existing correlate_with_ml(ml_result=...) -> existing
           expected-vs-ML comparison (correlation.comparison.ml_comparison)

Scope boundaries (all enforced here, none changed elsewhere):

* The mapping is strictly one-way: ``controller result -> MLResult``. No
  MLResult field is ever re-derived from expected state; ``expected`` is a
  caller-owned input that this module never constructs, overwrites, or derives.
* The RF is a 6-class traffic-profile classifier ONLY
  (voip / video / messaging / email / web / icmp).  No other class is mapped or
  invented; a profile outside ``ALLOWED_TRAFFIC_PROFILES`` is rejected.
* ``anomaly`` / ``anomaly_score`` stay ``None`` (the model has no anomaly
  capability).  No anomaly logic is added.
* The full probability vector is preserved verbatim in ``extras``.
* Optional artifact provenance (``model_artifact_sha256``, the training commit
  and dataset run ids) is passed through verbatim when the producer supplies
  it, so a result is traceable to one exact model file.  It is never derived or
  invented by this module.
* Protocol comparison lists and ``result.status`` come exclusively from the
  existing ComparisonEngine; ML outcomes are attached as source-labeled
  metadata and never merged into them.

The module keeps ``correlate_with_ml`` and ``ml_comparison.py`` semantics
byte-identical: it builds a precomputed ``MLResult`` and hands it to the
existing ``ml_result`` slot.  The controller inference dependency is imported
lazily so that importing the correlation package stays free of
numpy/sklearn/matplotlib unless the RF path is actually used.
"""

from __future__ import annotations

import math
from collections.abc import Mapping
from typing import Any, Dict, Optional, Sequence, Union

from ..adapters import MaterializedExpectedState
from ..comparison.engine import ComparisonEngine
from ..models import (
    ALLOWED_TRAFFIC_PROFILES,
    CorrelationIdentity,
    CorrelationResult,
    ExpectedState,
    LiveFeatureWindow,
    MLResult,
    ObservedState,
)
from .feature_contract import validate_feature_window
from .integration import correlate_with_ml

#: Field names the controller RF result contract guarantees.
_CONTROLLER_RESULT_FIELDS = (
    "model_version",
    "feature_schema_version",
    "window_id",
    "timestamp",
    "traffic_profile",
    "probabilities",
)

#: Canonical six traffic classes shared by the RF and the correlation contract.
CANONICAL_TRAFFIC_PROFILES = tuple(ALLOWED_TRAFFIC_PROFILES)

#: Tolerance for the six-class probability sum (sklearn predict_proba sums to 1
#: within floating-point error).
_PROBABILITY_SUM_TOLERANCE = 1e-6

#: Optional artifact-provenance fields a controller result may carry.  They are
#: passed through verbatim and never derived or invented by the bridge, so a
#: result is traceable to the exact model file that produced it.
OPTIONAL_PROVENANCE_KEYS = (
    "model_artifact_sha256",
    "model_trained_git_commit",
    "model_training_datasets",
    "model_trained_at",
)


def require_controller_result(result: Mapping[str, Any]) -> Dict[str, Any]:
    """Validate the controller ML-result shape and return a plain dict.

    Fails fast on any missing field, a traffic profile that is not one of the
    canonical six, probabilities that do not cover exactly the six classes, or
    a probability that is not a finite number in ``[0, 1]``.  Returns a fresh
    dict (never the caller's object) so the bridge cannot mutate its input.
    """
    if not isinstance(result, Mapping):
        raise TypeError(
            f"controller ML result must be a mapping, got {type(result).__name__}"
        )
    missing = sorted(set(_CONTROLLER_RESULT_FIELDS) - set(result))
    if missing:
        raise ValueError(f"controller ML result missing fields: {missing}")
    if result["model_version"] is None or not isinstance(result["model_version"], str):
        raise ValueError("controller ML result model_version must be a string")
    if not isinstance(result["feature_schema_version"], str):
        raise ValueError("controller ML result feature_schema_version must be a string")
    if not isinstance(result["window_id"], str):
        raise ValueError("controller ML result window_id must be a string")
    if not isinstance(result["timestamp"], str):
        raise ValueError("controller ML result timestamp must be a string")

    profile = result["traffic_profile"]
    if profile not in CANONICAL_TRAFFIC_PROFILES:
        raise ValueError(
            f"controller traffic_profile {profile!r} is not a canonical "
            f"traffic profile {tuple(CANONICAL_TRAFFIC_PROFILES)!r}; the RF is "
            "a 6-class classifier only and no other class may be invented"
        )

    probabilities = result["probabilities"]
    if not isinstance(probabilities, Mapping):
        raise ValueError("controller ML result probabilities must be a mapping")
    normalized: Dict[str, float] = {}
    for profile_name in CANONICAL_TRAFFIC_PROFILES:
        if profile_name not in probabilities:
            raise ValueError(
                f"controller probabilities missing class {profile_name!r}; the "
                "full six-class vector must be preserved"
            )
        value = probabilities[profile_name]
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ValueError(
                f"probability for {profile_name!r} is not a number: {value!r}"
            )
        value = float(value)
        if not math.isfinite(value):
            raise ValueError(
                f"probability for {profile_name!r} is not finite: {value!r}"
            )
        if not (0.0 <= value <= 1.0):
            raise ValueError(
                f"probability for {profile_name!r} outside [0, 1]: {value!r}"
            )
        normalized[profile_name] = value
    unexpected = sorted(set(probabilities) - set(CANONICAL_TRAFFIC_PROFILES))
    if unexpected:
        raise ValueError(
            f"controller probabilities contain unknown classes {unexpected}; "
            "the full six-class vector is the contract"
        )
    if abs(sum(normalized.values()) - 1.0) > _PROBABILITY_SUM_TOLERANCE:
        raise ValueError(
            "controller probabilities do not sum to 1.0: "
            f"{sum(normalized.values())!r}"
        )

    normalized_out = {
        "model_version": result["model_version"],
        "feature_schema_version": result["feature_schema_version"],
        "window_id": result["window_id"],
        "timestamp": result["timestamp"],
        "traffic_profile": profile,
        "probabilities": normalized,
    }
    # Artifact provenance is optional: it is carried only when the producer
    # supplied it, so a result can be tied to one exact model file.  Recorded
    # results written before provenance existed carry none, and none is
    # invented here.
    for key in OPTIONAL_PROVENANCE_KEYS:
        value = result.get(key)
        if value not in (None, "", [], {}):
            normalized_out[key] = value
    return normalized_out


def controller_result_to_ml_result(result: Mapping[str, Any]) -> MLResult:
    """Map a controller ML result dict onto ``correlation.models.MLResult``.

    Mapping (the single seam between the two systems):

    * ``model_version``        -> ``MLResult.model_version`` (verbatim)
    * ``traffic_profile``      -> ``MLResult.traffic_class`` (verbatim)
    * ``probabilities[profile]`` -> ``classification_confidence`` (in [0, 1])
    * ``anomaly``              -> ``None``  (RF has no anomaly capability)
    * ``anomaly_score``        -> ``None``
    * ``extras``               -> ``source="ml"`` plus the full controller
       contract preserved verbatim (model_version, feature_schema_version,
       window_id, timestamp, traffic_profile, probabilities) and any optional
       artifact provenance the result carried.

    Expected state is never consulted; the full probability vector is never
    discarded.
    """
    validated = require_controller_result(result)
    traffic_class = validated["traffic_profile"]
    confidence = validated["probabilities"][traffic_class]
    extras: Dict[str, Any] = {
        "source": "ml",
        "bridge": "controller",
        "model_version": validated["model_version"],
        "feature_schema_version": validated["feature_schema_version"],
        "window_id": validated["window_id"],
        "timestamp": validated["timestamp"],
        "traffic_profile": traffic_class,
        "probabilities": dict(validated["probabilities"]),
    }
    extras.update({
        key: validated[key] for key in OPTIONAL_PROVENANCE_KEYS
        if key in validated
    })
    return MLResult(
        model_version=validated["model_version"],
        traffic_class=traffic_class,
        classification_confidence=confidence,
        anomaly=None,
        anomaly_score=None,
        extras=extras,
    )


def live_window_to_controller_record(
    window: LiveFeatureWindow,
) -> Dict[str, Any]:
    """Convert a v2 ``LiveFeatureWindow`` into the controller RF record shape.

    The v2 window IS the live feature data produced by the authoritative
    extractor; the controller adapter's strict 57-feature validation re-checks
    it (dropping the two verified constants).  No feature is rebuilt and no
    extractor is introduced here.  The record is validated against the
    correlation contract first and control stays in the controller ML record if
    the two contracts ever differ at runtime (they name the same v2 schema).
    """
    validate_feature_window(window)
    return {
        "feature_schema_version": window.feature_schema_version,
        "window_start_ns": window.window_start_ns,
        "window_end_ns": window.window_end_ns,
        "features": dict(window.features),
    }


def infer_controller_ml_result(
    window: LiveFeatureWindow,
    *,
    artifact: Optional[Mapping[str, Any]] = None,
    timestamp: Optional[str] = None,
) -> MLResult:
    """Run the REAL RF artifact on a live v2 window and return an ``MLResult``.

    ``artifact`` / ``timestamp`` are forwarded verbatim to
    ``controller.ml_inference.predict`` (None = load the committed model /
    use the current UTC generation time).  The controller adapter performs the
    authoritative validation and inference; this function only converts.
    """
    from controller import ml_inference as controller_ml_inference

    record = live_window_to_controller_record(window)
    controller_result = controller_ml_inference.predict(
        record, artifact=artifact, timestamp=timestamp
    )
    return controller_result_to_ml_result(controller_result)


def correlate_with_controller_ml(
    engine: ComparisonEngine,
    expected: Union[ExpectedState, MaterializedExpectedState],
    observed: ObservedState,
    *,
    identity: Optional[CorrelationIdentity] = None,
    observed_identity: CorrelationIdentity,
    window: LiveFeatureWindow,
    artifact: Optional[Mapping[str, Any]] = None,
    timestamp: Optional[str] = None,
    evidence_refs: Sequence = (),
    clock_alignment=None,
    observed_values=None,
) -> CorrelationResult:
    """Full live flow: window -> real RF -> MLResult -> existing correlate_with_ml.

    This is the precomputed-``ml_result`` path of the existing
    :func:`correlation.ml.integration.correlate_with_ml`; its semantics
    (expected-vs-ML metadata attachment, protocol non-interference, absent-ML
    null handling) are unchanged.  ``expected`` is passed through untouched.
    """
    ml_result = infer_controller_ml_result(
        window, artifact=artifact, timestamp=timestamp
    )
    return correlate_with_ml(
        engine,
        expected,
        observed,
        identity=identity,
        observed_identity=observed_identity,
        ml_result=ml_result,
        evidence_refs=evidence_refs,
        clock_alignment=clock_alignment,
        observed_values=observed_values,
    )