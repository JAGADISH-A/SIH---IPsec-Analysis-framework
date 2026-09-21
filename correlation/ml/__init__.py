"""Phase 5 ML integration layer: FEATURES -> ML -> MLResult -> CORRELATION.

Public surface (deterministic, stdlib-only):

* ``feature_contract``   canonical v2 59-feature validation + vector builder
* ``model_metadata``     provenance container for model artifacts
* ``models``             deterministic nearest-centroid demo/test-double model
* ``training``           reproducible (re)training + JSON artifact I/O
* ``adapter``            model-agnostic normalization to canonical vocabulary
* ``inference``          windows -> MLResult (traffic_class/confidence/anomaly)
* ``integration``        attach ML outcomes to a correlation result
* ``comparison.mp_comparison`` expected-vs-ML outcomes (never in mismatch lists)
"""

from .adapter import ClassificationResult, ModelAdapter  # noqa: F401
from .errors import (  # noqa: F401
    FeatureContractError,
    MLInferenceError,
    MLIntegrationError,
    ModelArtifactError,
    ModelMetadataError,
    ModelUnavailableError,
)
from .feature_contract import (  # noqa: F401
    FEATURE_COLUMNS,
    FEATURE_COUNT,
    FEATURE_SCHEMA_VERSION,
    canonical_feature_names,
    feature_vector,
    normalize_feature_values,
    validate_feature_values,
    validate_feature_window,
    verify_authoritative_contract,
)
from .inference import MLInferencePipeline, run_ml_inference  # noqa: F401
from .integration import (  # noqa: F401
    MLCorrelationMissingModelError,
    attach_ml_metadata,
    correlate_with_ml,
    run_ml_for_window,
)
from .model_metadata import (  # noqa: F401
    MODEL_TYPE_CENTROID,
    ModelMetadata,
    class_label_mapping,
)
from .models import NearestCentroidModel, model_from_dict  # noqa: F401
from .training import (  # noqa: F401
    MODEL_ARTIFACT_EXTENSION,
    load_artifact,
    save_artifact,
    train_nearest_centroid,
)

__all__ = [
    "FeatureContractError",
    "MLInferenceError",
    "MLIntegrationError",
    "ModelArtifactError",
    "ModelMetadataError",
    "ModelUnavailableError",
    "FEATURE_COLUMNS",
    "FEATURE_COUNT",
    "FEATURE_SCHEMA_VERSION",
    "canonical_feature_names",
    "feature_vector",
    "normalize_feature_values",
    "validate_feature_values",
    "validate_feature_window",
    "verify_authoritative_contract",
    "MODEL_TYPE_CENTROID",
    "ModelMetadata",
    "class_label_mapping",
    "NearestCentroidModel",
    "model_from_dict",
    "MODEL_ARTIFACT_EXTENSION",
    "load_artifact",
    "save_artifact",
    "train_nearest_centroid",
    "ClassificationResult",
    "ModelAdapter",
    "MLInferencePipeline",
    "run_ml_inference",
    "MLCorrelationMissingModelError",
    "attach_ml_metadata",
    "correlate_with_ml",
    "run_ml_for_window",
]