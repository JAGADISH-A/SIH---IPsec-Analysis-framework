"""ML integration error hierarchy (Phase 5).

Every failure in the ML boundary raises a specific exception so callers can
distinguish a feature-contract violation (a data quality problem on the path)
from a missing model (an environment/artifact problem) from an inference
failure. All exceptions are ``ValueError`` subclasses except the base.
"""


class MLIntegrationError(Exception):
    """Base class for all correlation-ML layer errors."""


class FeatureContractError(MLIntegrationError):
    """The feature window violates the canonical v2 feature contract.

    Raised for wrong ``feature_schema_version``, missing/extra/renamed feature
    keys, wrong orderings (model/artifact requires a fixed column order), and
    non-finite or non-numeric values. The ML layer FAILS FAST: no feature is
    silently filled, imputed or dropped.
    """


class ModelMetadataError(MLIntegrationError):
    """A model artifact's metadata is missing, malformed or inconsistent
    with the canonical feature contract (e.g. feature order drift)."""


class ModelArtifactError(MLIntegrationError):
    """The model artifact cannot be loaded or its format is unsupported.

    Model artifacts are JSON only (trusted-artifact behavior); paths are never
    taken from untrusted runtime input and no model file is ever executed.
    """


class ModelUnavailableError(MLIntegrationError):
    """No usable trained model is available for the requested capability."""


class MLInferenceError(MLIntegrationError):
    """Inference failed after feature validation (e.g. adapter/model contract
    violation)."""