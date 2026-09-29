"""Longitudinal drift detection over IPsec security state.

Public surface:

* :func:`validate_baseline` -- explicitly establish a validated baseline from
  an observation (never implicit).
* :class:`ValidatedBaseline` -- the sealed baseline record, with both the
  comparable-state fingerprint and the tamper-evident seal.
* :func:`assess_drift` -- compare a later observation against a baseline.
* :class:`BaselineRegistry` -- append-only, optionally file-backed storage.
* :class:`DriftCurrentSource` -- what kind of artifact the current state is, so
  a declared demonstration is never readable as a live observation.
* :mod:`correlation.drift.canonical` -- what participates, what does not, and
  why, as data (``COMPARABLE_FIELDS``, ``EXCLUDED_FIELDS``).

Scope: IPsec security-state drift, category ``configuration_drift``. See
:mod:`correlation.drift.models` for the categories this deliberately does not
implement, and ``DRIFT_AWARE_ASSESSMENT_REPORT.md`` for the full rationale.
"""

from .baseline import (
    BaselineIntegrityError,
    ValidatedBaseline,
)
from .canonical import (
    COMPARABLE_FIELDS,
    COMPARABLE_VARIABLES,
    EXCLUDED_FIELDS,
    canonical_security_state,
    canonical_state_digest,
    describe_canonicalization,
    observation_is_informative,
)
from .comparison import (
    DRIFT_RULE_ID,
    DriftAssessment,
    DriftCurrentSource,
    FieldChange,
    assess_drift,
    validate_baseline,
)
from .models import (
    BASELINE_SOURCE,
    DRIFT_CATEGORIES,
    DRIFT_CATEGORY_CONFIGURATION,
    DRIFT_COMPONENT,
    DRIFT_COMPONENT_VERSION,
    DRIFT_MODEL_VERSION,
    DRIFT_SCHEMA_VERSION,
    DRIFT_STATUS_DRIFT,
    DRIFT_STATUS_INDETERMINATE,
    DRIFT_STATUS_NO_DRIFT,
    DRIFT_STATUS_NOT_CONFIGURED,
    DRIFT_SOURCE_KIND_DECLARED,
    DRIFT_SOURCE_KIND_RECORDED,
    DRIFT_SOURCE_KINDS,
    DRIFT_STATUSES,
    UNSUPPORTED_DRIFT_CATEGORIES,
    VALIDATION_STATUS_VALIDATED,
)
from .registry import (
    BaselineRegistry,
    registry_from_dicts,
    registry_from_observations,
)

__all__ = [
    "BASELINE_SOURCE",
    "BaselineIntegrityError",
    "BaselineRegistry",
    "COMPARABLE_FIELDS",
    "COMPARABLE_VARIABLES",
    "DRIFT_CATEGORIES",
    "DRIFT_CATEGORY_CONFIGURATION",
    "DRIFT_COMPONENT",
    "DRIFT_COMPONENT_VERSION",
    "DRIFT_MODEL_VERSION",
    "DRIFT_RULE_ID",
    "DRIFT_SCHEMA_VERSION",
    "DRIFT_STATUS_DRIFT",
    "DRIFT_STATUS_INDETERMINATE",
    "DRIFT_STATUS_NO_DRIFT",
    "DRIFT_STATUS_NOT_CONFIGURED",
    "DRIFT_SOURCE_KIND_DECLARED",
    "DRIFT_SOURCE_KIND_RECORDED",
    "DRIFT_SOURCE_KINDS",
    "DRIFT_STATUSES",
    "DriftAssessment",
    "DriftCurrentSource",
    "EXCLUDED_FIELDS",
    "FieldChange",
    "UNSUPPORTED_DRIFT_CATEGORIES",
    "VALIDATION_STATUS_VALIDATED",
    "ValidatedBaseline",
    "assess_drift",
    "canonical_security_state",
    "canonical_state_digest",
    "describe_canonicalization",
    "observation_is_informative",
    "registry_from_dicts",
    "registry_from_observations",
    "validate_baseline",
]
