"""Drift layer constants: what drift is, and what it is deliberately not.

The scope of this layer is exactly:

    "detect meaningful deviation between a previously validated IPsec
     security-state baseline and a later independently observed IPsec state."

Everything else is out of scope, and the reason is not caution -- it is that
the authoritative observation path cannot supply the inputs. Phase 1 fixed the
following, and this layer does not attempt to work around it:

* ``correlation.models.observed.ObservedState`` has **no** crypto fields.
  ``ebpf/ipsec_state_builder.py`` records ``tunnel_seen`` as "any traffic was
  observed at all" and models no cipher, DH group, PFS, integrity or IKE
  version. The docstring of ``ObservedState`` states it outright: "CRYPTO IS NOT
  INFERRED".
* ``correlation.artifacts.observed_evidence_values`` returns ``{}`` on
  purpose, and documents the consequence: "the only authoritative statements
  about the tunnel come from the signals the snapshot really has: ESP/IKE
  presence, SPI observations, and window coverage".
* The dataset plan *does* carry authoritative **expected** crypto (``mode``,
  ``address_family``, ``ike.*``, ``esp.*`` including ``dh_group`` and ``pfs``),
  but no observation ever reports any of it back.

So a DH-group change, a PFS change or a cipher change cannot be detected
longitudinally by this system, and this layer does not pretend otherwise. See
:mod:`correlation.drift.canonical` for the fields that *are* comparable, and
``DRIFT_AWARE_ASSESSMENT_REPORT.md`` section 6 for the exclusions.
"""

#: Schema version of the baseline record itself.
DRIFT_SCHEMA_VERSION = "v1"

#: Model version of the canonical-state projection and the drift comparison.
DRIFT_MODEL_VERSION = "drift-model-v1"

#: Component identity, following the convention of the other correlation layers.
DRIFT_COMPONENT = "correlation.drift"
DRIFT_COMPONENT_VERSION = "drift-v1"

#: A baseline is only ever ``validated``. There is no other state, and in
#: particular there is no "latest observation is implicitly trusted" state:
#: creating a baseline is an explicit operation (see
#: :func:`correlation.drift.comparison.validate_baseline`).
VALIDATION_STATUS_VALIDATED = "validated"

#: Provenance label for a baseline's source observation.
BASELINE_SOURCE = "validated_ipsec_security_state_baseline"

# -- comparison outcomes -----------------------------------------------------

#: The comparable security state is identical to the validated baseline.
DRIFT_STATUS_NO_DRIFT = "no_drift"

#: At least one comparable security-state field changed.
DRIFT_STATUS_DRIFT = "drift"

#: No baseline was supplied. Reported, never papered over with a default.
DRIFT_STATUS_NOT_CONFIGURED = "not_configured"

#: A current observation exists but cannot support a comparison claim (for
#: example it saw no traffic at all). This is NOT drift and NOT "no drift":
#: absence of evidence is never promoted to a security finding here, exactly
#: as ``RiskPolicy.unknown_handling`` already requires.
DRIFT_STATUS_INDETERMINATE = "indeterminate"

DRIFT_STATUSES = (
    DRIFT_STATUS_DRIFT,
    DRIFT_STATUS_NO_DRIFT,
    DRIFT_STATUS_NOT_CONFIGURED,
    DRIFT_STATUS_INDETERMINATE,
)

# -- drift taxonomy ----------------------------------------------------------

#: The security-state posture in force differs from the validated baseline.
#: This is the only category this milestone supports, and it is supported
#: because the underlying fields are directly observed booleans / derived
#: address family -- not because drift needs a taxonomy to look complete.
DRIFT_CATEGORY_CONFIGURATION = "configuration_drift"

DRIFT_CATEGORIES = (DRIFT_CATEGORY_CONFIGURATION,)

#: Categories this milestone deliberately does NOT implement, recorded so the
#: absence is a documented decision rather than an oversight. None of them can
#: be supported: the repository contains no authoritative firmware, vendor,
#: implementation-version or payload-derived signal to compare.
UNSUPPORTED_DRIFT_CATEGORIES = (
    "firmware_drift",
    "implementation_drift",
    "traffic_behavior_drift",
    "ml_behavior_drift",
)

# -- what kind of thing the current state is ---------------------------------

#: The current state was recorded by the live sensor from a real capture.
DRIFT_SOURCE_KIND_RECORDED = "recorded_capture"

#: The current state was declared by a producer -- for example a controlled
#: fixture derived from a recorded capture. Named distinctly from
#: :data:`DRIFT_SOURCE_KIND_RECORDED` so that a demonstration can never be read
#: as an observation of a live device, whatever any other field says.
DRIFT_SOURCE_KIND_DECLARED = "declared_observation"

DRIFT_SOURCE_KINDS = (
    DRIFT_SOURCE_KIND_RECORDED,
    DRIFT_SOURCE_KIND_DECLARED,
)

