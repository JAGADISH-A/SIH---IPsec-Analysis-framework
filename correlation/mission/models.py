"""Mission context — explicit, externally supplied asset context.

This module exists to make one distinction that a security tool must not blur:

    EVIDENCE-DERIVED INFORMATION
        observed IPsec characteristics, tunnel state, comparison findings,
        technical severity, technical risk, evidence, provenance

    EXTERNALLY-SUPPLIED ASSESSMENT CONTEXT
        asset role, asset criticality, mission impact classification

The second group is **not** derived from packets. It is declared by an operator
and read from a static profile file. Nothing in this package inspects a capture,
an address, a payload or a model output to decide that a host is important.

Why this is a hard boundary
---------------------------
An encrypted IPsec capture carries almost no usable semantics. The observation
layer already refuses to guess: ``ObservedState`` records ``tunnel_seen`` as "any
traffic at all", not the negotiated mode, and exposes no cipher, DH group or PFS
field. Inferring a mission role from what little *is* visible would be a guess
about the operator's organisation, not a measurement.

So the direction of travel is reversed: the organisation's own inventory (a CMDB,
asset register, security-classification system, or an operator-approved
assessment profile) supplies the context, and the evidence-derived technical
assessment is what gets placed *in* that context. This prototype does not
integrate any of those systems. It stands in for one with a small static JSON
file so the correlation can be demonstrated end to end, which is a deliberate
substitution and not a claim of discovery.

Provenance
----------
Every value here carries :data:`CONTEXT_SOURCE` and the source file's digest, so
a consumer can always tell an operator's declaration from an observation. The
custody layer files these values under its ``CONFIGURED`` fact category, which is
explicitly *not* in :data:`correlation.custody.models.AUTHORITATIVE_CATEGORIES`:
configured context may shape a contextualised risk number, but it can never be
cited as evidence that something was observed.
"""

from typing import Any, Tuple

#: Schema version of the on-disk profile file.
MISSION_CONTEXT_SCHEMA_VERSION = "v1"

#: Version of the contextualisation model. Bump this if the formula, the
#: category weights or the cap change in any way; a consumer can then tell two
#: mission-risk numbers apart without knowing this module.
MISSION_CONTEXT_MODEL_VERSION = "mission-context-v1"

#: Component label, matching the ``correlation.custody`` convention.
MISSION_CONTEXT_COMPONENT = "correlation.mission"

#: Where configured context always comes from. This is the *provenance label*,
#: not a claim that this repository is the real source of truth.
CONTEXT_SOURCE = "operator_supplied_asset_mission_profile"

# ---- bounded categoricals ----------------------------------------------------
# Deliberately three values each. A larger taxonomy would need a scoring
# rationale this milestone explicitly does not build.

CRITICALITY_LOW = "low"
CRITICALITY_MEDIUM = "medium"
CRITICALITY_HIGH = "high"
CRITICALITIES: Tuple[str, ...] = (
    CRITICALITY_LOW,
    CRITICALITY_MEDIUM,
    CRITICALITY_HIGH,
)

MISSION_IMPACT_LOW = "low"
MISSION_IMPACT_MEDIUM = "medium"
MISSION_IMPACT_HIGH = "high"
MISSION_IMPACTS: Tuple[str, ...] = (
    MISSION_IMPACT_LOW,
    MISSION_IMPACT_MEDIUM,
    MISSION_IMPACT_HIGH,
)

#: Asset roles. **Descriptive only** — ``role`` never enters the calculation.
#: Keeping it out of the formula means a role rename can never silently move a
#: risk number, which is the failure mode a free-text role field invites.
ROLE_DEVELOPMENT = "development"
ROLE_TEST = "test"
ROLE_OPERATIONAL = "operational-communications"
ROLE_MISSION_SUPPORT = "mission-support"
ROLES: Tuple[str, ...] = (
    ROLE_DEVELOPMENT,
    ROLE_TEST,
    ROLE_OPERATIONAL,
    ROLE_MISSION_SUPPORT,
)

# ---- context status ----------------------------------------------------------

#: A profile was found for the asset and the model ran.
STATUS_CONFIGURED = "configured"
#: No profile applies. No criticality is assumed and no risk is produced.
STATUS_NOT_CONFIGURED = "not_configured"
CONTEXT_STATUSES: Tuple[str, ...] = (STATUS_CONFIGURED, STATUS_NOT_CONFIGURED)


def validate_criticality(value: Any) -> str:
    if value not in CRITICALITIES:
        raise ValueError(
            f"asset criticality must be one of {CRITICALITIES}, got {value!r}"
        )
    return str(value)


def validate_mission_impact(value: Any) -> str:
    if value not in MISSION_IMPACTS:
        raise ValueError(
            f"mission_impact must be one of {MISSION_IMPACTS}, got {value!r}"
        )
    return str(value)


def validate_role(value: Any) -> str:
    if value not in ROLES:
        raise ValueError(f"asset role must be one of {ROLES}, got {value!r}")
    return str(value)
