"""The canonical comparable security state, and the exclusions behind it.

Phase 4 of the milestone asks for one thing above all: a canonical
representation that is stable against everything that is not a security-state
change. This module is that representation, and it is the only place in the
codebase that decides which ``ObservedState`` fields take part.

The rule applied throughout: **a field participates only if the existing
comparison layer already treats it as a directly observable, security-relevant
signal.** The comparable variables below are named with the *existing*
comparison variable names and resolved with the *existing* derivations, so drift
speaks the same language as expected-vs-observed comparison and cannot quietly
drift away from it.

Three fields participate
------------------------

=====================  =========================================  ==========
variable               derived from                              example
=====================  =========================================  ==========
``address_family``     ``ObservedState.endpoints`` (IP version)   ``ipv4``
``esp.presence``       ``ObservedState.esp_seen``                 ``True``
``ah.presence``        ``ObservedState.ah_seen``                  ``False``
=====================  =========================================  ==========

Each maps to an existing comparison rule (``address_family.endpoints``,
``presence.esp``, ``presence.ah``) and to an existing entry in
``correlation.risk.rules.MISMATCH_FINDING_SPECS``, which is where the severity
and the security relevance of each change come from. Nothing about severity is
decided in this module.

Why these three are the *maximum* honest scope
-----------------------------------------------

ESP present versus absent, and AH present versus absent, describe which IPsec
protection is actually in force -- ESP carries confidentiality and integrity,
AH carries integrity only, so an ESP-to-AH substitution is a real and
meaningful reduction in the protection of the same traffic. Address family is
the outer-header IP version of the tunnel endpoints, which the existing
comparison layer already treats as DIRECT_OBSERVABLE.

What is *not* here, and why
---------------------------

The dataset plan carries authoritative **expected** crypto -- ``mode``,
``address_family``, ``ike.version/encryption/integrity/dh_group`` and
``esp.encryption/integrity/dh_group/pfs``. No observation ever reports any of
those values back (see :mod:`correlation.drift.models`). A DH-group change, a
PFS change or a cipher change is therefore *not detectable* by this layer, and
inferring one from traffic would be the false inference the state builder's
``_FORBIDDEN_INFERENCE_KEYS`` exists to prevent.

Every exclusion is recorded in :data:`EXCLUDED_FIELDS` with its reason, and
``tests/test_drift_detection.py`` asserts that changing any of them cannot
produce drift.
"""

from dataclasses import dataclass
from typing import Any, Callable, Dict, Optional, Tuple

from ..comparison.rules import _endpoint_address_family
from ..models.observed import ObservedState
from ..risk.rules import MISMATCH_FINDING_SPECS
from .models import DRIFT_MODEL_VERSION


@dataclass(frozen=True)
class ComparableField:
    """One field that participates in the validated-baseline comparison.

    ``comparison_rule`` and ``security_relevance`` are *read from* the existing
    comparison and risk rule tables rather than restated, so a change in the
    project's security-relevance judgement is picked up here automatically.
    """

    variable: str
    label: str
    comparison_rule: str
    extractor: Callable[[ObservedState], Optional[Any]]
    inclusion_reason: str


#: Reused, not reimplemented: the comparison layer already derives the address
#: family directly from observed endpoints and documents it as
#: DIRECT_OBSERVABLE. Returns ``(family, reason)`` with ``family is None`` when
#: the endpoints cannot establish it.
def _address_family(observed: ObservedState) -> Optional[str]:
    family, _reason = _endpoint_address_family(observed.endpoints)
    return family


COMPARABLE_FIELDS: Tuple[ComparableField, ...] = (
    ComparableField(
        variable="address_family",
        label="IPsec endpoint address family",
        comparison_rule="address_family.endpoints",
        extractor=_address_family,
        inclusion_reason=(
            "the outer-header IP version of the observed tunnel endpoints, "
            "which the existing comparison layer treats as DIRECT_OBSERVABLE"
        ),
    ),
    ComparableField(
        variable="esp.presence",
        label="ESP protection in force",
        comparison_rule="presence.esp",
        extractor=lambda observed: observed.esp_seen,
        inclusion_reason=(
            "ESP presence is directly observed and decides whether the "
            "protected traffic is confidential as well as integrity-protected"
        ),
    ),
    ComparableField(
        variable="ah.presence",
        label="AH protection in force",
        comparison_rule="presence.ah",
        extractor=lambda observed: observed.ah_seen,
        inclusion_reason=(
            "AH presence is directly observed; an AH-where-none-was-validated "
            "substitution replaces confidentiality with integrity-only"
        ),
    ),
)

COMPARABLE_VARIABLES: Tuple[str, ...] = tuple(
    field.variable for field in COMPARABLE_FIELDS
)

_BY_VARIABLE: Dict[str, ComparableField] = {
    field.variable: field for field in COMPARABLE_FIELDS
}


@dataclass(frozen=True)
class ExcludedField:
    """An ``ObservedState`` field deliberately kept out of the baseline."""

    field: str
    reason: str


#: Every ``ObservedState`` field that does NOT participate, and why. Kept as
#: data so the report, the API and the tests all read the same list.
EXCLUDED_FIELDS: Tuple[ExcludedField, ...] = (
    ExcludedField(
        "timestamp_ns",
        "wall-clock position of the snapshot; a re-observation is expected to "
        "carry a different one, and it says nothing about security state",
    ),
    ExcludedField(
        "last_ike_timestamp_ns / last_ike_nat_t_timestamp_ns / "
        "last_esp_timestamp_ns / last_ah_timestamp_ns",
        "recency of the last packet of each protocol; timing is liveness, not "
        "posture, and differs between two captures of the same state",
    ),
    ExcludedField(
        "packets_seen / bytes_seen / packets_a_to_b / packets_b_to_a / "
        "bytes_a_to_b / bytes_b_to_a",
        "volume counters; they depend on how long the capture ran, not on the "
        "security state. The two real recorded live captures in this repository "
        "report 93 and 30 packets for the SAME security state",
    ),
    ExcludedField(
        "active",
        "liveness within the builder's 1000 ms activity timeout, so an idle but "
        "unchanged tunnel reports False. Comparing it would report drift for a "
        "pause in traffic",
    ),
    ExcludedField(
        "tunnel_seen",
        "'any traffic was observed at all' (IPsecStateBuilder), not tunnel mode; "
        "a quiet window would flip it without any security change",
    ),
    ExcludedField(
        "spis[].spi",
        "SPI values are chosen at random by the responder and re-rolled on every "
        "rekey. The two real recorded live captures carry disjoint SPI sets for "
        "the same security state, so SPIs would report drift on every rekey",
    ),
    ExcludedField(
        "spis[].first_seen_ns / last_seen_ns / packet_count / "
        "first_sequence / last_sequence / highest_sequence / sequence_delta",
        "per-SPI timestamps, counters and sequence arithmetic; window-dependent "
        "and never part of the protection in force",
    ),
    ExcludedField(
        "transitions",
        "observation history rather than state: it carries timestamps and "
        "restates the liveness fields excluded above (NO_TRAFFIC, ACTIVE, "
        "INACTIVE)",
    ),
    ExcludedField(
        "ike_seen / ike_nat_t_seen / observed_ike_activity",
        "the existing rule table maps ike.activity with security_relevance "
        "False (correlation/risk/rules.py MISMATCH_FINDING_SPECS), so IKE "
        "activity is deliberately not a security finding. It is still available "
        "as evidence for the presence fields",
    ),
)

EXCLUDED_FIELD_NAMES: Tuple[str, ...] = tuple(item.field for item in EXCLUDED_FIELDS)


def comparable_field(variable: str) -> Optional[ComparableField]:
    """The declared comparable field for ``variable``, or ``None``."""
    return _BY_VARIABLE.get(variable)


def security_relevance_of(variable: str) -> bool:
    """Whether the existing risk rules treat a change here as security-relevant.

    Read from ``MISMATCH_FINDING_SPECS`` so this layer cannot grant itself a
    relevance judgement the rest of the project does not share. A variable with
    no spec is not security-relevant.
    """
    spec = MISMATCH_FINDING_SPECS.get(variable)
    return bool(spec[4]) if spec is not None else False


def canonical_security_state(observed: ObservedState) -> Dict[str, Any]:
    """The canonical comparable security state of one real observation.

    Only determinate values are emitted. A field that cannot be established
    from this observation (an address family with no usable endpoints) is
    *omitted* rather than recorded as ``None``: absence of a value is not a
    value, and comparing ``None`` would manufacture drift out of missing data.
    The comparison reports such a field as unknown instead.

    The returned mapping is keyed by existing comparison variable names and is
    built in declaration order; the digest over it is order-independent because
    it is taken with ``sort_keys=True``.
    """
    state: Dict[str, Any] = {}
    for field in COMPARABLE_FIELDS:
        value = field.extractor(observed)
        if value is not None:
            state[field.variable] = value
    return state


def canonical_state_digest(state: Dict[str, Any]) -> str:
    """Digest of a canonical state, using the project's existing digest helper.

    ``correlation.custody.builder.canonical_digest`` is reused rather than
    reimplemented: it already canonicalises with ``sort_keys=True`` and tight
    separators, which is exactly the property a baseline fingerprint needs.
    """
    from ..custody.builder import canonical_digest

    return canonical_digest(state)


def unestablishable_variables(
    observed: ObservedState,
    state: Dict[str, Any],
) -> Tuple[str, ...]:
    """Comparable variables this observation cannot speak to, determinately."""
    return tuple(
        field.variable
        for field in COMPARABLE_FIELDS
        if field.variable not in state
    )


def observation_is_informative(observed: ObservedState) -> bool:
    """Whether this observation can support a comparison claim at all.

    An observation that saw no traffic at all reports every presence flag as
    ``False``. Reading that as "ESP is no longer in force" would promote absence
    of evidence into a security finding, which this project forbids in its risk
    policy and in the comparison engine's own UNKNOWN handling. Such an
    observation yields ``indeterminate`` instead of drift.

    The test is the same one the existing comparison layer uses for
    ``traffic.activity``: ``tunnel_seen`` ("any traffic was observed at all") or
    a non-zero packet count.
    """
    return bool(observed.tunnel_seen) or observed.packets_seen > 0


def describe_canonicalization() -> Dict[str, Any]:
    """Machine-readable description of what participates and what does not."""
    return {
        "model_version": DRIFT_MODEL_VERSION,
        "included": [
            {
                "variable": field.variable,
                "label": field.label,
                "comparison_rule": field.comparison_rule,
                "security_relevance": security_relevance_of(field.variable),
                "reason": field.inclusion_reason,
            }
            for field in COMPARABLE_FIELDS
        ],
        "excluded": [
            {"field": item.field, "reason": item.reason}
            for item in EXCLUDED_FIELDS
        ],
    }
