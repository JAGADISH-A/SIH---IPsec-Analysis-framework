"""Deterministic comparison rules for the Expected-vs-Observed engine.

Every canonical variable (TV01-TV14) plus the two derived metadata variables
(``configuration_id``, ``security_posture``) has exactly one explicit rule
registration in ``RULES`` and one classification in ``RULE_CLASSIFICATIONS``:

    DIRECT_COMPARISON   compared against authoritative observed evidence
    AUDIT_ONLY          requires authoritative audit/swanctl evidence
    INDIRECT            feature/ML-derived in a later phase; NOT evaluated here
    NOT_OBSERVABLE      planning/capture metadata, or hidden inside ESP payload

The engine is CONSERVATIVE: UNKNOWN is preferred over an unsupported security
conclusion, and no observation absence is ever turned into MISMATCH unless the
observation is complete enough to establish absence (``establish_completeness``).
"""

from dataclasses import dataclass, field
from typing import Any, Dict, Mapping, Optional, Tuple

from ..models import (
    CANONICAL_VARIABLES,
    CorrelationIdentity,
    EvidenceRef,
    ExpectedState,
    LiveFeatureWindow,
    ObservedState,
)
from ..models.correlation import (
    CORRELATION_STATUS_MATCH,
    CORRELATION_STATUS_MISMATCH,
    CORRELATION_STATUS_NOT_APPLICABLE,
    CORRELATION_STATUS_UNKNOWN,
)
from .clock import ClockAlignment
from .discrepancy import ComparisonOutcome

# ---- rule classifications -------------------------------------------------
RULE_DIRECT_COMPARISON = "DIRECT_COMPARISON"
RULE_AUDIT_ONLY = "AUDIT_ONLY"
RULE_INDIRECT = "INDIRECT"
RULE_NOT_OBSERVABLE = "NOT_OBSERVABLE"

RULE_CLASSIFICATIONS: Dict[str, str] = {
    "mode": RULE_DIRECT_COMPARISON,
    "address_family": RULE_DIRECT_COMPARISON,
    "ike.version": RULE_AUDIT_ONLY,
    "ike.encryption": RULE_AUDIT_ONLY,
    "ike.integrity": RULE_AUDIT_ONLY,
    "ike.dh_group": RULE_AUDIT_ONLY,
    "esp.encryption": RULE_INDIRECT,
    "esp.integrity": RULE_INDIRECT,
    "esp.dh_group": RULE_INDIRECT,
    "esp.pfs": RULE_INDIRECT,
    "traffic.profile": RULE_INDIRECT,
    "traffic.duration": RULE_NOT_OBSERVABLE,
    "traffic.port": RULE_NOT_OBSERVABLE,
    "capture_filter": RULE_NOT_OBSERVABLE,
    "configuration_id": RULE_NOT_OBSERVABLE,
    "security_posture": RULE_NOT_OBSERVABLE,
}

# Derived metadata variables that must also be explicitly accounted for.
DERIVED_COMPARISON_VARIABLES = ("configuration_id", "security_posture")

# All 14 canonical variables + the two derived metadata variables.
ACCOUNTED_VARIABLES = tuple(CANONICAL_VARIABLES) + DERIVED_COMPARISON_VARIABLES


# ---- observation completeness ----------------------------------------------
OBSERVATION_COMPLETE = "COMPLETE"
OBSERVATION_PARTIAL = "PARTIAL"
OBSERVATION_UNKNOWN = "UNKNOWN"
OBSERVATION_COMPLETENESS = (
    OBSERVATION_COMPLETE,
    OBSERVATION_PARTIAL,
    OBSERVATION_UNKNOWN,
)


def establish_completeness(
    expected: ExpectedState,
    live_features: Optional[LiveFeatureWindow],
) -> str:
    """Deterministic sufficiency of the observation for establishing ABSENCE.

    The observation is COMPLETE when a live feature window spans at least the
    expected traffic duration (the window observed the whole trial). Without a
    full-coverage window we cannot establish that something did NOT happen, so
    the result is PARTIAL (conservative -> UNKNOWN for absence rules).
    """
    if live_features is None:
        return OBSERVATION_PARTIAL
    start = live_features.window_start_ns
    end = live_features.window_end_ns
    if end <= start:
        return OBSERVATION_PARTIAL
    span_seconds = (end - start) / 1_000_000_000.0
    if span_seconds >= expected.traffic.duration:
        return OBSERVATION_COMPLETE
    return OBSERVATION_PARTIAL


# ---- per-rule context -------------------------------------------------------
@dataclass(frozen=True)
class RuleContext:
    expected: ExpectedState
    observed: ObservedState
    expected_identity: CorrelationIdentity
    evidence_refs: Tuple[EvidenceRef, ...] = ()
    observed_values: Mapping[str, Any] = field(default_factory=dict)
    live_features: Optional[LiveFeatureWindow] = None
    completeness: str = OBSERVATION_PARTIAL
    clock_alignment: Optional[ClockAlignment] = None
    observed_clock_domain: str = "LIVE_MONOTONIC_NS"
    window_clock_domain: str = "LIVE_MONOTONIC_NS"

    def has_observed(self, variable: str) -> bool:
        return variable in self.observed_values


# ---- helpers ----------------------------------------------------------------
def _unavailable(
    ctx: RuleContext,
    variable: str,
    rule: str,
    reason: str,
    expected_value: Any,
) -> ComparisonOutcome:
    return ComparisonOutcome(
        variable=variable,
        comparison_rule=rule,
        status=CORRELATION_STATUS_UNKNOWN,
        reason=reason,
        expected_value=expected_value,
        observed_value=None,
        identity=ctx.expected_identity.to_dict(),
    )


def _not_applicable(
    ctx: RuleContext,
    variable: str,
    rule: str,
    reason: str,
    expected_value: Any,
) -> ComparisonOutcome:
    return ComparisonOutcome(
        variable=variable,
        comparison_rule=rule,
        status=CORRELATION_STATUS_NOT_APPLICABLE,
        reason=reason,
        expected_value=expected_value,
        observed_value=None,
        identity=ctx.expected_identity.to_dict(),
    )


def _exact(
    ctx: RuleContext,
    variable: str,
    rule: str,
    expected_value: Any,
    observed_value: Any,
) -> ComparisonOutcome:
    if observed_value == expected_value:
        status = CORRELATION_STATUS_MATCH
        reason = f"authoritative observed {variable} equals expected"
    else:
        status = CORRELATION_STATUS_MISMATCH
        reason = f"authoritative observed {variable} contradicts expected"
    return ComparisonOutcome(
        variable=variable,
        comparison_rule=rule,
        status=status,
        reason=reason,
        expected_value=expected_value,
        observed_value=observed_value,
        identity=ctx.expected_identity.to_dict(),
        evidence_refs=ctx.evidence_refs,
    )


def _authoritative_or_unknown(
    ctx: RuleContext,
    variable: str,
    rule: str,
    expected_value: Any,
    unavailable_reason: str,
) -> ComparisonOutcome:
    if ctx.has_observed(variable):
        return _exact(ctx, variable, rule, expected_value, ctx.observed_values[variable])
    return _unavailable(ctx, variable, rule, unavailable_reason, expected_value)


def _endpoint_address_family(endpoints: Mapping[str, Any]) -> Tuple[Optional[str], str]:
    """Authoritative-address-family detection from observed endpoints.

    The endpoints are real observed IP addresses (``ObservedState.endpoints``);
    their IP version is DIRECTLY_OBSERVABLE (outer header version). Returns
    ``(family, err)``; family is ``None`` when it cannot be established
    unambiguously.
    """
    import ipaddress

    families = set()
    for value in endpoints.values():
        if value is None:
            continue
        try:
            families.add(ipaddress.ip_address(str(value).strip()).version)
        except ValueError:
            continue
    if not families:
        return None, "ObservedState exposes no endpoints; address family cannot be established."
    if len(families) > 1:
        return None, "Observed endpoints contain mixed address families; family cannot be established."
    version = families.pop()
    return ("ipv6" if version == 6 else "ipv4"), ""


# ---- rules for the 14 canonical variables + 2 derived metadata --------------
def compare_mode(ctx: RuleContext) -> ComparisonOutcome:
    return _authoritative_or_unknown(
        ctx,
        "mode",
        "mode.exact",
        ctx.expected.mode,
        "ObservedState exposes no authoritative mode field (tunnel_seen reflects "
        "traffic presence, not mode); no authoritative observed mode was supplied.",
    )


def compare_address_family(ctx: RuleContext) -> ComparisonOutcome:
    if ctx.has_observed("address_family"):
        return _exact(
            ctx, "address_family", "address_family.exact",
            ctx.expected.address_family, ctx.observed_values["address_family"],
        )
    family, err = _endpoint_address_family(ctx.observed.endpoints)
    if family is None:
        return _unavailable(
            ctx, "address_family", "address_family.endpoints",
            err, ctx.expected.address_family,
        )
    return _exact(
        ctx, "address_family", "address_family.endpoints",
        ctx.expected.address_family, family,
    )


_IKE_UNOBSERVABLE_REASONS = {
    "ike.version": "ObservedState does not expose IKE version (rule class "
                   "AUDIT_ONLY); authoritative audit evidence containing the required "
                   "value was not supplied.",
    "ike.encryption": "ObservedState does not expose IKE encryption (rule class "
                      "AUDIT_ONLY); authoritative audit evidence containing the required "
                      "value was not supplied.",
    "ike.integrity": "ObservedState does not expose IKE integrity (rule class "
                     "AUDIT_ONLY); authoritative audit evidence containing the required "
                     "value was not supplied.",
    "ike.dh_group": "ObservedState does not expose IKE DH group (rule class "
                    "AUDIT_ONLY); authoritative audit evidence containing the required "
                    "value was not supplied.",
}

_ESP_UNOBSERVABLE_REASONS = {
    "esp.encryption": "esp.encryption is only indirectly observable (feature-derived) "
                      "and Phase 4 does not evaluate ML; ObservedState exposes no "
                      "authoritative esp.encryption.",
    "esp.integrity": "esp.integrity is only indirectly observable (feature-derived) and "
                     "Phase 4 does not evaluate ML; ObservedState exposes no "
                     "authoritative esp.integrity.",
    "esp.dh_group": "esp.dh_group is only indirectly observable (IKE CREATE_CHILD_SA "
                    "derivation) and Phase 4 does not evaluate ML; ObservedState exposes "
                    "no authoritative esp.dh_group.",
    "esp.pfs": "esp.pfs is only indirectly observable (rekey DH-exchange presence) and "
               "Phase 4 does not evaluate ML; ObservedState exposes no authoritative "
               "esp.pfs and it is never inferred from an expected ESP DH group.",
}

_TRAFFIC_UNOBSERVABLE_REASONS = {
    "traffic.profile": "traffic.profile is indirectly observable via feature/ML "
                       "classification; Phase 4 does not evaluate ML and no "
                       "authoritative observed profile was supplied.",
    "traffic.duration": "traffic.duration is a planning property not observable from "
                        "the current sensor stack; no authoritative observed duration "
                        "was supplied.",
    "traffic.port": "traffic.port is hidden inside the ESP payload "
                    "(NOT_CURRENTLY_OBSERVABLE); no authoritative observed port was "
                    "supplied.",
}


def compare_ike_version(ctx: RuleContext) -> ComparisonOutcome:
    return _authoritative_or_unknown(
        ctx, "ike.version", "ike.version.exact", ctx.expected.ike.version,
        _IKE_UNOBSERVABLE_REASONS["ike.version"],
    )


def compare_ike_encryption(ctx: RuleContext) -> ComparisonOutcome:
    return _authoritative_or_unknown(
        ctx, "ike.encryption", "ike.encryption.exact", ctx.expected.ike.encryption,
        _IKE_UNOBSERVABLE_REASONS["ike.encryption"],
    )


def compare_ike_integrity(ctx: RuleContext) -> ComparisonOutcome:
    return _authoritative_or_unknown(
        ctx, "ike.integrity", "ike.integrity.exact", ctx.expected.ike.integrity,
        _IKE_UNOBSERVABLE_REASONS["ike.integrity"],
    )


def compare_ike_dh_group(ctx: RuleContext) -> ComparisonOutcome:
    return _authoritative_or_unknown(
        ctx, "ike.dh_group", "ike.dh_group.exact", ctx.expected.ike.dh_group,
        _IKE_UNOBSERVABLE_REASONS["ike.dh_group"],
    )


def compare_esp_encryption(ctx: RuleContext) -> ComparisonOutcome:
    return _authoritative_or_unknown(
        ctx, "esp.encryption", "esp.encryption.exact", ctx.expected.esp.encryption,
        _ESP_UNOBSERVABLE_REASONS["esp.encryption"],
    )


def compare_esp_integrity(ctx: RuleContext) -> ComparisonOutcome:
    # A deliberate GCM null integrity stays null and is NEVER coerced to "none".
    # When observed it is compared with exact (None == None) semantics.
    return _authoritative_or_unknown(
        ctx, "esp.integrity", "esp.integrity.exact", ctx.expected.esp.integrity,
        _ESP_UNOBSERVABLE_REASONS["esp.integrity"],
    )


def compare_esp_dh_group(ctx: RuleContext) -> ComparisonOutcome:
    return _authoritative_or_unknown(
        ctx, "esp.dh_group", "esp.dh_group.exact", ctx.expected.esp.dh_group,
        _ESP_UNOBSERVABLE_REASONS["esp.dh_group"],
    )


def compare_esp_pfs(ctx: RuleContext) -> ComparisonOutcome:
    return _authoritative_or_unknown(
        ctx, "esp.pfs", "esp.pfs.exact", ctx.expected.esp.pfs,
        _ESP_UNOBSERVABLE_REASONS["esp.pfs"],
    )


def compare_traffic_profile(ctx: RuleContext) -> ComparisonOutcome:
    return _authoritative_or_unknown(
        ctx, "traffic.profile", "traffic.profile.exact", ctx.expected.traffic.profile,
        _TRAFFIC_UNOBSERVABLE_REASONS["traffic.profile"],
    )


def compare_traffic_duration(ctx: RuleContext) -> ComparisonOutcome:
    return _authoritative_or_unknown(
        ctx, "traffic.duration", "traffic.duration.exact", ctx.expected.traffic.duration,
        _TRAFFIC_UNOBSERVABLE_REASONS["traffic.duration"],
    )


def compare_traffic_port(ctx: RuleContext) -> ComparisonOutcome:
    return _authoritative_or_unknown(
        ctx, "traffic.port", "traffic.port.exact", ctx.expected.traffic.port,
        _TRAFFIC_UNOBSERVABLE_REASONS["traffic.port"],
    )


def compare_capture_filter(ctx: RuleContext) -> ComparisonOutcome:
    if ctx.has_observed("capture_filter"):
        return _exact(
            ctx, "capture_filter", "capture_filter.exact",
            ctx.expected.capture_filter, ctx.observed_values["capture_filter"],
        )
    return _not_applicable(
        ctx, "capture_filter", "capture_filter.na",
        "capture_filter describes capture configuration, not network behavior; no "
        "authoritative observed capture configuration was supplied — not compared "
        "against the packet set.",
        ctx.expected.capture_filter,
    )


def compare_configuration_id(ctx: RuleContext) -> ComparisonOutcome:
    if ctx.has_observed("configuration_id"):
        return _exact(
            ctx, "configuration_id", "configuration_id.exact",
            ctx.expected.configuration_id, ctx.observed_values["configuration_id"],
        )
    return _not_applicable(
        ctx, "configuration_id", "configuration_id.na",
        "configuration_id is derived expected metadata; comparisons happen at the "
        "underlying observable variables; no authoritative observed configuration_id "
        "was supplied and none is guessed.",
        ctx.expected.configuration_id,
    )


def compare_security_posture(ctx: RuleContext) -> ComparisonOutcome:
    # NEVER recomputed and NEVER turned into a match signal in Phase 4.
    return _not_applicable(
        ctx, "security_posture", "security_posture.na",
        "security_posture is authoritative expected metadata produced by "
        "posture_of_config; Phase 4 never recomputes posture and ObservedState "
        "exposes no posture field.",
        ctx.expected.security_posture,
    )


# ---- presence / activity rules (directly observable fields) ----------------
def _presence_absence(
    ctx: RuleContext,
    variable: str,
    rule: str,
    expected_presence: bool,
    observed_presence: bool,
    label: str,
) -> ComparisonOutcome:
    if observed_presence == expected_presence:
        if observed_presence:
            reason = f"observed {label} presence equals expected (present)"
        else:
            reason = f"observed {label} absence equals expected (absent)"
        return ComparisonOutcome(
            variable=variable, comparison_rule=rule, status=CORRELATION_STATUS_MATCH,
            reason=reason, expected_value=expected_presence,
            observed_value=observed_presence,
            identity=ctx.expected_identity.to_dict(), evidence_refs=ctx.evidence_refs,
        )
    if not observed_presence and expected_presence:
        # Absence can only be authoritative when the observation is complete.
        if ctx.completeness == OBSERVATION_COMPLETE:
            return ComparisonOutcome(
                variable=variable, comparison_rule=rule,
                status=CORRELATION_STATUS_MISMATCH,
                reason=f"observed {label} is absent and the observation window was "
                       "complete (sufficient to establish absence); contradicts the "
                       "expected presence.",
                expected_value=expected_presence, observed_value=observed_presence,
                identity=ctx.expected_identity.to_dict(),
                evidence_refs=ctx.evidence_refs,
            )
        return ComparisonOutcome(
            variable=variable, comparison_rule=rule, status=CORRELATION_STATUS_UNKNOWN,
            reason=f"observation window is insufficient to establish {label} absence "
                   f"(completeness={ctx.completeness}).",
            expected_value=expected_presence, observed_value=observed_presence,
            identity=ctx.expected_identity.to_dict(),
        )
    return ComparisonOutcome(
        variable=variable, comparison_rule=rule, status=CORRELATION_STATUS_MISMATCH,
        reason=f"unexpected {label} presence was authoritatively observed "
               f"(observed={observed_presence}, expected={expected_presence}).",
        expected_value=expected_presence, observed_value=observed_presence,
        identity=ctx.expected_identity.to_dict(), evidence_refs=ctx.evidence_refs,
    )


def compare_esp_presence(ctx: RuleContext) -> ComparisonOutcome:
    return _presence_absence(
        ctx, "esp.presence", "presence.esp", True, ctx.observed.esp_seen, "ESP",
    )


def compare_ah_presence(ctx: RuleContext) -> ComparisonOutcome:
    return _presence_absence(
        ctx, "ah.presence", "presence.ah", False, ctx.observed.ah_seen, "AH",
    )


def compare_ike_activity(ctx: RuleContext) -> ComparisonOutcome:
    observed = ctx.observed.ike_seen or ctx.observed.ike_nat_t_seen
    return _presence_absence(
        ctx, "ike.activity", "activity.ike", True, observed, "IKE",
    )


def compare_traffic_activity(ctx: RuleContext) -> ComparisonOutcome:
    observed = ctx.observed.packets_seen > 0
    return _presence_absence(
        ctx, "traffic.activity", "activity.traffic", True, observed, "traffic",
    )


def compare_tunnel_activity(ctx: RuleContext) -> ComparisonOutcome:
    return _presence_absence(
        ctx, "tunnel.activity", "activity.tunnel", True,
        ctx.observed.tunnel_seen, "tunnel",
    )


# ---- window / temporal comparison ------------------------------------------
def compare_window_containment(ctx: RuleContext) -> ComparisonOutcome:
    identity = ctx.expected_identity
    if not identity.is_window_level():
        return _not_applicable(
            ctx, "window.containment", "window.containment.na",
            "identity carries no window scope (state-level comparison); no "
            "window boundaries to check.",
            None,
        )
    start, end = identity.window_start_ns, identity.window_end_ns
    if end <= start:
        return _not_applicable(
            ctx, "window.containment", "window.containment.na",
            "identity window is empty or degenerate (start == end); no "
            "containment check is meaningful.",
            None,
        )
    from .clock import domains_are_compatible

    if not domains_are_compatible(
        ctx.window_clock_domain, ctx.observed_clock_domain, ctx.clock_alignment
    ):
        return _unavailable(
            ctx, "window.containment", "window.containment.clock",
            f"No valid clock alignment supplied between window clock domain "
            f"{ctx.window_clock_domain!r} and observed clock domain "
            f"{ctx.observed_clock_domain!r}.",
            None,
        )
    if ctx.clock_alignment is not None:
        start = ctx.clock_alignment.aligned_ns(start)
        end = ctx.clock_alignment.aligned_ns(end)
    ts = ctx.observed.timestamp_ns
    if start <= ts <= end:
        return ComparisonOutcome(
            variable="window.containment", comparison_rule="window.containment.bounds",
            status=CORRELATION_STATUS_MATCH,
            reason="observed snapshot timestamp lies inside the expected window "
                   "(clock domains aligned).",
            expected_value=[start, end], observed_value=ts,
            identity=ctx.expected_identity.to_dict(), evidence_refs=ctx.evidence_refs,
        )
    return ComparisonOutcome(
        variable="window.containment", comparison_rule="window.containment.bounds",
        status=CORRELATION_STATUS_MISMATCH,
        reason="observed snapshot timestamp lies outside the expected window.",
        expected_value=[start, end], observed_value=ts,
        identity=ctx.expected_identity.to_dict(), evidence_refs=ctx.evidence_refs,
    )


# ---- SPI comparison ---------------------------------------------------------
def compare_spi(ctx: RuleContext) -> ComparisonOutcome:
    spis = sorted(ctx.observed.spis, key=lambda s: (str(s.spi), str(s.direction or "")))
    summary = summarize_spis(spis)
    return ComparisonOutcome(
        variable="spi", comparison_rule="spi.supporting_evidence",
        status=CORRELATION_STATUS_NOT_APPLICABLE,
        reason="no expected SPI is defined by the plan; Phase 4 does not invent one. "
               "SPI observations are preserved as supporting evidence "
               "(all SPIs, first/last timestamps and packet counts retained).",
        expected_value=None,
        observed_value=summary.get("spi_count") if spis else None,
        identity=ctx.expected_identity.to_dict(), evidence_refs=ctx.evidence_refs,
    )


def summarize_spis(spis) -> Dict[str, Any]:
    """Deterministic SPI summary (never arbitrarily selects one observation)."""
    total = len(spis)
    unique_spis = len({str(s.spi) for s in spis})
    duplicates = total - unique_spis
    direction_conflicts = 0
    by_spi: Dict[str, set] = {}
    for s in spis:
        by_spi.setdefault(str(s.spi), set()).add(s.direction)
    for directions in by_spi.values():
        if len(directions) > 1:
            direction_conflicts += 1
    first_seen = min((s.first_seen_ns for s in spis), default=None)
    last_seen = max((s.last_seen_ns for s in spis), default=None)
    packets = sum(s.packet_count for s in spis)
    return {
        "spi_count": total,
        "unique_spis": unique_spis,
        "duplicate_observations": duplicates,
        "direction_conflicts": direction_conflicts,
        "first_seen_ns": first_seen,
        "last_seen_ns": last_seen,
        "total_packets": packets,
    }


# ---- rule registry ----------------------------------------------------------
RULES: Dict[str, Any] = {
    "mode": compare_mode,
    "address_family": compare_address_family,
    "ike.version": compare_ike_version,
    "ike.encryption": compare_ike_encryption,
    "ike.integrity": compare_ike_integrity,
    "ike.dh_group": compare_ike_dh_group,
    "esp.encryption": compare_esp_encryption,
    "esp.integrity": compare_esp_integrity,
    "esp.dh_group": compare_esp_dh_group,
    "esp.pfs": compare_esp_pfs,
    "traffic.profile": compare_traffic_profile,
    "traffic.duration": compare_traffic_duration,
    "traffic.port": compare_traffic_port,
    "capture_filter": compare_capture_filter,
    "configuration_id": compare_configuration_id,
    "security_posture": compare_security_posture,
    "esp.presence": compare_esp_presence,
    "ah.presence": compare_ah_presence,
    "ike.activity": compare_ike_activity,
    "traffic.activity": compare_traffic_activity,
    "tunnel.activity": compare_tunnel_activity,
    "window.containment": compare_window_containment,
    "spi": compare_spi,
}


def accounting_driven_rule_order() -> Tuple[str, ...]:
    """Deterministic execution order: canonical, then derived, then presence,
    then window, then supporting SPI."""
    return ACCOUNTED_VARIABLES + (
        "esp.presence", "ah.presence", "ike.activity",
        "traffic.activity", "tunnel.activity", "window.containment", "spi",
    )