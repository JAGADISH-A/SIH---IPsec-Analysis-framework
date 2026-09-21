"""Comparison engine (Phase 4): Expected vs Observed pipeline orchestrator.

The engine is a deterministic, audit component:

* it verifies identity compatibility BEFORE any comparison (``IdentityMismatchError``),
* it executes every registered rule in a fixed order,
* it NEVER turns UNKNOWN into MISMATCH (conservative),
* it never infers crypto from ``configuration_id`` / ``security_posture`` /
  traffic profile / packet sizes / ML output,
* it never computes risk, never ranks, never assigns scores.

Overall status aggregation (documented in code + tests):

    MISMATCH        at least one authoritative contradiction exists
    UNKNOWN         no mismatch, but one or more required comparisons unresolved
    MATCH           all applicable comparable fields match, none unresolved
    NOT_APPLICABLE  no applicable comparison exists
    NOT_EVALUATED   nothing was compared (never produced by a real comparison)
"""

from dataclasses import dataclass
from typing import Any, Dict, List, Mapping, Optional, Sequence, Union

from ..adapters import MaterializedExpectedState
from ..models import (
    CORRELATION_STATUS_MATCH,
    CORRELATION_STATUS_MISMATCH,
    CORRELATION_STATUS_NOT_APPLICABLE,
    CORRELATION_STATUS_NOT_EVALUATED,
    CORRELATION_STATUS_UNKNOWN,
    CorrelationIdentity,
    CorrelationResult,
    EvidenceRef,
    ExpectedState,
    LiveFeatureWindow,
    MLResult,
    ObservedState,
)
from .clock import (
    CLOCK_DOMAIN_LIVE_MONOTONIC_NS,
    ClockAlignment,
    validate_clock_domain,
)
from .discrepancy import bucket_outcomes
from .rules import (
    RULES,
    RuleContext,
    accounting_driven_rule_order,
    establish_completeness,
    summarize_spis,
)

COMPARISON_ENGINE_VERSION = "v1"

CORE_IDENTITY_FIELDS = (
    "dataset_run_id",
    "sequence",
    "experiment_id",
    "attempt_number",
)
WINDOW_IDENTITY_FIELDS = ("window_index", "window_start_ns", "window_end_ns")


class IdentityMismatchError(ValueError):
    """Expected and observed belong to different experiments; nothing is compared."""


def identity_mismatch_reason(
    identity_a: CorrelationIdentity,
    identity_b: CorrelationIdentity,
) -> Optional[str]:
    """Return a structured reason when two identities do not designate the same
    experiment. Window fields are compared only when BOTH carry them (state-level
    records may legitimately lack a window)."""
    for field in CORE_IDENTITY_FIELDS:
        value_a = getattr(identity_a, field)
        value_b = getattr(identity_b, field)
        if value_a != value_b:
            return f"{field} differs: expected={value_a!r}, observed={value_b!r}"
    for field in WINDOW_IDENTITY_FIELDS:
        value_a = getattr(identity_a, field)
        value_b = getattr(identity_b, field)
        if value_a is not None and value_b is not None and value_a != value_b:
            return f"{field} differs: expected={value_a!r}, observed={value_b!r}"
    return None


def assert_identity_compatible(
    identity_a: CorrelationIdentity,
    identity_b: CorrelationIdentity,
) -> None:
    reason = identity_mismatch_reason(identity_a, identity_b)
    if reason is not None:
        raise IdentityMismatchError(
            "expected and observed belong to different experiments; comparison "
            f"aborted: {reason}"
        )


def aggregate_status(
    matches: Sequence[Any],
    mismatches: Sequence[Any],
    unknowns: Sequence[Any],
    not_applicable: Sequence[Any],
) -> str:
    """Deterministic overall-status aggregation (documented in the module
    docstring). Inputs are the bucketed outcome payloads."""
    if mismatches:
        return CORRELATION_STATUS_MISMATCH
    if unknowns:
        return CORRELATION_STATUS_UNKNOWN
    if matches:
        return CORRELATION_STATUS_MATCH
    if not_applicable:
        return CORRELATION_STATUS_NOT_APPLICABLE
    return CORRELATION_STATUS_NOT_EVALUATED


@dataclass(frozen=True)
class ComparisonEngineOptions:
    """Configuration for the deterministic engine (no thresholds, no scores)."""

    observed_clock_domain: str = CLOCK_DOMAIN_LIVE_MONOTONIC_NS
    window_clock_domain: str = CLOCK_DOMAIN_LIVE_MONOTONIC_NS


class ComparisonEngine:
    """Deterministic expected-vs-observed comparison engine."""

    def __init__(self, options: Optional[ComparisonEngineOptions] = None) -> None:
        self.options = options or ComparisonEngineOptions()
        validate_clock_domain(self.options.observed_clock_domain)
        validate_clock_domain(self.options.window_clock_domain)

    def compare(
        self,
        expected: Union[ExpectedState, MaterializedExpectedState],
        observed: ObservedState,
        *,
        identity: Optional[CorrelationIdentity] = None,
        observed_identity: Optional[CorrelationIdentity] = None,
        live_features: Optional[LiveFeatureWindow] = None,
        ml_result: Optional[MLResult] = None,
        evidence_refs: Sequence[EvidenceRef] = (),
        clock_alignment: Optional[ClockAlignment] = None,
        observed_values: Optional[Mapping[str, Any]] = None,
    ) -> CorrelationResult:
        """Compare ``expected`` against ``observed``.

        ``observed_values`` is the authoritative observed-value channel (e.g.
        swanctl / audit-derived): canonical variable -> observed value. When a
        canonical variable is NOT present there (and not derivable from a field
        that actually exists in ``ObservedState``), the rule conservatively
        returns UNKNOWN / NOT_APPLICABLE — never MISMATCH.

        ``ml_result`` is accepted but NEVER evaluated in Phase 4.
        """
        expected_state, expected_identity = self._resolve_expected(expected, identity)
        if not isinstance(observed, ObservedState):
            raise TypeError(
                f"observed must be an ObservedState, got {type(observed).__name__}"
            )
        if observed_identity is None:
            raise IdentityMismatchError(
                "observed_identity is required: identity safety cannot be verified "
                "without an observed identity; nothing is compared."
            )
        if not isinstance(observed_identity, CorrelationIdentity):
            raise TypeError("observed_identity must be a CorrelationIdentity")
        assert_identity_compatible(expected_identity, observed_identity)

        evidence = tuple(evidence_refs)
        for ev in evidence:
            if not isinstance(ev, EvidenceRef):
                raise TypeError("evidence_refs must contain EvidenceRef objects")

        completeness = establish_completeness(expected_state, live_features)

        context = RuleContext(
            expected=expected_state,
            observed=observed,
            expected_identity=expected_identity,
            evidence_refs=evidence,
            observed_values=dict(observed_values or {}),
            live_features=live_features,
            completeness=completeness,
            clock_alignment=clock_alignment,
            observed_clock_domain=self.options.observed_clock_domain,
            window_clock_domain=self.options.window_clock_domain,
        )

        outcomes = []
        for variable in accounting_driven_rule_order():
            rule = RULES[variable]
            outcomes.append(rule(context))

        matches, mismatches, unknowns, not_applicable = bucket_outcomes(outcomes)
        status = aggregate_status(matches, mismatches, unknowns, not_applicable)

        spi_summary = summarize_spis(observed.spis)
        metadata: Dict[str, Any] = {
            "comparison_engine_version": COMPARISON_ENGINE_VERSION,
            "observation_completeness": completeness,
            "spi_summary": spi_summary,
            "ml_evaluated": ml_result is not None,
            "rules_executed": list(accounting_driven_rule_order()),
        }

        return CorrelationResult(
            identity=expected_identity,
            status=status,
            matches=matches,
            mismatches=mismatches,
            unknowns=unknowns,
            not_applicable=not_applicable,
            metadata=metadata,
        )

    @staticmethod
    def _resolve_expected(
        expected: Union[ExpectedState, MaterializedExpectedState],
        identity: Optional[CorrelationIdentity],
    ) -> tuple:
        if isinstance(expected, ExpectedState):
            if identity is None:
                raise ValueError(
                    "identity is required when expected is an ExpectedState"
                )
            return expected, identity
        if isinstance(expected, MaterializedExpectedState):
            if identity is not None and identity != expected.identity:
                raise ValueError(
                    "identity parameter conflicts with the MaterializedExpectedState "
                    "identity"
                )
            return expected.expected, expected.identity
        raise TypeError(
            "expected must be an ExpectedState or a MaterializedExpectedState"
        )